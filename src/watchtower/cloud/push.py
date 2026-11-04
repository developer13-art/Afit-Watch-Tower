"""Firebase Cloud Messaging HTTP v1 delivery.

Three rules govern everything in this file:

  1. **FCM acceptance is not delivery to a human.** A 200 from Google means the message was
     accepted for the device. Android power management can defer the wake-up and the user can
     dismiss the notification without opening it, so the vocabulary stops at `accepted` and the
     API never reports more than that.
  2. **The service-account private key never leaves this module.** It is read from the file
     named by `CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE` at startup, used to sign an OAuth2
     assertion, and never stored, logged, returned or placed in an exception message.
  3. **Absent configuration is a reported state, not a silent one.** With no Firebase project,
     sends come back `not_configured` and every attempt is recorded as a failure with that
     reason, so the console says "push is not delivering" instead of showing a green tick.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

import jwt as pyjwt

from ..mobile.outbox import SendResult, Sender, urllib_sender
from ..models import Severity
from ..security.secrets import redact
from .config import CloudSettings
from .targeting import KIND_HEALTH

LOGGER = logging.getLogger("watchtower.cloud.push")

FCM_SCOPE = "https://www.googleapis.com/auth/firebase.messaging"
ASSERTION_TTL_SECONDS = 3600
# A registration token that means the app is gone. Retrying these is pointless and it keeps
# a dead handset in the targeting pool forever.
PERMANENT_ERRORS = frozenset(
    {
        "registration-token-not-registered",
        "invalid-argument",
        "sender-id-permission-denied",
        "messaging/registration-token-not-registered",
        "messaging/invalid-registration-token",
    }
)


@dataclass(slots=True)
class PushOutcome:
    ok: bool
    provider_message_id: str | None = None
    error_code: str | None = None
    failure_reason: str | None = None
    token_is_dead: bool = False
    retryable: bool = False

    @classmethod
    def accepted(cls, message_id: str) -> PushOutcome:
        return cls(ok=True, provider_message_id=message_id)

    @classmethod
    def failure(
        cls,
        code: str,
        reason: str,
        *,
        token_is_dead: bool = False,
        retryable: bool = False,
    ) -> PushOutcome:
        return cls(
            ok=False,
            error_code=code,
            failure_reason=reason[:256],
            token_is_dead=token_is_dead,
            retryable=retryable,
        )


def endpoint(project_id: str) -> str:
    return f"https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"


# The channel ids the Android app creates on launch (`personnel-app/src/lib/severity.ts`,
# `ALL_CHANNELS`). Android discards a notification whose `channel_id` does not exist on the
# handset, so naming a channel the app never made is not a cosmetic mismatch - it is an alert
# that never appears while this service reports the send as accepted.
CHANNEL_BY_SEVERITY = {
    Severity.CRITICAL.value: "watchtower-critical",
    Severity.HIGH.value: "watchtower-high",
    Severity.MEDIUM.value: "watchtower-warning",
    Severity.LOW.value: "watchtower-informational",
}
HEALTH_CHANNEL = "watchtower-camera-health"
# `note.severity` is an enum column, so an unclassifiable severity means a payload built outside
# this module. It goes to the same channel the operating system uses when a message names no
# channel at all - the one the app declares as its default in AndroidManifest.xml - rather than
# to a quiet one, because a duty alert that is silently ranked down is the worse failure.
DEFAULT_CHANNEL = CHANNEL_BY_SEVERITY[Severity.CRITICAL.value]


def channel_for(data: dict[str, str]) -> str:
    """The handset channel a payload must use, from the two fields the app can act on."""
    if data.get("kind") == KIND_HEALTH:
        return HEALTH_CHANNEL
    return CHANNEL_BY_SEVERITY.get(data.get("severity", ""), DEFAULT_CHANNEL)


def build_payload(
    *, token: str, title: str, body: str, data: dict[str, str], priority: str = "high",
    collapse_key: str | None = None, sound: str = "default",
) -> dict[str, Any]:
    """The FCM message body.

    Only `data` carries application content, and only the fields the contract lists: an
    incident id, a notification id, a severity, a title, a camera name and a deep link. No
    evidence URL, no coordinate, no summary text - a push payload passes through Google's
    servers and is stored on the handset in the clear.

    `title` is repeated into the Android notification block because that block, not `data`, is
    what Android displays for a background message; without it the handset posts an empty
    notification. `body` is deliberately *not* repeated: it is the operator's own sentence (an
    escalation reason, a resolution note), and a lock screen shows whatever the notification
    block contains to anyone standing next to the phone. The alert's detail is read inside the
    app, after authentication.
    """
    message: dict[str, Any] = {
        "token": token,
        "data": {str(k): str(v) for k, v in data.items()},
        "android": {
            "priority": "high" if priority == "high" else "normal",
            "notification": {
                "title": title[:120],
                "channel_id": channel_for(data),
                "sound": sound if sound != "silent" else "",
                "default_light": True,
            },
        },
        "webpush": {"notification": {"title": title, "body": body[:120]}},
    }
    if collapse_key:
        message["android"]["collapse_key"] = collapse_key
    return {"message": message}


class FcmSender:
    """HTTP v1 delivery using a service-account OAuth2 assertion."""

    configured = True
    provider_name = "fcm"

    def __init__(
        self,
        settings: CloudSettings,
        *,
        transport: Sender | None = None,
        now: callable = time.time,
    ) -> None:
        if not settings.firebase_project_id or not settings.firebase_service_account_file:
            raise ValueError(
                "FcmSender needs CLOUD_FIREBASE_PROJECT_ID and CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE"
            )
        self._project_id = settings.firebase_project_id
        self._url = endpoint(self._project_id)
        self._transport = transport or urllib_sender(timeout=20.0)
        self._now = now
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._account = _read_service_account(settings.firebase_service_account_file)

    # -- OAuth2 ------------------------------------------------------------- #

    def _assertion(self) -> str:
        issued = int(self._now())
        claims = {
            "iss": self._account["client_email"],
            "scope": FCM_SCOPE,
            "aud": self._account.get("token_uri", "https://oauth2.googleapis.com/token"),
            "exp": issued + ASSERTION_TTL_SECONDS,
            "iat": issued,
        }
        return pyjwt.encode(
            claims, self._account["private_key"], algorithm="RS256", headers={"typ": "JWT"}
        )

    def _access_token(self) -> str:
        if self._token and self._now() < self._token_expires_at - 60:
            return self._token
        body = urllib.parse.urlencode(
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion": self._assertion(),
            }
        ).encode()
        result = self._transport(
            self._account.get("token_uri", "https://oauth2.googleapis.com/token"),
            body,
            {"content-type": "application/x-www-form-urlencoded"},
        )
        if not result.ok:
            raise RuntimeError(
                f"the OAuth2 token endpoint refused the service-account assertion "
                f"(status {result.status or result.error})"
            )
        payload = json.loads(result.body)
        self._token = payload["access_token"]
        self._token_expires_at = self._now() + float(payload.get("expires_in", 3600))
        return self._token

    # -- sending ------------------------------------------------------------- #

    def send(
        self, token: str, *, title: str, body: str, data: dict[str, str], sound: str = "default"
    ) -> PushOutcome:
        if not token:
            return PushOutcome.failure("no_token", "This device has no stored push token.")
        try:
            access = self._access_token()
        except Exception as exc:  # noqa: BLE001 - a credential fault is a delivery failure
            LOGGER.error("push credential unavailable: %s", redact(str(exc)))
            return PushOutcome.failure(
                "credential_unavailable", redact(str(exc))[:200], retryable=True
            )

        payload = build_payload(token=token, title=title, body=body, data=data, sound=sound)
        result = self._transport(
            self._url,
            json.dumps(payload).encode(),
            {"authorization": f"Bearer {access}", "content-type": "application/json"},
        )
        if result.ok:
            name = None
            try:
                name = json.loads(result.body).get("name")
            except (json.JSONDecodeError, AttributeError):
                name = None
            return PushOutcome.accepted(str(name or "unknown"))

        reason = _failure_reason(result)
        if result.status in (404,) or reason["code"] in PERMANENT_ERRORS:
            return PushOutcome.failure(
                reason["code"] or "unregistered", reason["message"], token_is_dead=True
            )
        if result.status in (429, 500, 502, 503, 504) or result.status == 0:
            return PushOutcome.failure(
                reason["code"] or "temporarily_unavailable",
                reason["message"],
                retryable=True,
            )
        return PushOutcome.failure(reason["code"] or "refused", reason["message"])


class DisabledSender:
    """No Firebase project configured on this host. Every attempt is an honest failure."""

    configured = False
    provider_name = "fcm"

    def send(
        self, token: str, *, title: str, body: str, data: dict[str, str], sound: str = "default"
    ) -> PushOutcome:
        return PushOutcome.failure(
            "not_configured",
            "This cloud host has no Firebase project configured, so no push was sent.",
        )


def build_push_sender(
    settings: CloudSettings, _secret_store=None
) -> FcmSender | DisabledSender | UnreachableSender:
    if settings.push_enabled:
        try:
            return FcmSender(settings)
        except (OSError, ValueError, KeyError) as exc:
            # A missing or unreadable key file is a configuration fault to be reported, not a
            # reason for the whole service to refuse to start: incident records and the phone's
            # own incident list still work while nobody is paged.
            LOGGER.error("push is configured but could not start: %s", redact(str(exc)))
            return UnreachableSender(redact(str(exc))[:200])
    return DisabledSender()


class UnreachableSender:
    """Configured badly. Same reporting contract as `DisabledSender`, different reason."""

    configured = False
    provider_name = "fcm"

    def __init__(self, detail: str) -> None:
        self._detail = detail

    def send(
        self, token: str, *, title: str, body: str, data: dict[str, str], sound: str = "default"
    ) -> PushOutcome:
        return PushOutcome.failure("push_misconfigured", self._detail)


def _read_service_account(path) -> dict[str, str]:
    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    for field_name in ("client_email", "private_key"):
        value = data.get(field_name)
        if not isinstance(value, str) or not value:
            raise ValueError(
                f"the Firebase service-account file is missing {field_name!r}"
            )
    return {
        "client_email": data["client_email"],
        "private_key": data["private_key"],
        "token_uri": data.get("token_uri") or "https://oauth2.googleapis.com/token",
    }


def _failure_reason(result: SendResult) -> dict[str, str]:
    """`{code, message}` from an FCM error body, with nothing sensitive retained."""
    if result.error:
        return {"code": "transport_error", "message": redact(result.error)[:200]}
    try:
        parsed = json.loads(result.body)
        error = parsed.get("error", {}) if isinstance(parsed, dict) else {}
        status_text = error.get("status") or ""
        message = error.get("message") or ""
        details = error.get("details") or []
        for entry in details if isinstance(details, list) else []:
            reason = entry.get("reason") if isinstance(entry, dict) else None
            if reason:
                status_text = status_text or reason
        return {"code": _normalise(status_text), "message": redact(message)[:200]}
    except (json.JSONDecodeError, AttributeError):
        return {"code": "", "message": f"delivery failed with status {result.status}"}


def _normalise(status: str) -> str:
    lowered = (status or "").lower().replace("_", "-")
    if not lowered:
        return ""
    return lowered.split(":", 1)[-1]
