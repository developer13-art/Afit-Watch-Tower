"""Device registry: which handset belongs to whom, and how to reach it.

A device row is created by a successful login or an explicit `POST /devices`, never by the
cloud inventing one. The FCM registration token is stored sealed with this host's key ring
because the token is a bearer capability: whoever holds it can deliver that person's security
alerts to that device. A short non-reversible fingerprint is kept alongside so a token change is
detectable without decrypting anything.
"""

from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import utcnow
from ..mobile.models import MobileDevice, PushState
from ..security.secrets import fingerprint, redact
from .deps import CloudContainer
from .errors import CloudError

LOGGER = logging.getLogger("watchtower.cloud.devices")

PLATFORMS = frozenset({"android", "ios", "web"})
INSTALLATION_ID_MAX = 64


@dataclass(slots=True)
class DeviceView:
    id: int
    installation_id: str
    platform: str
    model: str | None
    os_version: str | None
    app_version: str | None
    push_state: str
    push_capable: bool
    registered_at: dt.datetime
    last_seen_at: dt.datetime

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "installation_id": self.installation_id,
            "platform": self.platform,
            "model": self.model,
            "os_version": self.os_version,
            "app_version": self.app_version,
            "push_state": self.push_state,
            "push_capable": self.push_capable,
            "registered_at": self.registered_at.isoformat(),
            "last_seen_at": self.last_seen_at.isoformat(),
        }


def _view(device: MobileDevice) -> DeviceView:
    return DeviceView(
        id=device.id,
        installation_id=device.installation_id,
        platform=device.platform,
        model=device.model,
        os_version=device.os_version,
        app_version=device.app_version,
        push_state=device.push_state,
        push_capable=device.push_state == PushState.ACTIVE.value
        and device.push_token_ciphertext is not None,
        registered_at=device.registered_at,
        last_seen_at=device.last_seen_at,
    )


def find(session: Session, *, user_id: int, installation_id: str) -> MobileDevice | None:
    return session.scalar(
        select(MobileDevice).where(
            MobileDevice.user_id == user_id,
            MobileDevice.installation_id == installation_id,
        )
    )


def register(
    session: Session,
    container: CloudContainer,
    *,
    user_id: int,
    installation_id: str,
    platform: str = "android",
    push_provider: str = "fcm",
    push_token: str | None = None,
    model: str | None = None,
    os_version: str | None = None,
    app_version: str | None = None,
) -> tuple[MobileDevice, bool]:
    """Register or refresh. Returns the row and whether the push token actually changed.

    Idempotent on (`user_id`, `installation_id`) - the unique constraint makes a racing second
    install of the same app land on the same row rather than fork a second device identity.
    """
    installation_id = (installation_id or "").strip()
    if not installation_id:
        raise CloudError("installation_id_required", "installation_id is required.", status_code=422)
    if len(installation_id) > INSTALLATION_ID_MAX:
        raise CloudError(
            "installation_id_invalid",
            f"installation_id must be at most {INSTALLATION_ID_MAX} characters.",
            status_code=422,
        )
    if platform not in PLATFORMS:
        raise CloudError(
            "platform_unsupported",
            f"platform must be one of {', '.join(sorted(PLATFORMS))}.",
            status_code=422,
        )

    device = find(session, user_id=user_id, installation_id=installation_id)
    token_changed = False
    if device is None:
        device = MobileDevice(
            user_id=user_id,
            installation_id=installation_id,
            platform=platform,
            push_provider=push_provider,
            model=model,
            os_version=os_version,
            app_version=app_version,
            push_state=PushState.ACTIVE.value if push_token else PushState.INACTIVE.value,
        )
        session.add(device)
        session.flush()
    else:
        device.platform = platform
        device.push_provider = push_provider
        device.model = model or device.model
        device.os_version = os_version or device.os_version
        device.app_version = app_version or device.app_version
        if device.push_state == PushState.REVOKED.value:
            # A revoked handset stays revoked until the administrator or the person who forgot it
            # registers the installation again, which mints a new row identity. Re-installing the
            # app over a revoked row and silently restoring delivery would undo a decision taken
            # to stop a specific phone - a shared or lost one - being paged.
            session.flush()
            return device, False
        if device.deactivated_at is not None:
            # Any other retirement is the app's own state, and the app coming back ends it.
            device.deactivated_at = None
            device.push_state = PushState.INACTIVE.value

    if push_token:
        token_changed = _store_push_token(session, container, device, push_token)

    device.last_seen_at = utcnow()
    session.flush()
    return device, token_changed


def _store_push_token(
    session: Session, container: CloudContainer, device: MobileDevice, plaintext: str
) -> bool:
    """Seal the token. Returns False when nothing moved, so an FCM refresh is not an event."""
    new_print = fingerprint(plaintext)
    if device.push_token_fingerprint == new_print and device.push_state == PushState.ACTIVE.value:
        return False
    try:
        ciphertext, key_id = container.seal_push_token(plaintext)
    except Exception as exc:
        # A key-ring fault is reported as a storage failure rather than allowed to lose the
        # login: the person still needs a session, and the device simply stays un-pageable.
        LOGGER.error("could not seal a push token: %s", redact(str(exc)))
        raise CloudError(
            "storage_unavailable",
            "The service could not store this device's push token.",
            status_code=503,
        ) from exc
    device.push_token_ciphertext = ciphertext
    device.push_token_key_id = key_id
    device.push_token_fingerprint = new_print
    device.token_updated_at = utcnow()
    device.push_state = PushState.ACTIVE.value
    device.invalid_reason = None
    return True


def reveal_token(container: CloudContainer, device: MobileDevice) -> str | None:
    return container.unseal_push_token(device.push_token_ciphertext, device.push_token_key_id)


def list_for_user(session: Session, user_id: int) -> list[dict]:
    rows = session.scalars(
        select(MobileDevice)
        .where(MobileDevice.user_id == user_id)
        .order_by(MobileDevice.registered_at)
    ).all()
    return [_view(row).as_dict() for row in rows]


def deactivate(session: Session, *, user_id: int, installation_id: str) -> MobileDevice:
    device = find(session, user_id=user_id, installation_id=installation_id)
    if device is None:
        raise CloudError("not_found", "No such device on this account.", status_code=404)
    device.push_state = PushState.REVOKED.value
    device.deactivated_at = utcnow()
    device.push_token_ciphertext = None
    device.push_token_key_id = None
    device.push_token_fingerprint = None
    session.flush()
    return device


def mark_invalid(session: Session, device: MobileDevice, reason: str) -> None:
    """FCM says the token is dead: drop the secret, keep the history."""
    device.push_state = PushState.INVALID.value
    device.invalid_reason = reason[:128]
    device.push_token_ciphertext = None
    device.push_token_key_id = None
    device.push_token_fingerprint = None
    session.flush()


def touch(session: Session, device: MobileDevice) -> None:
    device.last_seen_at = utcnow()


def targetable(session: Session, user_ids: list[int]) -> list[MobileDevice]:
    if not user_ids:
        return []
    return list(
        session.scalars(
            select(MobileDevice).where(
                MobileDevice.user_id.in_(user_ids),
                MobileDevice.push_state == PushState.ACTIVE.value,
                MobileDevice.push_token_ciphertext.is_not(None),
                MobileDevice.deactivated_at.is_(None),
            )
        )
    )


def registered(session: Session, user_ids: list[int]) -> list[MobileDevice]:
    """Handsets that can *display* an alert, whether or not they can be woken for one.

    A phone that signed in but never obtained an FCM token - every phone on a build with no
    Firebase project, and the web build - is in this set and not in `targetable`. The two must not
    be confused: only `targetable` may be sent to, while this set decides whether there is a screen
    the officer can read the alert on (contract §10.7).
    """
    if not user_ids:
        return []
    return list(
        session.scalars(
            select(MobileDevice).where(
                MobileDevice.user_id.in_(user_ids),
                MobileDevice.push_state != PushState.REVOKED.value,
                MobileDevice.deactivated_at.is_(None),
            )
        )
    )
