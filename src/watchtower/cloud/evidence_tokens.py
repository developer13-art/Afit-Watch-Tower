"""Short-lived, single-asset evidence tokens.

An Android `<img>` or `<video>` element cannot attach a bearer header, and putting the session
token in a query string would leave a full account credential in the phone's URL history, in the
proxy log and in the crash report. So evidence gets its own credential, and this module is the
only place that mints or redeems it.

What a token is bound to:

  * one asset id, so it cannot be traded for a different piece of evidence;
  * the user id it was issued to, checked against the asset's incident scope on redemption, so
    a token minted for a person who has since lost the grant stops working immediately;
  * a lifetime (10 minutes by default), carried inside the sealed value and enforced by the
    cipher rather than by a clock comparison the caller can forget to make.

What it is not: a permanent link, a bucket name, a storage credential, or a capability the cloud
can hand to somebody who was never authorised. The response body in contract 7.1 carries only
this token's URL, and the URL is meaningless once the token expires.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from ..security.secrets import derive_media_key
from .config import CloudSettings
from .errors import CloudError

PURPOSE = "evidence-access-token"


@dataclass(slots=True)
class EvidenceGrant:
    asset_id: int
    user_id: int
    expires_at: int

    @property
    def seconds_left(self) -> int:
        return max(0, int(self.expires_at - time.time()))


def _fernet(settings: CloudSettings) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(derive_media_key(settings.jwt_secret, PURPOSE)))


def mint(settings: CloudSettings, *, asset_id: int, user_id: int, ttl_seconds: int | None = None) -> tuple[str, int]:
    """Return `(token, expires_at_epoch)`. The caller puts the expiry in the response body."""
    ttl = ttl_seconds or settings.evidence_token_ttl_seconds
    expires_at = int(time.time()) + int(ttl)
    payload = json.dumps({"a": int(asset_id), "u": int(user_id), "e": expires_at}).encode()
    return _fernet(settings).encrypt(payload).decode(), expires_at


def redeem(settings: CloudSettings, token: str) -> EvidenceGrant:
    raw = (token or "").strip()
    if not raw:
        raise CloudError("evidence_token_required", "An evidence token is required.", status_code=401)
    try:
        payload = _fernet(settings).decrypt(raw.encode())
        data = json.loads(payload)
        asset_id = int(data["a"])
        user_id = int(data["u"])
        expires_at = int(data["e"])
    except (InvalidToken, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        # One answer for "tampered", "forged", "not valid base64" and "wrong shape". The
        # distinction only helps whoever is probing the endpoint.
        raise CloudError(
            "evidence_token_invalid", "This evidence link is not valid.", status_code=401
        ) from exc
    if expires_at <= int(time.time()):
        raise CloudError(
            "evidence_token_expired",
            "This evidence link has expired. Refresh the incident to get a new one.",
            status_code=410,
        )
    return EvidenceGrant(asset_id=asset_id, user_id=user_id, expires_at=expires_at)
