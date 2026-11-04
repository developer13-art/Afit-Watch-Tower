"""Encrypted camera credential storage (proposal sections 8.3 and 16).

Camera passwords never live in the `cameras` or `camera_connection_profiles` rows. They
are encrypted with a key from a separate key ring file and referenced by an opaque
`secret_reference`. The raw RTSP URL is accepted as *input* only; it is parsed so the
credential never reaches a log line, an API response or a database column.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets as _pysecrets
from dataclasses import dataclass
from datetime import datetime, UTC
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..models import CameraSecret

_KEYRING_VERSION = 1


class SecretStoreError(RuntimeError):
    pass


class KeyRing:
    """File-backed key ring with support for rotation.

    The ring file holds Fernet keys, not camera secrets. In a hardened deployment this is
    replaced by the institution's approved secrets manager; `SecretStore` is the seam.
    """

    def __init__(self, path: Path, *, create_if_missing: bool) -> None:
        self.path = path
        if path.exists():
            self._data = json.loads(path.read_text())
            if self._data.get("version") != _KEYRING_VERSION:
                raise SecretStoreError(f"unsupported key ring version in {path}")
        elif create_if_missing:
            key_id = _pysecrets.token_hex(4)
            self._data = {
                "version": _KEYRING_VERSION,
                "active_key_id": key_id,
                "keys": {key_id: Fernet.generate_key().decode()},
            }
            self._write()
        else:
            raise SecretStoreError(
                f"no key ring at {path}. Provision it before starting in production "
                "(section 16: approved secret-management mechanism)."
            )

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 0o600 is advisory on Windows; deployment guidance is to keep the ring on a
        # restricted volume and outside any web root.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as handle:
            json.dump(self._data, handle, indent=2)
        # 0o600 is advisory on Windows, where the creating mode above already applied it.
        with contextlib.suppress(OSError):
            os.chmod(self.path, 0o600)

    @property
    def active_key_id(self) -> str:
        return self._data["active_key_id"]

    def fernet(self, key_id: str) -> Fernet:
        try:
            raw = self._data["keys"][key_id]
        except KeyError as exc:
            raise SecretStoreError(f"unknown key id {key_id!r}") from exc
        return Fernet(raw.encode())

    def rotate(self) -> str:
        key_id = _pysecrets.token_hex(4)
        self._data["keys"][key_id] = Fernet.generate_key().decode()
        self._data["active_key_id"] = key_id
        self._write()
        return key_id


def derive_media_key(master_secret: str, purpose: str) -> bytes:
    """Derive a purpose-bound 32-byte key from the application master secret."""
    if not master_secret:
        raise SecretStoreError("WATCHTOWER_JWT_SECRET is unset; refusing to derive keys.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        info=purpose.encode(),
        salt=None,
    ).derive(master_secret.encode())


@dataclass(slots=True)
class SealedSecret:
    reference: str
    ciphertext: bytes
    key_id: str
    plaintext_length: int


class SecretStore:
    def __init__(self, key_ring: KeyRing) -> None:
        self._keys = key_ring

    def seal(self, plaintext: str) -> SealedSecret:
        key_id = self._keys.active_key_id
        token = self._keys.fernet(key_id).encrypt(plaintext.encode())
        return SealedSecret(
            reference=f"sec_{_pysecrets.token_hex(8)}",
            ciphertext=token,
            key_id=key_id,
            plaintext_length=len(plaintext),
        )

    def persist(self, session, sealed: SealedSecret) -> CameraSecret:
        row = CameraSecret(
            reference=sealed.reference,
            ciphertext=sealed.ciphertext,
            key_id=sealed.key_id,
        )
        session.add(row)
        session.flush()
        return row

    def reveal(self, row: CameraSecret | None) -> str | None:
        """Return the plaintext password for stream construction only.

        Callers must never place the result in a response, log line or exception message;
        `redact()` is applied at those boundaries as defence in depth.
        """
        if row is None:
            return None
        try:
            return self._keys.fernet(row.key_id).decrypt(row.ciphertext).decode()
        except InvalidToken as exc:
            raise SecretStoreError(
                f"cannot decrypt camera secret {row.reference!r}; key ring mismatch"
            ) from exc

    def replace(self, row: CameraSecret, plaintext: str) -> CameraSecret:
        sealed = self.seal(plaintext)
        row.ciphertext = sealed.ciphertext
        row.key_id = sealed.key_id
        row.rotated_at = _utcnow()
        return row


def _utcnow() -> datetime:
    return datetime.now(UTC)


# --------------------------------------------------------------------------- #
# Redaction (sections 6.5 and 22: "redact logs")
# --------------------------------------------------------------------------- #

# rtsp://user:pass@host  ->  mask the password, keep the user for diagnostics.
# The password group may itself contain `@`, because the parser percent-encodes that character
# and section 6.1 requires such credentials to round-trip. Anchoring on the last `@` before the
# path (rather than the first) is what keeps `p@ssw0rd` from leaking `ssw0rd` into a log line.
_CREDENTIAL_URL_RE = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)(?P<user>[^:/@\s]+):(?P<pw>[^@/\s]+(?:@[^@/\s]+)*)@",
    re.I,
)
_PASSWORD_QUERY_RE = re.compile(r"([?&](?:password|passwd|pwd)=)[^&\s]*", re.I)
_SECRET_FIELD_RE = re.compile(
    r'("(?:password|passwd|secret|rtsp_password|authorization)"\s*:\s*")([^"]*)(")', re.I
)


def redact(text: str) -> str:
    """Remove credential material from anything destined for a log, error or audit row."""

    def _url_mask(match: re.Match[str]) -> str:
        return f"{match['scheme']}{match['user']}:***@"

    masked = _CREDENTIAL_URL_RE.sub(_url_mask, text)
    masked = _PASSWORD_QUERY_RE.sub(r"\1***", masked)
    masked = _SECRET_FIELD_RE.sub(r"\1***\3", masked)
    return masked


# A value under a key that names it as a credential cannot be pattern-matched - the plaintext
# is a bare word like "sup3r-secret-pw" - so the key itself is the redaction signal for the
# structured sanitizers. `has_secret` and `secret_reference` are deliberately not matched;
# they are descriptors, not credentials.
_SECRET_KEY_NAMES = frozenset(
    {
        "password", "passwd", "pwd", "pass", "secret", "rtsp_password", "authorization",
        "auth", "token", "api_key", "apikey", "access_token", "refresh_token",
        "session_token", "credentials", "connection_secret",
    }
)
_SECRET_KEY_SUFFIXES = ("_password", "_passwd", "_pwd", "_token", "_secret_key", "_credentials")
REDACTED_PLACEHOLDER = "***"


def key_is_secret(name: object) -> bool:
    """Whether a mapping key names a credential, so its value must not be recorded."""
    normalized = str(name).strip().lower().replace("-", "_")
    return normalized in _SECRET_KEY_NAMES or normalized.endswith(_SECRET_KEY_SUFFIXES)


_SCHEME_URL_RE = re.compile(r"[a-z][a-z0-9+.-]*://[^\s\"',;)\]}]+", re.I)


def strip_urls(text: str | None) -> str:
    """Remove transport URLs from text destined for a browser (sections 9 and 16).

    `redact()` keeps the host and the stream path because an operator debugging a camera needs
    them in a log line. A browser never needs them: section 9 promises the raw RTSP URL does not
    reach the client at all, so error text is passed through this before it is serialized.
    """
    return _SCHEME_URL_RE.sub("[connection address withheld]", text or "")


def client_safe(text: str | None) -> str:
    """The form used for anything serialized to a browser: mask secrets, then drop URLs."""
    return strip_urls(redact(text or ""))


def fingerprint(plaintext: str) -> str:
    """A non-reversible short handle, used to record 'the password changed' in audits."""
    return hashlib.sha256(plaintext.encode()).hexdigest()[:12]
