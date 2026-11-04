"""Service-to-service request signing (mobile proposal sections 4 step 4, 11 and 13).

The monitoring host makes outbound HTTPS calls to the cloud service. Every call is signed so
the cloud can answer three separate questions before it touches the payload:

  1. **Is this fresh?** The timestamp must be inside a five-minute window.
  2. **Have I seen this exact call before?** The nonce is recorded in `ingest_nonces`; the
     unique constraint is the check, so a replay after a cloud restart still fails.
  3. **Did the claimed sender make it?** HMAC-SHA256 over a canonical string that includes a
     hash of the raw body bytes.

Order matters and is deliberate: the cheap checks run before the expensive one, and all of
them run before the JSON is parsed, so an unauthenticated caller cannot make the service do
per-request database work or object-storage work.

The signature covers the *bytes*, never a re-serialisation of the parsed body. Two JSON
serialisations of the same object can differ in key order and whitespace, and a verifier
that re-serialised would reject requests it had just accepted.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets as _secrets
import time
from dataclasses import dataclass
from urllib.parse import quote

ALGORITHM = "WATCHTOWER-HMAC-SHA256"
MAX_CLOCK_SKEW_SECONDS = 300
NONCE_BYTES = 16
HEADER_KEY_ID = "x-watchtower-key-id"
HEADER_TIMESTAMP = "x-watchtower-timestamp"
HEADER_NONCE = "x-watchtower-nonce"
HEADER_CONTENT_SHA = "x-watchtower-content-sha256"
HEADER_AUTHORIZATION = "authorization"

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_NONCE_RE = re.compile(r"^[0-9a-f]{16,64}$")
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")


class SignatureError(Exception):
    """A request the cloud must refuse. `code` is what the response body reports."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True, slots=True)
class ServiceCredentials:
    """One machine credential. The secret never appears in a log line or a response."""

    key_id: str
    secret: str

    def __post_init__(self) -> None:
        if not _KEY_ID_RE.match(self.key_id):
            raise ValueError("key_id must be 1-64 characters of [A-Za-z0-9_.:-]")
        if len(self.secret) < 32:
            raise ValueError(
                "the service secret must be at least 32 characters; it signs every ingest "
                "request, so anything shorter is guessable"
            )


@dataclass(frozen=True, slots=True)
class SignedRequest:
    method: str
    path: str
    timestamp: int
    nonce: str
    content_sha256: str
    key_id: str
    body: bytes


def content_sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def canonical_string(*, method: str, path: str, timestamp: int, nonce: str, content_sha: str) -> str:
    """The exact string both sides must agree on.

    The path is percent-encoded the same way on both sides so a query string cannot shift the
    signature; the body hash is lowercase hex from `hashlib`.
    """
    return "\n".join(
        (
            method.upper(),
            _canonical_path(path),
            str(int(timestamp)),
            nonce,
            content_sha,
        )
    )


def _canonical_path(path: str) -> str:
    """Normalise to a leading-slash, percent-encoded path with no query string."""
    clean = path.split("?", 1)[0]
    if not clean.startswith("/"):
        clean = "/" + clean
    return quote(clean, safe="/-_.~")


def sign(secret: str, canonical: str) -> str:
    return hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()


def build_headers(
    credentials: ServiceCredentials,
    *,
    method: str,
    path: str,
    body: bytes,
    nonce: str | None = None,
    timestamp: int | None = None,
) -> dict[str, str]:
    """Headers for an outbound ingest call.

    `nonce` and `timestamp` are parameters so a test can produce a byte-for-byte reproducible
    request; production callers omit them.
    """
    stamp = int(time.time()) if timestamp is None else int(timestamp)
    used_nonce = nonce if nonce is not None else _secrets.token_hex(NONCE_BYTES)
    sha = content_sha256(body)
    canonical = canonical_string(
        method=method, path=path, timestamp=stamp, nonce=used_nonce, content_sha=sha
    )
    return {
        "content-type": "application/json; charset=utf-8",
        HEADER_KEY_ID: credentials.key_id,
        HEADER_TIMESTAMP: str(stamp),
        HEADER_NONCE: used_nonce,
        HEADER_CONTENT_SHA: sha,
        HEADER_AUTHORIZATION: (
            f"{ALGORITHM} {credentials.key_id}:{sign(credentials.secret, canonical)}"
        ),
    }


def parse_authorization(header_value: str | None) -> tuple[str, str]:
    if not header_value or not header_value.startswith(f"{ALGORITHM} "):
        raise SignatureError("unsupported_scheme", f"authorization must start with {ALGORITHM}")
    key_id, _, provided = header_value.removeprefix(f"{ALGORITHM} ").partition(":")
    if not key_id or not provided:
        raise SignatureError("malformed_signature", "expected '<key_id>:<signature>'")
    return key_id, provided.strip().lower()


def verify(
    *,
    method: str,
    path: str,
    body: bytes,
    headers: dict[str, str],
    credentials: dict[str, str],
    now: float | None = None,
    max_skew_seconds: int = MAX_CLOCK_SKEW_SECONDS,
) -> SignedRequest:
    """Verify a request and return what the caller must persist for replay protection.

    `headers` lookups are case-insensitive. Nothing here touches the database: the nonce
    insert is the caller's job because only the caller is inside a transaction.
    """
    lowered = {str(key).lower(): value for key, value in headers.items()}

    key_id = lowered.get(HEADER_KEY_ID, "").strip()
    if not key_id:
        raise SignatureError("missing_key_id", "x-watchtower-key-id is required")
    secret = credentials.get(key_id)
    if secret is None:
        # An unknown key id is refused without saying whether it once existed.
        raise SignatureError("unknown_key_id", "the presented key id is not recognised")

    raw_stamp = lowered.get(HEADER_TIMESTAMP, "").strip()
    if not raw_stamp.isdigit():
        raise SignatureError("invalid_timestamp", "x-watchtower-timestamp must be unix seconds")
    stamp = int(raw_stamp)
    current = time.time() if now is None else now
    if abs(current - stamp) > max_skew_seconds:
        raise SignatureError(
            "timestamp_out_of_window",
            f"request timestamp differs from server time by more than {max_skew_seconds}s",
        )

    nonce = lowered.get(HEADER_NONCE, "").strip().lower()
    if not _NONCE_RE.match(nonce):
        raise SignatureError("invalid_nonce", "x-watchtower-nonce must be 16-64 hex characters")

    claimed_sha = lowered.get(HEADER_CONTENT_SHA, "").strip().lower()
    if not _SHA_RE.match(claimed_sha):
        raise SignatureError("invalid_content_sha256", "x-watchtower-content-sha256 is required")
    actual_sha = content_sha256(body)
    if not hmac.compare_digest(claimed_sha, actual_sha):
        # A body changed in transit, or the client hashed a re-serialisation instead of the
        # bytes it sent. Either way the payload is not the thing that was signed.
        raise SignatureError("content_mismatch", "body does not match the signed digest")

    header_authorization = lowered.get(HEADER_AUTHORIZATION)
    signed_by, provided = parse_authorization(header_authorization)
    if not hmac.compare_digest(signed_by, key_id):
        raise SignatureError("key_id_mismatch", "authorization names a different key id")

    canonical = canonical_string(
        method=method, path=path, timestamp=stamp, nonce=nonce, content_sha=actual_sha
    )
    if not hmac.compare_digest(provided, sign(secret, canonical)):
        raise SignatureError("bad_signature", "the request signature does not verify")

    return SignedRequest(
        method=method.upper(),
        path=_canonical_path(path),
        timestamp=stamp,
        nonce=nonce,
        content_sha256=actual_sha,
        key_id=key_id,
        body=body,
    )
