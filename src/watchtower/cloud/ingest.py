"""The ingest gate: how a monitoring host proves who it is.

One request, four checks, in the cheapest order, all of them fail-closed:

  1. **Timestamp window.** A request more than `CLOUD_INGEST_MAX_SKEW_SECONDS` (300 s) from this
     server's clock is refused before anything is read from it. This is what bounds the useful
     lifetime of a captured request.
  2. **Nonce.** The nonce format is checked, then the `(key_id, nonce)` pair is inserted into
     `ingest_nonces`. The unique constraint *is* the replay check, and because the insert
     happens in the caller's transaction, a request that is later rolled back did not consume
     its nonce either.
  3. **Content digest.** The raw bytes the server received are hashed and compared with
     `x-watchtower-content-sha256`. A body that changed in transit - or that the sender hashed
     after re-serialising instead of signing what it actually put on the wire - is refused.
  4. **Signature**, compared in constant time against the canonical string
     `POST\n<path>\n<timestamp>\n<nonce>\n<content-sha256>`.

`WATCHTOWER-HMAC-SHA256 <key_id>:<signature>` naming a different key id than the header is a
mismatch, not a fallback: one request must be attributable to exactly one credential.

Then, and only then, the idempotency key: a key already recorded in `ingest_records` returns the
first answer with `duplicate: true`, so the forwarder's retry after a lost response cannot page
anybody twice.

The cloud never creates an incident from this path. The monitoring host already wrote the
incident row in the shared database, so `POST /ingest/incident` carries that row's id and this
module *links* to it. Fabricating an incident here would be the second source of truth the
proposal forbids.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..mobile import signing
from ..mobile.models import IngestNonce, IngestRecord
from ..security.secrets import redact
from .config import CloudSettings
from .errors import CloudError

LOGGER = logging.getLogger("watchtower.cloud.ingest")

MAX_BODY_BYTES = 32 * 1024 * 1024  # the evidence relay sends base64 bytes in the body


@dataclass(slots=True)
class IngestCall:
    """A verified request, ready for a route to act on."""

    signed: signing.SignedRequest
    key_id: str
    body: dict[str, Any]
    idempotency_key: str
    duplicate_of: IngestRecord | None = None

    @property
    def is_duplicate(self) -> bool:
        return self.duplicate_of is not None


def verify(
    *,
    session: Session,
    settings: CloudSettings,
    method: str,
    path: str,
    headers: dict[str, str],
    body: bytes,
) -> signing.SignedRequest:
    """Signature plus nonce. Raises `CloudError` with the contract's code for every refusal."""
    if not settings.ingest_enabled:
        raise CloudError(
            "ingest_unconfigured",
            "This cloud host accepts no monitoring-host traffic yet: no service key is "
            "configured (CLOUD_SERVICE_KEYS_JSON / CLOUD_INGEST_KEY_ID).",
            status_code=503,
        )
    if len(body) > MAX_BODY_BYTES:
        raise CloudError(
            "payload_too_large",
            f"Ingest bodies are limited to {MAX_BODY_BYTES // (1024 * 1024)} MiB.",
            status_code=413,
        )

    try:
        signed = signing.verify(
            method=method,
            path=path,
            body=body,
            headers=headers,
            credentials=settings.service_keys,
            max_skew_seconds=settings.ingest_max_skew_seconds,
        )
    except signing.SignatureError as exc:
        # The code is safe to return; the message never contains the secret. What a caller who
        # is not the monitoring host learns from these is only that they are not recognised.
        raise CloudError(
            exc.code, "The service signature for this request is not valid.", status_code=401
        ) from exc

    _consume_nonce(session, signed)
    return signed


def _consume_nonce(session: Session, signed: signing.SignedRequest) -> None:
    """Persist the nonce. A collision means this exact request has been here before.

    The insert goes through a savepoint: the constraint violation would otherwise poison the
    caller's transaction, and this route is about to answer 401 with a body - the rollback of
    the failed request must not be the rollback of the incident it follows in the same session.
    """
    try:
        with session.begin_nested():
            session.add(IngestNonce(key_id=signed.key_id, nonce=signed.nonce))
    except IntegrityError as exc:
        LOGGER.warning("replayed ingest request from %s", redact(signed.key_id))
        raise CloudError(
            "replay_detected",
            "This request has already been processed once.",
            status_code=401,
        ) from exc


def parse_body(signed: signing.SignedRequest) -> dict[str, Any]:
    try:
        parsed = json.loads(signed.body or b"{}")
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise CloudError(
            "invalid_json", "The request body is not JSON.", status_code=422
        ) from exc
    if not isinstance(parsed, dict):
        raise CloudError("invalid_json", "The request body must be a JSON object.", status_code=422)
    return parsed


def begin(session: Session, signed: signing.SignedRequest, body: dict[str, Any]) -> IngestCall:
    """Look up the idempotency key and hand back something a route can act on."""
    key = str(body.get("idempotency_key") or "").strip()
    if not key:
        raise CloudError(
            "idempotency_key_required",
            "Every ingest call carries an idempotency_key.",
            status_code=422,
        )
    if len(key) > 160:
        raise CloudError("idempotency_key_invalid", "idempotency_key is too long.", status_code=422)
    existing = session.scalar(select(IngestRecord).where(IngestRecord.idempotency_key == key))
    if existing is not None and existing.request_digest != signed.content_sha256:
        # The same key carrying different bytes is not a retry, it is a different alert that has
        # been given a used key. Answering it with the stored response would report success while
        # discarding this content, which is how an alert disappears without leaving a failure.
        LOGGER.warning(
            "idempotency conflict on key %s from %s: digest differs from the stored request",
            redact(key),
            redact(signed.key_id),
        )
        raise CloudError(
            "idempotency_conflict",
            "This idempotency_key was already used for a different request body.",
            status_code=409,
        )
    return IngestCall(
        signed=signed,
        key_id=signed.key_id,
        body=body,
        idempotency_key=key,
        duplicate_of=existing,
    )


def record(
    session: Session,
    call: IngestCall,
    *,
    route: str,
    incident_id: int | None,
    response: dict[str, Any],
) -> IngestRecord:
    """Store the first answer so a retry can be given the same one.

    The unique index on `idempotency_key` is the guarantee; a second writer racing the same key
    loses and reads back what the winner stored rather than duplicating the work.
    """
    row = IngestRecord(
        idempotency_key=call.idempotency_key,
        route=route[:96],
        key_id=call.key_id[:64],
        request_digest=call.signed.content_sha256,
        incident_id=incident_id,
        response=response,
    )
    try:
        with session.begin_nested():
            session.add(row)
    except IntegrityError:
        stored = session.scalar(
            select(IngestRecord).where(IngestRecord.idempotency_key == call.idempotency_key)
        )
        if stored is None:
            raise
        return stored
    return row
