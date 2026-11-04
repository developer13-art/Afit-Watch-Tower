"""The signed inbound door: monitoring host to cloud (contract section 9).

Nothing here is reachable with a person's token, and nothing here trusts the payload it receives
before the signature, timestamp, nonce and content digest have all passed. The four checks and
their order live in `watchtower.cloud.ingest`; this module is only what to do once a call has
earned the right to be acted on.

The cloud does not create incidents. The monitoring host wrote the incident row in the shared
database, carried that row's id in the payload, and this service *links* to it: notifications,
relay states and ingest records all reference the same primary key. A payload describing an
incident that is not in the table is refused permanently, because inventing a second record of a
security event is the failure mode the whole design exists to avoid.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...mobile.models import (
    EvidenceRelayState,
    IngestRecord,
    MonitoringHeartbeat,
    UploadState,
)
from ...models import EvidenceAsset, Incident, Severity, utcnow
from ...security.secrets import redact
from .. import ingest as gate
from .. import storage
from ..config import CloudSettings
from ..delivery import enqueue_alert
from ..deps import get_db, get_settings
from ..errors import CloudError
from ..targeting import AlertIntent

LOGGER = logging.getLogger("watchtower.cloud.ingest")

router = APIRouter(prefix="/ingest", tags=["ingest"])

MAX_BASE64_OVERHEAD = 4  # base64 grows the payload by 4/3; beyond that it is not a file we sent


async def read_body(request: Request) -> bytes:
    """The raw bytes, because the signature covers bytes and not a re-serialisation.

    `content-length` is checked first so an oversized request is refused before it is buffered;
    the second check after reading is the one that counts, since the header can lie.
    """
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > gate.MAX_BODY_BYTES:
        raise CloudError(
            "payload_too_large",
            f"Ingest bodies are limited to {gate.MAX_BODY_BYTES // (1024 * 1024)} MiB.",
            status_code=413,
        )
    body = await request.body()
    if len(body) > gate.MAX_BODY_BYTES:
        raise CloudError(
            "payload_too_large",
            f"Ingest bodies are limited to {gate.MAX_BODY_BYTES // (1024 * 1024)} MiB.",
            status_code=413,
        )
    return body


def _verified(request: Request, body: bytes, session: Session, settings: CloudSettings) -> Any:
    signed = gate.verify(
        session=session,
        settings=settings,
        method=request.method,
        path=request.url.path,
        headers=dict(request.headers),
        body=body,
    )
    parsed = gate.parse_body(signed)
    return signed, parsed


def _int(value: Any, *, name: str) -> int:
    """A count the sender meant as a number. Malformed text is the sender's error, not ours."""
    if value in (None, ""):
        return 0
    if isinstance(value, bool):
        raise CloudError("validation_failed", f"{name} must be a whole number.", status_code=422)
    try:
        return max(int(value), 0)
    except (TypeError, ValueError) as exc:
        raise CloudError(
            "validation_failed", f"{name} must be a whole number.", status_code=422
        ) from exc


def _severity(value: Any) -> str:
    known = {item.value for item in Severity}
    text = str(value or "")
    return text if text in known else Severity.MEDIUM.value


def _uuid(value: Any) -> uuid.UUID | None:
    if value in (None, ""):
        return None
    try:
        return uuid.UUID(str(value))
    except (ValueError, AttributeError):
        return None


def _occurred_at(payload: dict[str, Any]) -> dt.datetime:
    raw = payload.get("occurred_at")
    if isinstance(raw, str):
        try:
            parsed = dt.datetime.fromisoformat(raw.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
        except ValueError:
            pass
    return utcnow()


@router.post("/incident", status_code=201)
async def ingest_incident(
    request: Request,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
):
    body = await read_body(request)
    signed, payload = _verified(request, body, session, settings)
    call = gate.begin(session, signed, payload)
    if call.is_duplicate and call.duplicate_of is not None:
        return {**dict(call.duplicate_of.response or {}), "duplicate": True}

    incident_block = payload.get("incident") or {}
    incident_id = incident_block.get("id") or payload.get("incident_id")
    if not isinstance(incident_id, int):
        raise CloudError(
            "incident_id_required",
            "The payload must carry the id of the incident the monitoring host already wrote.",
            status_code=422,
        )
    incident = session.get(Incident, incident_id)
    if incident is None:
        # 410 rather than 404: the forwarder treats both as permanent, and this says the record
        # is gone rather than "maybe it will appear".
        raise CloudError(
            "incident_unavailable",
            "This incident is not in the shared database; the cloud does not create incidents.",
            status_code=410,
        )

    kind = str(payload.get("kind") or incident_block.get("kind") or "incident.created")
    intent = AlertIntent(
        kind=kind[:48],
        severity=_severity(incident_block.get("severity") or incident.severity),
        title=str(incident_block.get("title") or incident.title)[:200],
        body=str(payload.get("body") or incident.summary or incident.title)[:2000],
        incident_id=incident.id,
        camera_id=_uuid(incident_block.get("camera_id") or incident.camera_id),
        event_id=incident_block.get("origin_event_id"),
        requires_action=not kind.endswith("resolved"),
    )
    report = enqueue_alert(session, settings, intent)
    response = {
        "incident_id": incident.id,
        "reference": incident.reference,
        "notifications_created": report.created,
        "notifications_suppressed": report.suppressed,
        "devices_targeted": report.devices_targeted,
        "delivery": "queued",
        "occurred_at": _occurred_at(payload).isoformat(),
    }
    gate.record(session, call, route="/api/v1/ingest/incident", incident_id=incident.id,
                response=response)
    return response


@router.post("/heartbeat")
async def ingest_heartbeat(
    request: Request,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
):
    body = await read_body(request)
    signed, payload = _verified(request, body, session, settings)
    host = str(payload.get("monitoring_host") or "").strip()
    if not host:
        raise CloudError("monitoring_host_required", "monitoring_host is required.", status_code=422)
    row = MonitoringHeartbeat(
        monitoring_host=host[:128],
        app_version=str(payload.get("app_version") or "")[:32] or None,
        outbox_pending=_int(payload.get("outbox_pending"), name="outbox_pending"),
        outbox_failed=_int(payload.get("outbox_failed"), name="outbox_failed"),
    )
    session.add(row)
    session.flush()
    LOGGER.info(
        "heartbeat from %s: %s pending, %s failed",
        redact(host),
        row.outbox_pending,
        row.outbox_failed,
    )
    del signed
    return {
        "received_at": row.received_at.isoformat(),
        "monitoring_host": row.monitoring_host,
        "next_heartbeat_seconds": max(int(settings.supervision_poll_seconds), 5),
    }


@router.post("/outbox-ack")
async def ingest_outbox_ack(
    request: Request,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
):
    """Confirm that a key was processed. Acking an unknown key says so, and is not an error.

    The local row already settled when the original call answered 2xx; this is the belt to that
    brace, used by the console's "is the forwarder alive?" screen and by an operator replaying a
    batch.
    """
    body = await read_body(request)
    signed, payload = _verified(request, body, session, settings)
    key = str(payload.get("idempotency_key") or "").strip()
    if not key:
        raise CloudError("idempotency_key_required", "idempotency_key is required.", status_code=422)
    row = session.scalar(select(IngestRecord).where(IngestRecord.idempotency_key == key[:160]))
    del signed
    if row is None:
        return {"processed": False, "idempotency_key": key}
    return {
        "processed": True,
        "idempotency_key": key,
        "incident_id": row.incident_id,
        "processed_at": row.processed_at.isoformat(),
    }


@router.post("/evidence/{asset_id}", status_code=201)
async def ingest_evidence(
    asset_id: int,
    request: Request,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
):
    """Receive one relayed asset's bytes and put them where a phone can reach them.

    The row already exists - the monitoring host created it when it captured the frame. What the
    cloud adds is the file, under the same `storage_key`, inside `CLOUD_EVIDENCE_DIR`, verified
    against the digest on the row before the temporary file is renamed into place.
    """
    body = await read_body(request)
    signed, payload = _verified(request, body, session, settings)
    relay_key = str(payload.get("idempotency_key") or f"evidence:{asset_id}").strip()
    payload = {**payload, "idempotency_key": relay_key}
    call = gate.begin(session, signed, payload)
    if call.is_duplicate and call.duplicate_of is not None:
        return {**dict(call.duplicate_of.response or {}), "duplicate": True}

    asset = session.get(EvidenceAsset, asset_id)
    if asset is None or asset.deleted_at is not None:
        raise CloudError("not_found", "No such evidence asset.", status_code=404)

    declared_digest = str(payload.get("sha256") or asset.sha256)
    if declared_digest != asset.sha256:
        # The sender is describing bytes that are not the ones on the record it names.
        _relay_state(session, asset, UploadState.MISSING, declared_digest, None, 0,
                     error="declared digest differs from the asset row", durable=True)
        raise CloudError(
            "evidence_digest_mismatch",
            "The declared digest does not match the asset record.",
            status_code=422,
        )

    encoded = payload.get("data_base64")
    if not isinstance(encoded, str) or not encoded:
        raise CloudError("evidence_data_required", "data_base64 is required.", status_code=422)
    if len(encoded) > gate.MAX_BODY_BYTES * MAX_BASE64_OVERHEAD:
        raise CloudError("payload_too_large", "This relay is too large.", status_code=413)
    try:
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise CloudError(
            "evidence_data_invalid", "data_base64 is not valid base64.", status_code=422
        ) from exc

    if payload.get("byte_size") in (None, ""):
        raise CloudError(
            "evidence_size_required", "byte_size is required.", status_code=422
        )
    declared_size = _int(payload.get("byte_size"), name="byte_size")
    if declared_size != len(data) or (asset.byte_size and asset.byte_size != len(data)):
        # Both the sender's word and the row it names have to agree with the bytes actually here.
        _relay_state(session, asset, UploadState.MISSING, declared_digest, None, len(data),
                     error="declared byte size differs from the bytes received", durable=True)
        raise CloudError(
            "evidence_size_mismatch",
            "The declared byte size does not match the data received.",
            status_code=422,
        )
    # The row written by the monitoring host decides what this asset is and what header it may
    # later be served with. The `kind`/`content_type` inside the relay body is only what the
    # sender claims: letting it through would turn another machine's string into a browser
    # instruction, so it is checked for agreement and then discarded.
    declared_kind = str(payload.get("kind") or asset.kind)
    declared_type = str(payload.get("content_type") or asset.content_type)
    if declared_kind != asset.kind or declared_type != asset.content_type:
        _relay_state(session, asset, UploadState.MISSING, declared_digest, None, len(data),
                     error="declared kind or content type differs from the asset row", durable=True)
        raise CloudError(
            "evidence_metadata_mismatch",
            "The declared asset kind or content type does not match the asset record.",
            status_code=422,
        )
    if not storage.content_type_allowed(asset):
        # The row itself says this asset can never be served, so the attempt is recorded rather
        # than left as a permanent "still arriving".
        _relay_state(session, asset, UploadState.MISSING, declared_digest, None, len(data),
                     error="asset kind or content type is not accepted by the cloud", durable=True)
        raise CloudError(
            "evidence_type_unsupported",
            "This asset kind or content type is not accepted.",
            status_code=422,
        )

    try:
        storage.store_bytes(settings, asset.storage_key, data, expected_sha256=asset.sha256)
    except CloudError as exc:
        # The declared digest matched but the bytes did not: something between the two hosts
        # changed them, and the phone must never be offered the file it is waiting for.
        _relay_state(session, asset, UploadState.MISSING, declared_digest, None, len(data),
                     error=str(exc), durable=True)
        raise
    digest = storage.sha256_of(settings, asset.storage_key)
    state = _relay_state(
        session, asset, UploadState.AVAILABLE, declared_digest, digest, len(data), error=None
    )
    response = {
        "asset_id": asset.id,
        "stored": True,
        "bytes_received": len(data),
        "state": state.state,
        "incident_id": asset.incident_id,
    }
    gate.record(
        session, call, route=f"/api/v1/ingest/evidence/{asset_id}",
        incident_id=asset.incident_id, response=response,
    )
    return response


def _relay_state(
    session: Session,
    asset: EvidenceAsset,
    state: UploadState,
    expected: str | None,
    received: str | None,
    byte_count: int,
    *,
    error: str | None,
    durable: bool = False,
) -> EvidenceRelayState:
    """Record what happened to the cloud's copy, without touching the shared asset row.

    `durable=True` belongs on the refusal paths. The request that refuses is rolled back on its
    way out of `get_db`, and "an attempt arrived and did not match the record" is a fact worth
    keeping through that rollback - it is what turns an app screen saying "evidence still
    arriving" into one saying what is actually wrong. The write stays in this session and commits
    here rather than opening a second connection, which would contend with the lock this
    transaction already holds.
    """
    row = session.scalar(
        select(EvidenceRelayState).where(EvidenceRelayState.asset_id == asset.id)
    )
    if row is None:
        row = EvidenceRelayState(asset_id=asset.id)
        session.add(row)
    row.state = state.value
    row.expected_sha256 = (expected or row.expected_sha256 or asset.sha256)[:64]
    row.received_sha256 = received[:64] if received else None
    row.bytes_received = byte_count
    row.last_error = (error or "")[:256] or None
    session.flush()
    if durable:
        session.commit()
    return row
