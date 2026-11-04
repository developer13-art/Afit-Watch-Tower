"""Transactional outbox and the local-to-cloud forwarder (mobile proposal sections 4, 10, 11).

Why an outbox instead of calling the cloud from the request handler: the incident row and the
alert must either both exist or neither exist. A direct HTTP call inside the transaction would
either hold a database transaction open across a network round trip, or commit the incident
and then discover the internet is down - which is precisely the failure the proposal forbids.

So: `enqueue()` writes a row in the caller's transaction. A separate worker reads due rows,
signs an HTTPS POST, and settles them. Retries are ordinary row updates, so a restart loses
nothing and the queue is inspectable with SQL.

Two distinct outages are handled, and they need different mechanisms:

  * **Cloud unreachable, database reachable** - the normal case. Rows stay `queued` with a
    `next_retry_at` and the worker comes back. Nothing local is needed.
  * **Database unreachable** - the row cannot exist, so the intent is written to a JSONL spool
    under `settings.spool_dir` and replayed into the outbox on a later cycle. The spool is
    deliberately small and dumb: it exists so an alert intent is not silently discarded, and
    `replay()` is the only thing that reads it back.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import logging
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import and_, func, or_, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from ..config import Settings
from ..models import Camera, DetectionEvent, EvidenceAsset, Incident, Severity, utcnow
from ..security.secrets import redact
from . import signing
from .models import NotificationOutbox, OutboxState

LOGGER = logging.getLogger("watchtower.mobile.outbox")

SPOOL_NAME = "outbox-spool.jsonl"
SPOOL_MAX_LINES = 5000
INCIDENT_ROUTE = "/api/v1/ingest/incident"
HEARTBEAT_ROUTE = "/api/v1/ingest/heartbeat"
EVIDENCE_ROUTE = "/api/v1/ingest/evidence"

# A response code that means "the cloud will never accept this as-is". Retrying it burns
# attempts and hides the real problem, which is a misconfiguration or a rejected payload.
PERMANENT_STATUS = frozenset({400, 401, 403, 404, 410, 413, 422})

# Rows still owed work. `processing` counts as pending because a worker that died mid-send
# leaves the row there; `claim_due` only re-takes such a row once it looks abandoned.
_PENDING_STATES = (
    OutboxState.QUEUED.value,
    OutboxState.PROCESSING.value,
    OutboxState.FAILED.value,
)
STALE_PROCESSING_SECONDS = 900


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value


# --------------------------------------------------------------------------- #
# Idempotency keys
# --------------------------------------------------------------------------- #


def incident_key(*, incident_id: int, kind: str = "created") -> str:
    return f"incident:{incident_id}:{kind}"


def event_key(*, event_id: int) -> str:
    return f"event:{event_id}:candidate"


def health_key(*, camera_id: Any, reason_code: str, status: str) -> str:
    return f"health:{camera_id}:{status}:{reason_code}"


# --------------------------------------------------------------------------- #
# Enqueue
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class EnqueueIntent:
    """Everything needed to write an outbox row later, if it cannot be written now."""

    kind: str
    severity: str
    title: str
    body: str
    idempotency_key: str
    payload: dict[str, Any] = field(default_factory=dict)
    incident_id: int | None = None
    event_id: int | None = None
    camera_id: str | None = None
    evidence_keys: list[str] = field(default_factory=list)

    def as_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "severity": self.severity,
            "title": self.title,
            "body": self.body,
            "idempotency_key": self.idempotency_key,
            "payload": self.payload,
            "incident_id": self.incident_id,
            "event_id": self.event_id,
            "camera_id": str(self.camera_id) if self.camera_id else None,
            "evidence_keys": list(self.evidence_keys),
        }

    @classmethod
    def from_json(cls, raw: dict[str, Any]) -> EnqueueIntent:
        return cls(
            kind=str(raw["kind"]),
            severity=str(raw.get("severity") or Severity.MEDIUM.value),
            title=str(raw.get("title") or ""),
            body=str(raw.get("body") or ""),
            idempotency_key=str(raw["idempotency_key"]),
            payload=dict(raw.get("payload") or {}),
            incident_id=raw.get("incident_id"),
            event_id=raw.get("event_id"),
            camera_id=raw.get("camera_id"),
            evidence_keys=list(raw.get("evidence_keys") or []),
        )


def intent_for_incident(
    incident: Incident,
    *,
    camera: Camera | None = None,
    event: DetectionEvent | None = None,
    kind: str = "created",
) -> EnqueueIntent:
    """The ingest body the contract promises, built from rows that already exist.

    The cloud reads the same incident row from the same database, so this payload is a
    cross-check and a display hint, not the source of truth. Camera credentials are not
    reachable from these columns at all, which is the point.
    """
    metadata = dict(event.event_metadata or {}) if event else {}
    payload: dict[str, Any] = {
        "idempotency_key": incident_key(incident_id=incident.id, kind=kind),
        "occurred_at": _as_utc(incident.occurred_at).isoformat(),
        "incident": {
            "id": incident.id,
            "reference": incident.reference,
            "title": incident.title,
            "summary": incident.summary,
            "category": incident.category,
            "severity": incident.severity,
            "status": incident.status,
            "camera_id": str(incident.camera_id) if incident.camera_id else None,
            "camera_name": camera.display_name if camera else None,
            "campus_location": incident.campus_location
            or (camera.campus_location if camera else None),
            "detection_source": "manual" if event is None else "ai_candidate",
            "confidence": metadata.get("peak_confidence", metadata.get("confidence")),
            "origin_event_id": incident.origin_event_id,
        },
    }
    return EnqueueIntent(
        kind=f"incident.{kind}",
        severity=incident.severity,
        title=incident.title[:200],
        body=(incident.summary or incident.title)[:2000],
        idempotency_key=payload["idempotency_key"],
        payload=payload,
        incident_id=incident.id,
        event_id=event.id if event else None,
        camera_id=str(incident.camera_id) if incident.camera_id else None,
    )


def find_by_key(session: Session, idempotency_key: str) -> NotificationOutbox | None:
    return session.scalar(
        select(NotificationOutbox).where(
            NotificationOutbox.idempotency_key == idempotency_key
        )
    )


def enqueue(session: Session, intent: EnqueueIntent) -> NotificationOutbox | None:
    """Write the outbox row in the caller's transaction.

    Returning the existing row on a key collision is what makes a re-run of the same
    escalation idempotent rather than a second push to every phone.
    """
    existing = find_by_key(session, intent.idempotency_key)
    if existing is not None:
        return existing
    row = NotificationOutbox(
        idempotency_key=intent.idempotency_key,
        kind=intent.kind,
        severity=intent.severity,
        title=intent.title,
        body=intent.body,
        payload=intent.payload,
        evidence_keys=list(intent.evidence_keys),
        incident_id=intent.incident_id,
        event_id=intent.event_id,
        camera_id=_as_uuid(intent.camera_id),
        state=OutboxState.QUEUED.value,
        next_retry_at=utcnow(),
    )
    session.add(row)
    session.flush()
    return row


def _as_uuid(value: str | None) -> uuid.UUID | None:
    if value is None:
        return None
    try:
        return uuid.UUID(str(value))
    except ValueError:
        return None


def enqueue_or_spool(settings: Settings, session: Session, intent: EnqueueIntent) -> str:
    """Enqueue, or spool the intent if the database is unreachable.

    Returns `"queued"`, `"spooled"` or `"duplicate"`. Never raises: the caller is usually a
    background loop that has other cameras to look at, and a lost alert must at least be
    written down somewhere durable rather than turning into an exception.
    """
    try:
        if find_by_key(session, intent.idempotency_key) is not None:
            return "duplicate"
        enqueue(session, intent)
        session.flush()
        return "queued"
    except SQLAlchemyError as exc:
        Spool(settings.spool_dir).append(intent)
        LOGGER.error("outbox enqueue failed, spooled instead: %s", redact(str(exc)))
        return "spooled"


# --------------------------------------------------------------------------- #
# Spool
# --------------------------------------------------------------------------- #


class Spool:
    """Append-only JSONL holding alert intents the database could not accept."""

    def __init__(self, directory: Path) -> None:
        self.directory = Path(directory)
        self.path = self.directory / SPOOL_NAME

    def append(self, intent: EnqueueIntent) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(intent.as_json(), sort_keys=True) + "\n")

    def pending(self) -> list[EnqueueIntent]:
        if not self.path.exists():
            return []
        intents: list[EnqueueIntent] = []
        seen: set[str] = set()
        for line in self.path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                intent = EnqueueIntent.from_json(json.loads(line))
            except (ValueError, KeyError):
                # A torn final line after a crash is skipped, not fatal to the rest.
                continue
            if intent.idempotency_key in seen:
                continue
            seen.add(intent.idempotency_key)
            intents.append(intent)
        return intents[:SPOOL_MAX_LINES]

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)

    def rewrite(self, intents: Sequence[EnqueueIntent]) -> None:
        if not intents:
            self.clear()
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            "".join(json.dumps(item.as_json(), sort_keys=True) + "\n" for item in intents),
            encoding="utf-8",
        )

    def replay(self, session: Session) -> int:
        """Move spooled intents into the outbox; only drop a line once its row exists."""
        pending = self.pending()
        if not pending:
            return 0
        moved = 0
        remaining: list[EnqueueIntent] = []
        for intent in pending:
            try:
                enqueue(session, intent)
                session.flush()
            except SQLAlchemyError:
                remaining.append(intent)
                continue
            except Exception as exc:  # noqa: BLE001 - a malformed intent must not wedge replay
                LOGGER.error("spool replay refused %s: %s", intent.idempotency_key, redact(str(exc)))
                continue
            moved += 1
        self.rewrite(remaining)
        if moved:
            LOGGER.info("replayed %d spooled alert intent(s) into the outbox", moved)
        return moved


# --------------------------------------------------------------------------- #
# Claiming and settling
# --------------------------------------------------------------------------- #


def claim_due(
    session: Session, *, now: dt.datetime, limit: int
) -> list[NotificationOutbox]:
    """Rows ready to be sent, oldest first, locked so two workers cannot take the same one.

    A row left in `processing` is normally a live send, so it is only reclaimable once it is
    older than `STALE_PROCESSING_SECONDS` - that is what recovers a worker killed mid-flight
    without letting two workers send the same alert at the same time.

    `FOR UPDATE SKIP LOCKED` is PostgreSQL-only and is the whole point of running this as a
    single worker per monitoring host: a second worker would otherwise wait behind a slow
    HTTPS call. On the SQLite test harness the lock clause is simply not emitted.
    """
    reclaimable = or_(
        NotificationOutbox.state.in_([OutboxState.QUEUED.value, OutboxState.FAILED.value]),
        and_(
            NotificationOutbox.state == OutboxState.PROCESSING.value,
            NotificationOutbox.processing_at
            <= now - dt.timedelta(seconds=STALE_PROCESSING_SECONDS),
        ),
    )
    statement = (
        select(NotificationOutbox)
        .where(reclaimable, NotificationOutbox.next_retry_at <= now)
        .order_by(NotificationOutbox.created_at, NotificationOutbox.id)
        .limit(limit)
    )
    if session.bind is not None and session.bind.dialect.name == "postgresql":
        statement = statement.with_for_update(skip_locked=True)
    rows = list(session.scalars(statement).all())
    if not rows:
        return []
    session.execute(
        update(NotificationOutbox)
        .where(NotificationOutbox.id.in_([row.id for row in rows]))
        .values(state=OutboxState.PROCESSING.value, processing_at=now)
    )
    for row in rows:
        session.expire(row)
    return rows


def backoff_for(settings: Settings, attempts: int) -> dt.timedelta:
    table = settings.outbox_backoff_seconds or (60,)
    index = min(max(attempts - 1, 0), len(table) - 1)
    return dt.timedelta(seconds=int(table[index]))


def mark_delivered(session: Session, row: NotificationOutbox, *, now: dt.datetime) -> None:
    row.state = OutboxState.DELIVERED.value
    row.completed_at = now
    row.next_retry_at = now
    row.last_error = None


def mark_retry(session: Session, settings: Settings, row: NotificationOutbox, *, error: str, now: dt.datetime) -> None:
    row.attempts += 1
    row.last_error = redact(error)[:512]
    if row.attempts >= settings.outbox_max_attempts:
        row.state = OutboxState.DEAD.value
        row.completed_at = now
        LOGGER.error(
            "outbox row %s exhausted after %d attempts; the alert is NOT delivered: %s",
            row.idempotency_key,
            row.attempts,
            row.last_error,
        )
    else:
        row.state = OutboxState.FAILED.value
        row.next_retry_at = now + backoff_for(settings, row.attempts)


def mark_permanent(session: Session, row: NotificationOutbox, *, error: str, now: dt.datetime) -> None:
    """No retry will fix this. Left `failed` with a far-future retry so it stays visible."""
    row.attempts += 1
    row.state = OutboxState.FAILED.value
    row.last_error = redact(error)[:512]
    row.next_retry_at = now + dt.timedelta(days=1)


# --------------------------------------------------------------------------- #
# Transport
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class SendResult:
    status: int
    body: bytes = b""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and 200 <= self.status < 300


Sender = Callable[[str, bytes, dict[str, str]], SendResult]


def urllib_sender(timeout: float = 15.0) -> Sender:
    def send(url: str, body: bytes, headers: dict[str, str]) -> SendResult:
        request = urllib.request.Request(  # noqa: S310 - https enforced by config.load_settings
            url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                return SendResult(status=response.status, body=response.read())
        except urllib.error.HTTPError as exc:
            return SendResult(status=exc.code, body=exc.read() or b"", error=f"HTTP {exc.code}")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            return SendResult(status=0, error=redact(str(exc))[:400])

    return send


EvidenceReader = Callable[[str], bytes | None]


# --------------------------------------------------------------------------- #
# Forwarder
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ForwardReport:
    attempted: int = 0
    delivered: int = 0
    retrying: int = 0
    permanent_failures: int = 0
    dead: int = 0
    spooled_replayed: int = 0
    evidence_uploaded: int = 0
    pending: int = 0
    last_error: str | None = None
    last_success_at: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "attempted": self.attempted,
            "delivered": self.delivered,
            "retrying": self.retrying,
            "permanent_failures": self.permanent_failures,
            "dead": self.dead,
            "spooled_replayed": self.spooled_replayed,
            "evidence_uploaded": self.evidence_uploaded,
            "pending": self.pending,
            "last_error": self.last_error,
            "last_success_at": self.last_success_at,
        }


class OutboxForwarder:
    """Drains the outbox over signed HTTPS. One instance per monitoring host."""

    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker[Session],
        *,
        sender: Sender | None = None,
        evidence_reader: EvidenceReader | None = None,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._sender = sender or urllib_sender()
        self._evidence_reader = evidence_reader
        self._credentials = None
        if settings.mobile_forwarding_enabled:
            self._credentials = signing.ServiceCredentials(
                key_id=str(settings.cloud_key_id), secret=str(settings.cloud_key_secret)
            )
        self.report = ForwardReport()
        self.spool = Spool(settings.spool_dir)

    @property
    def enabled(self) -> bool:
        return self._credentials is not None

    def _url(self, route: str) -> str:
        base = (self._settings.cloud_api_url or "").rstrip("/")
        return f"{base}{route}"

    def _post(self, route: str, payload: dict[str, Any]) -> SendResult:
        if self._credentials is None:
            raise RuntimeError("forwarding is not configured; check mobile_forwarding_enabled")
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        headers = signing.build_headers(
            self._credentials, method="POST", path=route, body=body
        )
        return self._sender(self._url(route), body, headers)

    def run_once(self) -> ForwardReport:
        """One drain pass. Safe to call on a timer; a no-op when nothing is due."""
        report = ForwardReport()
        if not self.enabled:
            self.report = report
            return report
        now = utcnow()
        with self._session_factory() as session:
            try:
                report.spooled_replayed = self.spool.replay(session)
                if report.spooled_replayed:
                    session.commit()
            except SQLAlchemyError as exc:
                LOGGER.warning("spool replay deferred: %s", redact(str(exc)))
                session.rollback()

            rows: list[NotificationOutbox] = []
            try:
                rows = claim_due(session, now=now, limit=self._settings.outbox_batch_size)
                session.commit()
            except SQLAlchemyError as exc:
                session.rollback()
                report.last_error = redact(str(exc))[:400]
                self.report = report
                return report

            for row in rows:
                report.attempted += 1
                self._send_row(session, row, now, report)

            try:
                report.pending = pending_count(session)
            except SQLAlchemyError:  # pragma: no cover - reporting only
                report.pending = 0
            self.report = report
        return report

    def _send_row(
        self, session: Session, row: NotificationOutbox, now: dt.datetime, report: ForwardReport
    ) -> None:
        payload = dict(row.payload or {})
        payload.setdefault("idempotency_key", row.idempotency_key)
        result = self._post(INCIDENT_ROUTE, payload)

        if result.ok:
            report.delivered += 1
            report.last_success_at = time.time()
            mark_delivered(session, row, now=now)
            if self._settings.relay_evidence and row.evidence_keys:
                report.evidence_uploaded += self._relay_evidence(session, row, report)
        elif result.status in PERMANENT_STATUS:
            report.permanent_failures += 1
            report.last_error = result.error or f"HTTP {result.status}"
            mark_permanent(session, row, error=result.error or f"HTTP {result.status}", now=now)
        else:
            mark_retry(session, self._settings, row, error=result.error or f"HTTP {result.status}", now=now)
            report.last_error = row.last_error
            if row.state == OutboxState.DEAD.value:
                report.dead += 1
            else:
                report.retrying += 1
        session.commit()

    def _relay_evidence(
        self, session: Session, row: NotificationOutbox, report: ForwardReport
    ) -> int:
        """Upload the bytes the cloud does not have, one asset at a time.

        Each upload is separately idempotent, so an interruption mid-batch resumes rather
        than duplicating an asset the cloud already stored.
        """
        if self._evidence_reader is None:
            return 0
        uploaded = 0
        for storage_key in list(row.evidence_keys):
            asset = session.scalar(
                select(EvidenceAsset).where(EvidenceAsset.storage_key == storage_key)
            )
            if asset is None or asset.deleted_at is not None:
                continue
            data = self._evidence_reader(asset.storage_key)
            if data is None:
                continue
            result = self._post(
                f"{EVIDENCE_ROUTE}/{asset.id}",
                {
                    "idempotency_key": f"evidence:{asset.id}:{asset.sha256[:16]}",
                    "sha256": asset.sha256,
                    "byte_size": len(data),
                    "content_type": asset.content_type,
                    "kind": asset.kind,
                    "captured_at": _as_utc(asset.captured_at).isoformat(),
                    "data_base64": base64.b64encode(data).decode(),
                },
            )
            if result.ok:
                uploaded += 1
            else:
                report.last_error = result.error or f"HTTP {result.status}"
        return uploaded

    def send_heartbeat(self, *, monitoring_host: str, app_version: str) -> SendResult | None:
        if not self.enabled:
            return None
        with self._session_factory() as session:
            summary = queue_summary(session)
        return self._post(
            HEARTBEAT_ROUTE,
            {
                "idempotency_key": f"heartbeat:{monitoring_host}:{int(time.time() // 60)}",
                "monitoring_host": monitoring_host,
                "app_version": app_version,
                "outbox_pending": summary[OutboxState.QUEUED.value]
                + summary[OutboxState.PROCESSING.value]
                + summary[OutboxState.FAILED.value],
                "outbox_failed": summary[OutboxState.DEAD.value],
            },
        )


def pending_count(session: Session) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(NotificationOutbox)
            .where(NotificationOutbox.state.in_(_PENDING_STATES))
        )
        or 0
    )


def queue_summary(session: Session) -> dict[str, int]:
    rows = session.execute(
        select(NotificationOutbox.state, func.count()).group_by(NotificationOutbox.state)
    ).all()
    summary = {state: int(count) for state, count in rows}
    for state in OutboxState:
        summary.setdefault(state.value, 0)
    return summary


def recent_rows(
    session: Session, *, states: Iterable[str], limit: int = 100
) -> list[NotificationOutbox]:
    return list(
        session.scalars(
            select(NotificationOutbox)
            .where(NotificationOutbox.state.in_(list(states)))
            .order_by(NotificationOutbox.created_at.desc())
            .limit(limit)
        ).all()
    )
