"""Turns raw detector findings into candidate `DetectionEvent` rows (proposal section 11).

Two rules drive this module. The first is confidence gating against both the policy and the
platform floor, because a candidate is only useful if a human can still triage the queue.
The second is duplicate suppression: a zone that stays busy must not become an alert storm,
so a repeat of an event for the same camera+category+zone inside the duplicate window records
the continuation without emitting another alert.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import math
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

import numpy as np
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Camera, DetectionEvent, EventStatus, MonitoringPolicy
from ..security.secrets import REDACTED_PLACEHOLDER, key_is_secret, redact
from .detectors import FULL_FRAME_ZONE_ID, RawFinding

JPEG_MAGIC = b"\xff\xd8"
MIN_DUPLICATE_WINDOW_SECONDS = 5
MAX_DISTINCT_DEDUPE_ROWS = 200
SANITIZE_MAX_CHARS = 160
# Component caps keep the composed dedupe_key inside the column's 160 characters without
# ever cutting the window slot off the end.
MAX_CATEGORY_CHARS = 48
MAX_ZONE_CHARS = 60
_SAFE_KEY_RE = re.compile(r"[^A-Za-z0-9_.:-]+")


@dataclass(frozen=True, slots=True)
class EvidenceRef:
    """A reference to a stored snapshot, never its bytes."""

    storage_key: str
    sha256: str
    byte_size: int
    content_type: str = "image/jpeg"

    def as_metadata(self) -> dict[str, Any]:
        return {
            "storage_key": self.storage_key,
            "sha256": self.sha256,
            "byte_size": self.byte_size,
            "content_type": self.content_type,
        }


@runtime_checkable
class EvidenceWriter(Protocol):
    """Stores a JPEG snapshot outside the database and returns its reference."""

    def write_snapshot(
        self,
        *,
        camera_code: str,
        category: str,
        occurred_at: dt.datetime,
        jpeg: bytes,
    ) -> EvidenceRef | None: ...


class LocalEvidenceWriter:
    """Writes snapshots beneath a root directory; a stand-in for object storage."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def write_snapshot(
        self,
        *,
        camera_code: str,
        category: str,
        occurred_at: dt.datetime,
        jpeg: bytes,
    ) -> EvidenceRef | None:
        if not jpeg.startswith(JPEG_MAGIC):
            return None
        safe_code = _SAFE_KEY_RE.sub("-", redact(camera_code)) or "camera"
        safe_category = _SAFE_KEY_RE.sub("-", redact(category)) or "event"
        day = occurred_at.astimezone(dt.UTC)
        # The suffix stops two alerts in one second overwriting a file whose SHA the first event recorded.
        token = uuid.uuid4().hex[:8]
        relative = Path(
            day.strftime("%Y/%m/%d"), f"{safe_code}-{safe_category}-{int(day.timestamp())}-{token}.jpg"
        )
        target = self._root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(jpeg)
        return EvidenceRef(
            storage_key=relative.as_posix(),
            sha256=hashlib.sha256(jpeg).hexdigest(),
            byte_size=len(jpeg),
        )


@dataclass(slots=True)
class EventOutcome:
    """What happened to one finding: the row, and whether it should raise an alert."""

    event: DetectionEvent
    alert: bool
    duplicate: bool
    suppressed: bool
    reason: str = ""


def effective_min_confidence(settings: Settings, policy: MonitoringPolicy) -> float:
    """Higher of the policy target and the platform floor; the floor is not negotiable."""
    return max(float(policy.min_confidence), float(settings.detection_min_confidence))


def effective_window_seconds(settings: Settings, policy: MonitoringPolicy) -> int:
    """Per-policy duplicate window, falling back to the platform default when unset."""
    window = int(policy.duplicate_window_seconds or settings.duplicate_event_window_seconds)
    return max(MIN_DUPLICATE_WINDOW_SECONDS, window)


def dedupe_base(*, camera_id: Any, category: str, zone_id: str) -> str:
    """The situation identity: one camera, one category, one zone."""
    safe_category = (_SAFE_KEY_RE.sub("_", redact(category)) or "event")[:MAX_CATEGORY_CHARS]
    safe_zone = (_SAFE_KEY_RE.sub("_", redact(zone_id or FULL_FRAME_ZONE_ID)) or FULL_FRAME_ZONE_ID)[:MAX_ZONE_CHARS]
    return f"{camera_id}|{safe_category}|{safe_zone}"


def build_dedupe_key(
    *, camera_id: Any, category: str, zone_id: str, occurred_at: dt.datetime, window_seconds: int
) -> str:
    """Time-bucketed key, so a key repeats only while its duplicate window is open."""
    slot = int(occurred_at.timestamp() // max(1, window_seconds))
    return f"{dedupe_base(camera_id=camera_id, category=category, zone_id=zone_id)}|w{slot}"


def sanitize_metadata(finding: RawFinding, *, camera: Camera, zone_source: str) -> dict[str, Any]:
    """Scalar, redacted finding detail plus camera context; pixel data never belongs here."""
    metadata: dict[str, Any] = {
        "camera_code": redact(camera.code)[:SANITIZE_MAX_CHARS],
        "zone_id": redact(finding.zone_id)[:SANITIZE_MAX_CHARS],
        "zone_source": zone_source,
        "detector": redact(str(finding.detail.get("detector") or finding.category))[:SANITIZE_MAX_CHARS],
    }
    for key, value in finding.detail.items():
        if key in ("zone_id", "detector"):
            continue
        metadata[str(key)] = REDACTED_PLACEHOLDER if key_is_secret(key) else _scalar(value)
    return metadata


def recent_event(
    session: Session, *, camera_id: Any, base_key: str, since: dt.datetime
) -> DetectionEvent | None:
    """Newest event whose base key matches, within the duplicate window."""
    rows = (
        session.scalars(
            select(DetectionEvent)
            .where(
                DetectionEvent.camera_id == camera_id,
                DetectionEvent.dedupe_key.is_not(None),
                DetectionEvent.occurred_at >= since,
            )
            .order_by(DetectionEvent.occurred_at.desc())
            .limit(MAX_DISTINCT_DEDUPE_ROWS)
        )
    ).all()
    for row in rows:
        if row.dedupe_key and row.dedupe_key.rsplit("|w", 1)[0] == base_key:
            return row
    return None


def touch_event(
    session: Session, event: DetectionEvent, *, occurred_at: dt.datetime, confidence: float
) -> DetectionEvent:
    """Record a repeat on the alerting row instead of inserting a duplicate key."""
    metadata = dict(event.event_metadata or {})
    metadata["seen_count"] = int(metadata.get("seen_count", 1)) + 1
    metadata["last_seen_at"] = occurred_at.isoformat()
    metadata["peak_confidence"] = max(float(metadata.get("peak_confidence", event.confidence)), confidence)
    event.event_metadata = metadata
    session.flush()
    return event


def _attach_snapshot(
    metadata: dict[str, Any],
    outcome: EventOutcome,
    *,
    camera: Camera,
    category: str,
    occurred_at: dt.datetime,
    snapshot: bytes | None,
    evidence_writer: EvidenceWriter | None,
) -> None:
    """Write evidence only for the event that alerts; repeats point at nothing new."""
    if outcome.duplicate:
        metadata["snapshot"] = "not_captured_repeat"
        return
    if snapshot is None:
        metadata["snapshot"] = "no_frame_available"
        return
    if evidence_writer is None:
        metadata["snapshot"] = "evidence_writer_not_configured"
        return
    ref = evidence_writer.write_snapshot(
        camera_code=camera.code,
        category=category,
        occurred_at=occurred_at,
        jpeg=snapshot,
    )
    metadata["snapshot"] = ref.as_metadata() if ref is not None else "snapshot_rejected_by_writer"


def submit_finding(
    session: Session,
    *,
    camera: Camera,
    policy: MonitoringPolicy,
    settings: Settings,
    finding: RawFinding,
    occurred_at: dt.datetime,
    measured_fps: float = 0.0,
    snapshot: bytes | None = None,
    evidence_writer: EvidenceWriter | None = None,
    zone_source: str = "policy",
) -> EventOutcome | None:
    """Persist one candidate event, or fold it into the event it duplicates."""
    floor = effective_min_confidence(settings, policy)
    confidence = float(finding.confidence)
    if not math.isfinite(confidence) or confidence < floor:
        return None

    window = effective_window_seconds(settings, policy)
    key = build_dedupe_key(
        camera_id=camera.id,
        category=finding.category,
        zone_id=finding.zone_id,
        occurred_at=occurred_at,
        window_seconds=window,
    )
    base = dedupe_base(camera_id=camera.id, category=finding.category, zone_id=finding.zone_id)
    metadata = sanitize_metadata(finding, camera=camera, zone_source=zone_source)
    metadata["measured_fps"] = round(float(measured_fps), 3)
    metadata["confidence"] = round(confidence, 4)
    metadata["seen_count"] = 1
    metadata["peak_confidence"] = confidence

    existing = session.scalar(
        select(DetectionEvent)
        .where(DetectionEvent.camera_id == camera.id, DetectionEvent.dedupe_key == key)
        .order_by(DetectionEvent.occurred_at.desc())
        .limit(1)
    )
    if existing is not None:
        touch_event(session, existing, occurred_at=occurred_at, confidence=confidence)
        return EventOutcome(existing, alert=False, duplicate=True, suppressed=True, reason="same_window")

    since = occurred_at - dt.timedelta(seconds=window)
    recent = recent_event(session, camera_id=camera.id, base_key=base, since=since)
    if recent is not None:
        metadata["duplicate_of_event_id"] = recent.id

    event = DetectionEvent(
        camera_id=camera.id,
        policy_id=policy.id,
        category=redact(finding.category)[:64],
        confidence=round(confidence, 4),
        occurred_at=occurred_at,
        event_metadata=metadata,
        status=EventStatus.NEW.value,
        dedupe_key=key,
        suppressed=recent is not None,
    )
    if event.suppressed:
        outcome = EventOutcome(event, alert=False, duplicate=True, suppressed=True, reason="overlapping_window")
    else:
        outcome = EventOutcome(event, alert=True, duplicate=False, suppressed=False, reason="new_event")

    _attach_snapshot(
        metadata,
        outcome,
        camera=camera,
        category=finding.category,
        occurred_at=occurred_at,
        snapshot=snapshot,
        evidence_writer=evidence_writer,
    )

    try:
        with session.begin_nested():
            session.add(event)
            session.flush()
    except IntegrityError:
        # A concurrent poller won this key, so fold the finding into its row instead of
        # emitting a second alert for the same situation.
        winner = session.scalar(
            select(DetectionEvent)
            .where(DetectionEvent.camera_id == camera.id, DetectionEvent.dedupe_key == key)
            .order_by(DetectionEvent.occurred_at.desc())
            .limit(1)
        )
        if winner is None:
            raise
        touch_event(session, winner, occurred_at=occurred_at, confidence=confidence)
        return EventOutcome(winner, alert=False, duplicate=True, suppressed=True, reason="concurrent_same_key")
    return outcome


def submit_findings(
    session: Session,
    *,
    camera: Camera,
    policy: MonitoringPolicy,
    settings: Settings,
    findings: Sequence[RawFinding],
    occurred_at: dt.datetime,
    measured_fps: float = 0.0,
    snapshot: bytes | None = None,
    evidence_writer: EvidenceWriter | None = None,
    zone_source: str = "policy",
) -> list[EventOutcome]:
    """Submit every finding from one analysed frame; alerting events come first."""
    outcomes: list[EventOutcome] = []
    for index, finding in enumerate(findings):
        outcome = submit_finding(
            session,
            camera=camera,
            policy=policy,
            settings=settings,
            finding=finding,
            occurred_at=occurred_at,
            measured_fps=measured_fps,
            # One snapshot per alerting finding keeps evidence volume tied to alert volume.
            snapshot=snapshot if index == 0 else None,
            evidence_writer=evidence_writer,
            zone_source=zone_source,
        )
        if outcome is not None:
            outcomes.append(outcome)
    return outcomes


def _scalar(value: Any) -> Any:
    """Keep only JSON-safe scalars, redacting any string on its way into a database row."""
    if isinstance(value, (np.ndarray, bytes, bytearray)):
        return None
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED_PLACEHOLDER if key_is_secret(key) else _scalar(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scalar(item) for item in value][:32]
    if isinstance(value, float):
        return None if math.isnan(value) or math.isinf(value) else value
    if isinstance(value, (int, bool)) or value is None:
        return value
    return redact(str(value))[:SANITIZE_MAX_CHARS]
