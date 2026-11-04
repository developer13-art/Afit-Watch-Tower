"""Personnel-mobile schema layer (mobile proposal sections 4, 8, 10 and 11).

These tables extend the core schema in `watchtower.models`; they do not replace it. The
mobile application reads and writes the *same* `incidents`, `detection_events`,
`evidence_assets`, `notifications` and `audit_logs` rows as the monitoring console, because
both processes point at one Neon database. Duplicating incidents or cameras for the phone
would create two sources of truth about a security event, which is worse than no phone app.

What is genuinely new here:

  * `notification_outbox` - the transactional outbox. A row is written in the same database
    transaction that creates the incident, so an incident can never be recorded while its
    alert is silently lost. It is also the durable queue: an internet outage leaves these
    rows `queued` with a `next_retry_at`, and nothing is dropped.
  * `mobile_devices` - one row per installed app. The FCM registration token is stored
    encrypted with the deployment key ring, never in plaintext: a token is a bearer
    capability to deliver someone's security alerts to a device.
  * `refresh_tokens` - device-bound, single-use, rotated, with reuse detection.
  * `notification_attempts` - per-send records. FCM acceptance, opening and acknowledgement
    are three different facts and are stored as three different facts.
  * `incident_acknowledgements` - the unique constraint is what makes a duplicate
    acknowledgement impossible rather than merely unlikely.
  * `personnel_preferences` - what an individual may silence, with mandatory alerts enforced
    server-side rather than trusted to the client.
  * `ingest_nonces` / `ingest_records` - replay and duplicate protection for the
    service-to-service call from the monitoring host.

Import this module wherever the full metadata is needed (Alembic env, app startup, test
harness). `tests/test_mobile_schema.py` fails if a process forgets to.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import Any
from uuid import UUID

from sqlalchemy import (
    LargeBinary,
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    Uuid,
    Index,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..models import (
    Base,
    Camera,
    EnumColumn,
    Incident,
    JsonType,
    Notification,
    Severity,
    User,
    utcnow,
)


def _utcnow() -> dt.datetime:
    return utcnow()


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class OutboxState(str, enum.Enum):
    QUEUED = "queued"
    PROCESSING = "processing"
    DELIVERED = "delivered"
    FAILED = "failed"
    DEAD = "dead"


class PushState(str, enum.Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    REVOKED = "revoked"
    INVALID = "invalid"


class AttemptState(str, enum.Enum):
    SUBMITTED = "submitted"
    ACCEPTED = "accepted"
    FAILED = "failed"


class EvidenceHost(str, enum.Enum):
    """Where the evidence bytes actually are. The database row is shared; the file is not."""

    MONITOR = "monitor"
    CLOUD = "cloud"


class UploadState(str, enum.Enum):
    AVAILABLE = "available"
    PENDING_UPLOAD = "pending_upload"
    MISSING = "missing"
    DELETED = "deleted"


# --------------------------------------------------------------------------- #
# Transactional outbox
# --------------------------------------------------------------------------- #


class NotificationOutbox(Base):
    """One row per alert the monitoring host must hand to the cloud service.

    `idempotency_key` is unique and stable across retries, so the cloud can answer "already
    processed" instead of sending a second push for the same incident.
    """

    __tablename__ = "notification_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[str] = mapped_column(
        EnumColumn(Severity, "severity"), nullable=False, default=Severity.MEDIUM.value
    )
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_events.id", ondelete="SET NULL")
    )
    camera_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("cameras.id", ondelete="SET NULL")
    )

    # The exact JSON the forwarder will POST, minus anything it must not carry.
    payload: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    # Storage keys whose bytes are relayed to the cloud as evidence, in upload order.
    evidence_keys: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)

    state: Mapped[str] = mapped_column(
        EnumColumn(OutboxState, "outbox_state"),
        nullable=False,
        default=OutboxState.QUEUED.value,
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    next_retry_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_error: Mapped[str | None] = mapped_column(String(512))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    processing_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    incident: Mapped[Incident | None] = relationship(foreign_keys=[incident_id])
    camera: Mapped[Camera | None] = relationship(foreign_keys=[camera_id])

    __table_args__ = (
        Index("ix_outbox_state_retry", "state", "next_retry_at"),
        Index("ix_outbox_incident", "incident_id"),
    )


# --------------------------------------------------------------------------- #
# Devices and tokens
# --------------------------------------------------------------------------- #


class MobileDevice(Base):
    """One installed application on one handset, owned by one personnel account."""

    __tablename__ = "mobile_devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    installation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    platform: Mapped[str] = mapped_column(String(16), nullable=False, default="android")
    push_provider: Mapped[str] = mapped_column(String(16), nullable=False, default="fcm")

    # Fernet token, not the registration token itself; see the module docstring.
    push_token_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary)
    push_token_key_id: Mapped[str | None] = mapped_column(String(32))
    # Short non-reversible handle so a token change is detectable without decrypting.
    push_token_fingerprint: Mapped[str | None] = mapped_column(String(16))

    push_state: Mapped[str] = mapped_column(
        EnumColumn(PushState, "push_state"), nullable=False, default=PushState.ACTIVE.value
    )
    model: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(32))
    app_version: Mapped[str | None] = mapped_column(String(32))

    registered_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    last_seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    token_updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    deactivated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    invalid_reason: Mapped[str | None] = mapped_column(String(128))

    user: Mapped[User] = relationship(foreign_keys=[user_id])

    __table_args__ = (
        UniqueConstraint("user_id", "installation_id", name="uq_device_per_user"),
        Index("ix_device_push_state", "push_state"),
        Index("ix_device_token_fingerprint", "push_token_fingerprint"),
    )


class RefreshToken(Base):
    """A rotated, device-bound refresh token. Only its SHA-256 digest is stored.

    `family` groups every token produced by one rotation chain from one login. Presenting a
    token whose digest is already `rotated_at` means somebody has both the old and the new
    value, which is only possible if one of them was copied: the whole family is revoked.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("mobile_devices.id", ondelete="SET NULL")
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    family: Mapped[UUID] = mapped_column(Uuid(as_uuid=True), nullable=False)
    generation: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    issued_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    expires_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    rotated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    reuse_detected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    replaced_by_id: Mapped[int | None] = mapped_column(
        ForeignKey("refresh_tokens.id", ondelete="SET NULL")
    )
    client_ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(256))

    __table_args__ = (
        Index("ix_refresh_family", "family"),
        Index("ix_refresh_user_expires", "user_id", "expires_at"),
    )


# --------------------------------------------------------------------------- #
# Delivery records
# --------------------------------------------------------------------------- #


class NotificationAttempt(Base):
    """One send of one notification to one device.

    `accepted_at` is FCM saying it queued the message. It is not proof a human saw anything,
    and nothing in this schema or the API is allowed to imply otherwise.
    """

    __tablename__ = "notification_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    notification_id: Mapped[int] = mapped_column(
        ForeignKey("notifications.id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[int | None] = mapped_column(
        ForeignKey("mobile_devices.id", ondelete="SET NULL")
    )
    provider: Mapped[str] = mapped_column(String(16), nullable=False, default="fcm")
    provider_message_id: Mapped[str | None] = mapped_column(String(128))
    state: Mapped[str] = mapped_column(
        EnumColumn(AttemptState, "attempt_state"),
        nullable=False,
        default=AttemptState.SUBMITTED.value,
    )
    idempotency_key: Mapped[str] = mapped_column(String(160), nullable=False)
    requested_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    accepted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    failed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    opened_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    error_code: Mapped[str | None] = mapped_column(String(64))
    failure_reason: Mapped[str | None] = mapped_column(String(256))

    notification: Mapped[Notification] = relationship(foreign_keys=[notification_id])
    device: Mapped[MobileDevice | None] = relationship(foreign_keys=[device_id])

    __table_args__ = (
        UniqueConstraint(
            "notification_id", "device_id", "idempotency_key", name="uq_attempt_per_device"
        ),
        Index("ix_attempt_notification", "notification_id"),
    )


class IncidentAcknowledgement(Base):
    """Who accepted responsibility for an incident, and when.

    The unique constraint is the enforcement: two phones tapping acknowledge at once produce
    one record and one `already_acknowledged` response, not two activity entries.
    """

    __tablename__ = "incident_acknowledgements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=False
    )
    notification_id: Mapped[int | None] = mapped_column(
        ForeignKey("notifications.id", ondelete="SET NULL")
    )
    source: Mapped[str] = mapped_column(String(24), nullable=False, default="mobile")
    note: Mapped[str | None] = mapped_column(Text)
    acknowledged_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    incident: Mapped[Incident] = relationship(foreign_keys=[incident_id])

    __table_args__ = (
        UniqueConstraint("incident_id", "user_id", name="uq_ack_per_incident_user"),
        Index("ix_ack_incident", "incident_id"),
    )


class PersonnelPreference(Base):
    """What an individual may silence. Mandatory categories are enforced by the server."""

    __tablename__ = "personnel_preferences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    min_severity: Mapped[str] = mapped_column(
        EnumColumn(Severity, "severity"), nullable=False, default=Severity.LOW.value
    )
    kinds: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    quiet_hours: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    sound: Mapped[str] = mapped_column(String(24), nullable=False, default="default")
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )

    user: Mapped[User] = relationship(foreign_keys=[user_id])


class IngestNonce(Base):
    """Persisted replay cache.

    An in-memory cache alone is not enough: a cloud restart would forget every nonce, and a
    captured ingest request could be replayed into duplicate pushes. The unique constraint is
    the check, so recording a nonce is the act of rejecting its reuse.
    """

    __tablename__ = "ingest_nonces"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    nonce: Mapped[str] = mapped_column(String(64), nullable=False)
    seen_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (UniqueConstraint("key_id", "nonce", name="uq_ingest_nonce"),)


class IngestRecord(Base):
    """Processed ingest calls, keyed by idempotency key, so a retry gets the first answer."""

    __tablename__ = "ingest_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    idempotency_key: Mapped[str] = mapped_column(String(160), unique=True, nullable=False)
    route: Mapped[str] = mapped_column(String(96), nullable=False)
    key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    request_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    response: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict, nullable=False)
    processed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (Index("ix_ingest_incident", "incident_id"),)


class MonitoringHeartbeat(Base):
    """Last time the monitoring host said it was alive, and what its outbox looked like."""

    __tablename__ = "monitoring_heartbeats"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    monitoring_host: Mapped[str] = mapped_column(String(128), nullable=False)
    app_version: Mapped[str | None] = mapped_column(String(32))
    outbox_pending: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    outbox_failed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    received_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )

    __table_args__ = (Index("ix_heartbeat_host_received", "monitoring_host", "received_at"),)


class EvidenceRelayState(Base):
    """Cloud-side status of bytes relayed from the monitoring host.

    `evidence_assets` stays the single record of an asset; this row only tracks the
    monitor-to-cloud copy, because "the incident exists but its image has not arrived yet"
    is a state the phone must be able to display honestly rather than as a broken image.
    """

    __tablename__ = "evidence_relay_states"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(
        ForeignKey("evidence_assets.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    state: Mapped[str] = mapped_column(
        EnumColumn(UploadState, "upload_state"),
        nullable=False,
        default=UploadState.PENDING_UPLOAD.value,
    )
    expected_sha256: Mapped[str | None] = mapped_column(String(64))
    received_sha256: Mapped[str | None] = mapped_column(String(64))
    bytes_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False
    )
    last_error: Mapped[str | None] = mapped_column(String(256))

    __table_args__ = (Index("ix_relay_state", "state"),)


DETECTION_SOURCE_AI_CANDIDATE = "ai_candidate"
DETECTION_SOURCE_MANUAL = "manual"
DETECTION_SOURCE_HEALTH = "health"
