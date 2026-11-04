"""SQLAlchemy models for the AFIT WATCH TOWER core schema (proposal section 8.4).

Target dialect is PostgreSQL (section 8.1). Enum columns are stored as VARCHAR and validated
by `EnumColumn` at the bind boundary rather than as native Postgres enum types, so adding a
state later is an application change, not a type migration. The database itself carries one
check constraint (`ck_profile_port_range`); the enum vocabulary is enforced by the type.

Deliberate omissions:
  * Continuous video frames are NOT stored here (section 8.4) - only metadata and
    evidence references.
  * No camera table column holds a plaintext password or a credential-bearing RTSP URL
    (section 8.3). Credentials live encrypted in `camera_secrets`.
"""

from __future__ import annotations

import datetime as dt
import enum
from typing import Any
from uuid import UUID

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    TypeDecorator,
    Uuid,
    CheckConstraint,
    Index,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


# JSONB on PostgreSQL, plain JSON on the SQLite harness used by the unit tests.
JsonType = JSONB().with_variant(JSON(), "sqlite")


class Base(DeclarativeBase):
    pass


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class CameraStatus(str, enum.Enum):
    """The operational health states from section 10."""

    PENDING_SETUP = "pending_setup"
    TESTING = "testing"
    ONLINE = "online"
    DEGRADED = "degraded"
    RECONNECTING = "reconnecting"
    OFFLINE = "offline"
    AUTHENTICATION_FAILED = "authentication_failed"
    MAINTENANCE = "maintenance"
    DISABLED = "disabled"


class ProbeResult(str, enum.Enum):
    """Connection-test outcomes from section 6.5."""

    TESTING = "testing"
    CONNECTED = "connection_successful"
    AUTH_FAILED = "authentication_failed"
    HOST_UNREACHABLE = "host_unreachable"
    PATH_INVALID = "stream_path_invalid_or_unsupported"
    DECODE_FAILED = "video_decode_failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "test_cancelled"


class Transport(str, enum.Enum):
    TCP = "tcp"
    UDP = "udp"


class EventStatus(str, enum.Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    DISMISSED = "dismissed"
    ESCALATED = "escalated"


class IncidentStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    ASSIGNED = "assigned"
    RESOLVED = "resolved"
    CLOSED = "closed"
    FALSE_POSITIVE = "false_positive"


class Severity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationChannel(str, enum.Enum):
    DASHBOARD = "dashboard"
    EMAIL = "email"
    SMS = "sms"
    WEBHOOK = "webhook"
    MOBILE_PUSH = "mobile_push"


class NotificationState(str, enum.Enum):
    PENDING = "pending"
    DELIVERED = "delivered"
    READ = "read"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"
    SUPPRESSED = "suppressed"


class JobState(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EnumColumn(TypeDecorator):
    """Enum values stored as VARCHAR and validated on the way in.

    A native Postgres enum type would make adding a state an ALTER TYPE migration, so the
    Python enums above are the source of truth. A TypeDecorator rather than a String
    subclass because the value must be checked at the database boundary: writing
    `status="onlined"` from a bad code path would otherwise persist silently and only
    surface when the health evaluator failed to match a state it had never seen.
    """

    impl = String
    cache_ok = True

    def __init__(self, cls: type[enum.Enum], name: str, *args: Any, **kwargs: Any) -> None:
        kwargs.setdefault("length", 64)
        super().__init__(*args, **kwargs)
        self.enum_cls = cls
        self.enum_name = name

    def process_bind_param(self, value: Any, dialect: Dialect) -> str | None:
        if value is None:
            return None
        raw = value.value if isinstance(value, enum.Enum) else value
        if raw not in {member.value for member in self.enum_cls}:
            raise ValueError(f"{raw!r} is not a valid {self.enum_name} value")
        return str(raw)

    def process_result_value(self, value: Any, dialect: Dialect) -> Any:
        return value



# --------------------------------------------------------------------------- #
# Access control (sections 14 and 16)
# --------------------------------------------------------------------------- #


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    email: Mapped[str | None] = mapped_column(String(256))
    phone: Mapped[str | None] = mapped_column(String(32))
    password_hash: Mapped[str] = mapped_column(String(256), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # Section 16: camera streams are not exposed to the public internet, so sessions are
    # short-lived by default and failed-login lockout is tracked here.
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    password_changed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    # Personnel issued default credentials by an administrator; the mobile app forces a
    # change before anything else can be done with the account (proposal section 7.4).
    must_change_password: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    last_login_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    role_assignments: Mapped[list[UserRole]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    # Section 14: administrative rights and video-viewing rights are separated.
    is_administrative: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[int] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )


class UserRole(Base):
    """A role grant, optionally scoped to one camera group.

    Section 14 allows permissions to be restricted by camera group or location; an
    unscoped grant applies institution-wide.
    """

    __tablename__ = "user_roles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[int] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    camera_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("camera_groups.id", ondelete="CASCADE")
    )

    user: Mapped[User] = relationship(back_populates="role_assignments")
    role: Mapped[Role] = relationship()
    camera_group: Mapped[CameraGroup | None] = relationship()

    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "camera_group_id", name="uq_user_role_scope"),
        Index("ix_user_roles_user", "user_id"),
    )


# --------------------------------------------------------------------------- #
# Camera registry (sections 6 and 8.2)
# --------------------------------------------------------------------------- #


class CameraGroup(Base):
    __tablename__ = "camera_groups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    parent_id: Mapped[int | None] = mapped_column(
        ForeignKey("camera_groups.id", ondelete="SET NULL")
    )


class CameraSecret(Base):
    """Encrypted camera credential, referenced rather than embedded (section 8.3)."""

    __tablename__ = "camera_secrets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reference: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    key_id: Mapped[str] = mapped_column(String(32), nullable=False)
    # Length is kept for operator diagnostics only; it cannot reveal the secret.
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    rotated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))


class CameraConnectionProfile(Base):
    """Validated, non-secret connection parameters (section 6.3).

    `secret_reference` points at `camera_secrets`; no column here holds a password, and
    no column reassembles a credential-bearing URL.
    """

    __tablename__ = "camera_connection_profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=554)
    stream_path: Mapped[str] = mapped_column(String(256), nullable=False)
    username: Mapped[str | None] = mapped_column(String(128))
    secret_reference: Mapped[str | None] = mapped_column(
        ForeignKey("camera_secrets.reference", ondelete="SET NULL")
    )
    transport: Mapped[str] = mapped_column(
        EnumColumn(Transport, "transport"), nullable=False, default=Transport.TCP.value
    )
    verified_in_vlc: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_probe_result: Mapped[str | None] = mapped_column(String(64))
    last_probe_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    secret: Mapped[CameraSecret | None] = relationship(
        "CameraSecret", foreign_keys=[secret_reference], remote_side=[CameraSecret.reference]
    )

    __table_args__ = (
        Index("ix_profiles_host_port", "host", "port"),
        CheckConstraint("port > 0 AND port <= 65535", name="ck_profile_port_range"),
    )


class MonitoringPolicy(Base):
    """AI monitoring configuration per camera (sections 6.3 and 11)."""

    __tablename__ = "monitoring_policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    code: Mapped[str] = mapped_column(String(48), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    detector_codes: Mapped[list[str]] = mapped_column(JsonType, default=list, nullable=False)
    min_confidence: Mapped[float] = mapped_column(Float, default=0.55, nullable=False)
    analysis_fps: Mapped[float] = mapped_column(Float, default=4.0, nullable=False)
    # Restricted-zone polygons are institution-approved geometry, stored as metadata.
    zones: Mapped[list[dict]] = mapped_column(JsonType, default=list, nullable=False)
    duplicate_window_seconds: Mapped[int] = mapped_column(Integer, default=90, nullable=False)
    severity: Mapped[str] = mapped_column(
        EnumColumn(Severity, "severity"), nullable=False, default=Severity.MEDIUM.value
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class Camera(Base):
    """The camera record described in section 8.2."""

    __tablename__ = "cameras"

    id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True
    )
    code: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(128), nullable=False)
    campus_location: Mapped[str] = mapped_column(String(256), nullable=False)
    camera_group_id: Mapped[int | None] = mapped_column(
        ForeignKey("camera_groups.id", ondelete="SET NULL")
    )
    model: Mapped[str | None] = mapped_column(String(128))
    description: Mapped[str | None] = mapped_column(Text)

    connection_profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("camera_connection_profiles.id", ondelete="SET NULL")
    )
    monitoring_policy_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitoring_policies.id", ondelete="SET NULL")
    )
    # Section 6.3: recording policy is an approved settings blob, not free-form.
    recording_policy: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)

    status: Mapped[str] = mapped_column(
        EnumColumn(CameraStatus, "status"),
        nullable=False,
        default=CameraStatus.PENDING_SETUP.value,
    )
    # Section 7: an activated camera must be managed without restarting the server.
    desired_state: Mapped[str] = mapped_column(String(24), nullable=False, default="stopped")
    is_registered: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    last_successful_frame_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True)
    )
    last_error_code: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    modified_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    connection_profile: Mapped[CameraConnectionProfile | None] = relationship(
        cascade="all, delete-orphan",
        # A profile describes exactly one camera and is deleted with it; SQLAlchemy requires
        # single_parent before it will honour delete-orphan on the many side.
        single_parent=True,
        foreign_keys=[connection_profile_id],
    )
    monitoring_policy: Mapped[MonitoringPolicy | None] = relationship()
    group: Mapped[CameraGroup | None] = relationship()

    __table_args__ = (
        Index("ix_cameras_group", "camera_group_id"),
        Index("ix_cameras_status", "status"),
        Index("ix_cameras_location", "campus_location"),
    )


class CameraStreamSession(Base):
    """One supervised stream session per section 7."""

    __tablename__ = "camera_stream_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    camera_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    pid: Mapped[int | None] = mapped_column(Integer)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="starting")
    started_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    last_frame_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    frames_received: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    frames_dropped: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    decode_failures: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    viewer_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    measured_fps: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    terminal: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    termination_reason: Mapped[str | None] = mapped_column(String(64))

    camera: Mapped[Camera] = relationship(backref="stream_sessions")

    __table_args__ = (Index("ix_sessions_camera_started", "camera_id", "started_at"),)


class CameraHealthEvent(Base):
    """Section 10: health events stay distinct from AI-detected security incidents."""

    __tablename__ = "camera_health_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    camera_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    previous_status: Mapped[str | None] = mapped_column(String(48))
    status: Mapped[str] = mapped_column(String(48), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(64), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text)
    observed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    duration_seconds: Mapped[float | None] = mapped_column(Float)
    notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    camera: Mapped[Camera] = relationship(backref="health_events")

    __table_args__ = (Index("ix_health_camera_observed", "camera_id", "observed_at"),)


# --------------------------------------------------------------------------- #
# Detection, incidents and evidence (sections 11 and 12)
# --------------------------------------------------------------------------- #


class DetectionEvent(Base):
    """A candidate security event produced by the analysis service (section 11)."""

    __tablename__ = "detection_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    camera_id: Mapped[UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="CASCADE"),
        nullable=False,
    )
    policy_id: Mapped[int | None] = mapped_column(
        ForeignKey("monitoring_policies.id", ondelete="SET NULL")
    )
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    # `metadata` is reserved by the declarative base, so the attribute is
    # `event_metadata` while the database column keeps the schema name.
    event_metadata: Mapped[dict] = mapped_column("metadata", JsonType, default=dict, nullable=False)
    status: Mapped[str] = mapped_column(
        EnumColumn(EventStatus, "status"), nullable=False, default=EventStatus.NEW.value
    )
    dedupe_key: Mapped[str | None] = mapped_column(String(160))
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    reviewed_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    review_note: Mapped[str | None] = mapped_column(Text)

    camera: Mapped[Camera] = relationship(backref="detection_events")

    __table_args__ = (
        UniqueConstraint("camera_id", "dedupe_key", name="uq_event_dedupe"),
        Index("ix_events_status_occurred", "status", "occurred_at"),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    reference: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(256), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(
        EnumColumn(Severity, "severity"), nullable=False, default=Severity.MEDIUM.value
    )
    status: Mapped[str] = mapped_column(
        EnumColumn(IncidentStatus, "status"),
        nullable=False,
        default=IncidentStatus.OPEN.value,
    )
    camera_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="SET NULL"),
    )
    origin_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_events.id", ondelete="SET NULL")
    )
    campus_location: Mapped[str | None] = mapped_column(String(256))
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    assigned_to: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    escalated_to: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    resolved_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    resolution: Mapped[str | None] = mapped_column(Text)
    outcome: Mapped[str | None] = mapped_column(String(64))
    created_by: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )

    actions: Mapped[list[IncidentAction]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentAction.id"
    )
    evidence: Mapped[list[EvidenceAsset]] = relationship(
        back_populates="incident", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_incidents_status_occurred", "status", "occurred_at"),
        Index("ix_incidents_camera", "camera_id"),
    )


class IncidentAction(Base):
    """Assignment, notes, escalation and resolution steps (section 12)."""

    __tablename__ = "incident_actions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False
    )
    action: Mapped[str] = mapped_column(String(48), nullable=False)
    note: Mapped[str | None] = mapped_column(Text)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )

    incident: Mapped[Incident] = relationship(back_populates="actions")

    __table_args__ = (Index("ix_actions_incident", "incident_id"),)


class EvidenceAsset(Base):
    """Section 12: protected snapshots and clips with integrity and retention data."""

    __tablename__ = "evidence_assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE")
    )
    camera_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="SET NULL"),
    )
    detection_event_id: Mapped[int | None] = mapped_column(
        ForeignKey("detection_events.id", ondelete="SET NULL")
    )
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(512), unique=True, nullable=False)
    content_type: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    captured_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    deleted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))

    incident: Mapped[Incident] = relationship(back_populates="evidence")

    __table_args__ = (Index("ix_evidence_incident", "incident_id"),)


class Notification(Base):
    """Section 15: deduplicated, prioritised, routed alerts with delivery state."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        EnumColumn(Severity, "severity"), nullable=False, default=Severity.MEDIUM.value
    )
    channel: Mapped[str] = mapped_column(
        EnumColumn(NotificationChannel, "channel"),
        nullable=False,
        default=NotificationChannel.DASHBOARD.value,
    )
    state: Mapped[str] = mapped_column(
        EnumColumn(NotificationState, "state"),
        nullable=False,
        default=NotificationState.PENDING.value,
    )
    dedupe_key: Mapped[str | None] = mapped_column(String(160))
    camera_id: Mapped[UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("cameras.id", ondelete="CASCADE"),
    )
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    event_id: Mapped[int | None] = mapped_column(ForeignKey("detection_events.id", ondelete="CASCADE"))
    recipient_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    # Reading and acknowledging are two different facts (mobile contract 5.2), so they get two
    # different columns; `state` alone cannot tell "opened" from "accepted responsibility".
    read_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    failure_reason: Mapped[str | None] = mapped_column(String(256))

    __table_args__ = (
        UniqueConstraint("dedupe_key", "recipient_id", "channel", name="uq_notification_dedupe"),
        Index("ix_notifications_recipient_state", "recipient_id", "state"),
    )


class AuditLog(Base):
    """Section 16: sensitive administrative, viewing and incident actions are audited."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_username: Mapped[str | None] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(96), nullable=False)
    object_type: Mapped[str | None] = mapped_column(String(48))
    object_id: Mapped[str | None] = mapped_column(String(64))
    # Values are sanitised before they reach this column (see security.audit).
    details: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False, default="success")
    source_ip: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_audit_actor_created", "actor_id", "created_at"),
        Index("ix_audit_action_created", "action", "created_at"),
    )


class SystemJob(Base):
    """Section 17: discrete background work is database-backed."""

    __tablename__ = "system_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[dict] = mapped_column(JsonType, default=dict, nullable=False)
    state: Mapped[str] = mapped_column(
        EnumColumn(JobState, "state"), nullable=False, default=JobState.QUEUED.value
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    scheduled_for: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_jobs_state_scheduled", "state", "scheduled_for"),)
