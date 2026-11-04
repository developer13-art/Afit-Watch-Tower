"""Notification routing and delivery (proposal section 15).

Alerts are deduplicated per recipient and channel, prioritised by severity and routed only
to users whose role grant actually covers the affected camera. The dashboard is always a
delivery target because the database row *is* the dashboard inbox; external channels
(email, SMS, webhook, mobile push) are attempted only when configured, and an unconfigured
channel is recorded as failed rather than silently dropped - a security alert that goes
nowhere must be visible as such.
"""

from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.request
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..models import (
    Camera,
    DetectionEvent,
    Incident,
    Notification,
    NotificationChannel,
    NotificationState,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from ..security.secrets import redact

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(slots=True)
class NotificationRequest:
    kind: str
    title: str
    body: str
    severity: str = "medium"
    dedupe_key: str | None = None
    camera_id: object | None = None
    incident_id: int | None = None
    event_id: int | None = None
    channels: tuple[str, ...] = (NotificationChannel.DASHBOARD.value,)

    @property
    def priority(self) -> int:
        return SEVERITY_RANK.get(self.severity, 1)


class NotificationService:
    def __init__(self, session: Session, *, webhook_url: str | None = None) -> None:
        self._session = session
        self._webhook_url = webhook_url

    # ------------------------------------------------------------------ #
    # Routing
    # ------------------------------------------------------------------ #

    def recipients_for(
        self, permission: str, camera: Camera | None = None
    ) -> list[User]:
        """Users holding `permission`, narrowed by the camera's group when one applies.

        Section 14 lets a grant be scoped to a camera group, so a Main Gate operator must
        not receive alerts for the armoury camera.
        """
        rows = self._session.execute(
            select(UserRole.user_id, UserRole.camera_group_id)
            .join(Role, Role.id == UserRole.role_id)
            .join(RolePermission, RolePermission.role_id == Role.id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .join(User, User.id == UserRole.user_id)
            .where(Permission.code == permission, User.is_active.is_(True))
            .distinct()
        ).all()

        wanted_user_ids = set()
        for user_id, group_id in rows:
            if group_id is None or (camera is not None and camera.camera_group_id == group_id):
                wanted_user_ids.add(user_id)

        if not wanted_user_ids:
            return []
        return self._session.scalars(
            select(User).where(User.id.in_(wanted_user_ids), User.is_active.is_(True))
        ).all()

    # ------------------------------------------------------------------ #
    # Dispatch
    # ------------------------------------------------------------------ #

    def dispatch(self, request: NotificationRequest, recipients: list[User]) -> list[Notification]:
        created: list[Notification] = []
        for recipient in recipients:
            for channel in request.channels:
                row = self._create(request, recipient=recipient, channel=channel)
                if row is not None:
                    created.append(row)
        return created

    def _create(
        self,
        request: NotificationRequest,
        *,
        recipient: User | None,
        channel: str,
    ) -> Notification | None:
        if request.dedupe_key is not None and self._already_pending(request, recipient, channel):
            return None
        row = Notification(
            kind=request.kind,
            title=redact(request.title)[:200],
            body=redact(request.body),
            severity=request.severity,
            channel=channel,
            state=NotificationState.PENDING.value,
            dedupe_key=request.dedupe_key,
            camera_id=request.camera_id,
            incident_id=request.incident_id,
            event_id=request.event_id,
            recipient_id=recipient.id if recipient else None,
        )
        self._session.add(row)
        try:
            self._session.flush()
        except IntegrityError:
            # A concurrent dispatcher already queued this alert for this recipient.
            self._session.rollback()
            return None
        self._deliver(row)
        return row

    def _already_pending(
        self, request: NotificationRequest, recipient: User | None, channel: str
    ) -> bool:
        statement = select(Notification.id).where(
            Notification.dedupe_key == request.dedupe_key,
            Notification.channel == channel,
            Notification.state.in_(
                [NotificationState.PENDING.value, NotificationState.DELIVERED.value]
            ),
        )
        if recipient is None:
            statement = statement.where(Notification.recipient_id.is_(None))
        else:
            statement = statement.where(Notification.recipient_id == recipient.id)
        return self._session.scalar(statement) is not None

    def _deliver(self, row: Notification) -> None:
        now = dt.datetime.now(dt.UTC)
        if row.channel == NotificationChannel.DASHBOARD.value:
            row.state = NotificationState.DELIVERED.value
            row.delivered_at = now
            return
        if row.channel == NotificationChannel.WEBHOOK.value:
            if not self._webhook_url:
                row.state = NotificationState.FAILED.value
                row.failure_reason = "no webhook endpoint configured"
                self._session.flush()
                return
            payload = json.dumps(
                {
                    "kind": row.kind,
                    "severity": row.severity,
                    "title": row.title,
                    "body": row.body,
                    "camera_id": str(row.camera_id) if row.camera_id else None,
                    "incident_id": row.incident_id,
                }
            ).encode()
            request = urllib.request.Request(  # noqa: S310 - scheme is http(s) from config.load_settings
                self._webhook_url,
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:  # noqa: S310
                    ok = 200 <= response.status < 300
                row.state = NotificationState.DELIVERED.value if ok else NotificationState.FAILED.value
                if not ok:
                    row.failure_reason = f"webhook responded {response.status}"
                else:
                    row.delivered_at = now
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                row.state = NotificationState.FAILED.value
                row.failure_reason = redact(f"webhook delivery failed: {exc}")[:256]
            self._session.flush()
            return

        # Email, SMS and mobile push need institution-approved gateways. Recording the
        # intent as undelivered keeps the gap visible instead of pretending success.
        row.state = NotificationState.FAILED.value
        row.failure_reason = f"{row.channel} gateway is not configured for this deployment"
        self._session.flush()

    # ------------------------------------------------------------------ #
    # Named alerts (section 15 categories)
    # ------------------------------------------------------------------ #

    def camera_health_alert(self, camera: Camera, *, status: str, reason: str, detail: str) -> None:
        severity = "critical" if status == "offline" else "high" if "authentication" in status else "medium"
        self.dispatch(
            NotificationRequest(
                kind=f"camera.{status}",
                title=f"Camera {camera.display_name} is {status.replace('_', ' ')}",
                body=f"{camera.code} at {camera.campus_location}: {redact(detail)}",
                severity=severity,
                dedupe_key=f"camera-health:{camera.id}:{status}:{reason}",
                camera_id=camera.id,
            ),
            self.recipients_for("health.view", camera),
        )

    def candidate_event_alert(self, camera: Camera, event: DetectionEvent) -> None:
        self.dispatch(
            NotificationRequest(
                kind="event.new",
                title=f"Candidate event: {event.category}",
                body=(
                    f"{camera.display_name} ({camera.code}) produced a {event.category} "
                    f"candidate at confidence {event.confidence:.2f}. Human review required."
                ),
                severity="high",
                dedupe_key=f"event:{event.id}",
                camera_id=camera.id,
                event_id=event.id,
            ),
            self.recipients_for("event.review", camera),
        )

    def incident_alert(
        self, incident: Incident, *, kind: str, actor_label: str, note: str | None = None
    ) -> None:
        self.dispatch(
            NotificationRequest(
                kind=f"incident.{kind}",
                title=f"Incident {incident.reference} {kind}",
                body=redact(f"{actor_label} {kind} {incident.reference}: {note or incident.title}"),
                severity=incident.severity,
                dedupe_key=f"incident-{kind}:{incident.id}",
                camera_id=incident.camera_id,
                incident_id=incident.id,
            ),
            self.recipients_for("incident.view", None),
        )

    def mark_read(self, notification_id: int) -> None:
        row = self._session.get(Notification, notification_id)
        if row is not None and row.state == NotificationState.DELIVERED.value:
            row.state = NotificationState.READ.value
            self._session.flush()

    def mark_acknowledged(self, notification_id: int) -> None:
        row = self._session.get(Notification, notification_id)
        if row is not None:
            row.state = NotificationState.ACKNOWLEDGED.value
            row.acknowledged_at = dt.datetime.now(dt.UTC)
            self._session.flush()

    def unread(self, user_id: int) -> list[Notification]:
        return self._session.scalars(
            select(Notification)
            .where(
                Notification.recipient_id == user_id,
                Notification.state.in_(
                    [NotificationState.PENDING.value, NotificationState.DELIVERED.value]
                ),
            )
            .order_by(Notification.created_at.desc())
        ).all()
