"""Candidate-event review and the incident workflow (proposal sections 11 and 12).

Section 11 treats an AI detection as an indication that needs human verification, so this
service never converts a detection into a conclusion. A candidate event only becomes an
actively managed incident when a person with `event.review` escalates it, and each
transition is written to `incident_actions` and the audit log.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..mobile.alerts import enqueue_incident_alert
from ..models import (
    Camera,
    DetectionEvent,
    EventStatus,
    Incident,
    IncidentAction,
    IncidentStatus,
    Severity,
    User,
)
from ..security.audit import record as audit_record
from ..security.rbac import Principal, can_view_camera
from .evidence import EvidenceStore
from .notifications import NotificationRequest, NotificationService


class IncidentServiceError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(slots=True)
class IncidentFilters:
    status: str | None = None
    category: str | None = None
    camera_id: uuid.UUID | None = None
    campus_location: str | None = None
    severity: str | None = None
    assigned_to: int | None = None
    since: dt.datetime | None = None
    until: dt.datetime | None = None
    query: str | None = None
    limit: int = 100
    offset: int = 0


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class IncidentService:
    def __init__(
        self,
        session: Session,
        notifications: NotificationService,
        evidence: EvidenceStore,
        settings: Settings | None = None,
    ) -> None:
        self._session = session
        self._notifications = notifications
        self._evidence = evidence
        # `None`, or a Settings without cloud configuration, means this deployment keeps its
        # alerts on the monitoring host. The mobile outbox then stays empty by design.
        self._settings = settings

    def _queue_mobile_alert(
        self, incident: Incident, *, kind: str, event: DetectionEvent | None = None
    ) -> None:
        enqueue_incident_alert(self._settings, self._session, incident, kind=kind, event=event)

    # ------------------------------------------------------------------ #
    # Candidate event review (section 11, steps 6-8)
    # ------------------------------------------------------------------ #

    def review_event(
        self,
        event_id: int,
        principal: Principal,
        *,
        decision: str,
        note: str | None = None,
    ) -> tuple[DetectionEvent, Incident | None]:
        if decision not in {"acknowledge", "dismiss", "escalate"}:
            raise IncidentServiceError(
                "invalid_decision", "Review decisions are acknowledge, dismiss or escalate."
            )
        event = self._session.get(DetectionEvent, event_id)
        if event is None:
            raise IncidentServiceError("not_found", "No such candidate event.")
        camera = self._session.get(Camera, event.camera_id)
        if camera is None:
            raise IncidentServiceError("not_found", "The camera for this event no longer exists.")
        if not can_view_camera(principal, "event.review", camera):
            raise IncidentServiceError("forbidden", "You are not authorised for this camera group.")

        mapping = {
            "acknowledge": EventStatus.ACKNOWLEDGED,
            "dismiss": EventStatus.DISMISSED,
            "escalate": EventStatus.ESCALATED,
        }
        event.status = mapping[decision].value
        event.reviewed_by = principal.user_id
        event.reviewed_at = _utcnow()
        event.review_note = note

        incident: Incident | None = None
        if decision == "escalate":
            incident = self.create_from_event(event, camera, principal, note=note)
        self._session.flush()

        audit_record(
            self._session,
            principal=principal,
            action=f"event.{decision}",
            object_type="detection_event",
            object_id=str(event.id),
            details={
                "camera": camera.code,
                "category": event.category,
                "confidence": event.confidence,
                "note": note,
                "incident_reference": incident.reference if incident else None,
            },
        )
        if incident is not None:
            self._notifications.incident_alert(
                incident,
                kind="created",
                actor_label=f"{principal.display_name} escalated {event.category}",
                note=note,
            )
        return event, incident

    def pending_events(self, principal: Principal, *, only_new: bool = True) -> list[DetectionEvent]:
        statement = select(DetectionEvent).where(DetectionEvent.suppressed.is_(False))
        if only_new:
            statement = statement.where(DetectionEvent.status == EventStatus.NEW.value)
        events = self._session.scalars(statement.order_by(DetectionEvent.occurred_at.desc())).all()
        visible: list[DetectionEvent] = []
        for event in events:
            camera = self._session.get(Camera, event.camera_id)
            if camera is not None and can_view_camera(principal, "event.view", camera):
                visible.append(event)
        return visible

    # ------------------------------------------------------------------ #
    # Incidents (section 12)
    # ------------------------------------------------------------------ #

    def create_from_event(
        self,
        event: DetectionEvent,
        camera: Camera,
        principal: Principal,
        *,
        note: str | None = None,
    ) -> Incident:
        incident = self._new_incident(
            title=f"{event.category.replace('_', ' ').title()} at {camera.display_name}",
            category=event.category,
            severity=camera.monitoring_policy.severity if camera.monitoring_policy else Severity.MEDIUM.value,
            camera=camera,
            principal=principal,
            summary=note or (
                f"Escalated from candidate event {event.id} "
                f"(confidence {event.confidence:.2f}). Human review confirmed."
            ),
            occurred_at=event.occurred_at,
            origin_event_id=event.id,
        )
        incident.actions.append(
            IncidentAction(
                action="created_from_event",
                note=f"event {event.id}, confidence {event.confidence:.2f}",
                actor_id=principal.user_id,
            )
        )
        self._session.flush()
        # Without this link the reviewer escalates an event whose snapshot they cannot retrieve.
        self._evidence.link_to_incident(
            detection_event_id=event.id, incident_id=incident.id
        )
        # After the link, so the alert carries the evidence the reviewer just confirmed.
        self._queue_mobile_alert(incident, kind="created", event=event)
        return incident

    def create_manual(
        self,
        principal: Principal,
        *,
        title: str,
        category: str,
        severity: str,
        summary: str | None,
        camera_id: uuid.UUID | None,
        campus_location: str | None,
        occurred_at: dt.datetime | None,
    ) -> Incident:
        camera = self._session.get(Camera, camera_id) if camera_id else None
        if camera_id is not None and camera is None:
            raise IncidentServiceError("not_found", "No such camera.")
        if camera is not None and not can_view_camera(principal, "incident.create", camera):
            raise IncidentServiceError("forbidden", "You are not authorised for this camera group.")
        incident = self._new_incident(
            title=title,
            category=category,
            severity=severity,
            camera=camera,
            principal=principal,
            summary=summary,
            occurred_at=occurred_at or _utcnow(),
            campus_location=campus_location or (camera.campus_location if camera else None),
        )
        incident.actions.append(IncidentAction(action="created", note=summary, actor_id=principal.user_id))
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="incident.create",
            object_type="incident",
            object_id=str(incident.id),
            details={"reference": incident.reference, "category": category},
        )
        self._notifications.incident_alert(
            incident, kind="created", actor_label=principal.display_name
        )
        self._queue_mobile_alert(incident, kind="created")
        return incident

    def _new_incident(
        self,
        *,
        title: str,
        category: str,
        severity: str,
        camera: Camera | None,
        principal: Principal,
        summary: str | None,
        occurred_at: dt.datetime,
        campus_location: str | None = None,
        origin_event_id: int | None = None,
    ) -> Incident:
        incident = Incident(
            reference=self._next_reference(),
            title=title[:256],
            summary=summary,
            category=category,
            severity=severity,
            status=IncidentStatus.OPEN.value,
            camera_id=camera.id if camera else None,
            origin_event_id=origin_event_id,
            campus_location=campus_location or (camera.campus_location if camera else None),
            occurred_at=occurred_at,
            created_by=principal.user_id,
        )
        self._session.add(incident)
        return incident

    def _next_reference(self) -> str:
        """INC-<year>-<sequence>, collision-safe under concurrent creation."""
        year = _utcnow().year
        prefix = f"INC-{year}-"
        count = self._session.scalar(
            select(func.count(Incident.id)).where(Incident.reference.startswith(prefix))
        ) or 0
        for attempt in range(count, count + 50):
            reference = f"{prefix}{attempt + 1:04d}"
            if self._session.scalar(select(Incident.id).where(Incident.reference == reference)):
                continue
            return reference
        # Extremely unlikely; still preferable to an unbounded loop.
        return f"{prefix}{uuid.uuid4().hex[:8]}"

    def assign(
        self, incident_id: int, principal: Principal, *, assignee_id: int
    ) -> Incident:
        incident = self._require(incident_id, principal, "incident.assign")
        assignee = self._session.get(User, assignee_id)
        if assignee is None:
            raise IncidentServiceError("not_found", "No such user to assign to.")
        incident.assigned_to = assignee.id
        incident.status = IncidentStatus.ASSIGNED.value
        incident.actions.append(
            IncidentAction(action="assigned", note=f"assigned to {assignee.display_name}", actor_id=principal.user_id)
        )
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="incident.assign",
            object_type="incident",
            object_id=str(incident.id),
            details={"reference": incident.reference, "assignee": assignee.username},
        )
        self._notifications.incident_alert(
            incident, kind="assigned", actor_label=principal.display_name
        )
        self._queue_mobile_alert(incident, kind="assigned")
        return incident

    def escalate(
        self, incident_id: int, principal: Principal, *, to_user_id: int, note: str | None = None
    ) -> Incident:
        incident = self._require(incident_id, principal, "incident.escalate")
        target = self._session.get(User, to_user_id)
        if target is None:
            raise IncidentServiceError("not_found", "No such user to escalate to.")
        incident.escalated_to = target.id
        incident.severity = Severity.HIGH.value
        incident.status = IncidentStatus.INVESTIGATING.value
        incident.actions.append(
            IncidentAction(action="escalated", note=note or f"escalated to {target.display_name}", actor_id=principal.user_id)
        )
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="incident.escalate",
            object_type="incident",
            object_id=str(incident.id),
            details={"reference": incident.reference, "to": target.username, "note": note},
        )
        self._notifications.dispatch(
            NotificationRequest(
                kind="incident.escalated",
                title=f"Incident {incident.reference} escalated",
                body=f"{principal.display_name} escalated {incident.title}: {note or ''}",
                severity=Severity.HIGH.value,
                dedupe_key=f"incident-escalated:{incident.id}:{target.id}",
                camera_id=incident.camera_id,
                incident_id=incident.id,
            ),
            [target],
        )
        self._queue_mobile_alert(incident, kind="escalated")
        return incident

    def note(
        self, incident_id: int, principal: Principal, *, text: str, investigation: bool = True
    ) -> Incident:
        incident = self._require(incident_id, principal, "incident.view")
        incident.actions.append(
            IncidentAction(action="investigation_note" if investigation else "note", note=text, actor_id=principal.user_id)
        )
        if investigation and incident.status == IncidentStatus.OPEN.value:
            incident.status = IncidentStatus.INVESTIGATING.value
        self._session.flush()
        return incident

    def resolve(
        self,
        incident_id: int,
        principal: Principal,
        *,
        outcome: str,
        resolution: str,
        false_positive: bool = False,
    ) -> Incident:
        incident = self._require(incident_id, principal, "incident.resolve")
        incident.status = IncidentStatus.FALSE_POSITIVE.value if false_positive else IncidentStatus.RESOLVED.value
        incident.outcome = outcome
        incident.resolution = resolution
        incident.resolved_at = _utcnow()
        incident.actions.append(
            IncidentAction(
                action="resolved",
                note=f"{outcome}: {resolution}",
                actor_id=principal.user_id,
            )
        )
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="incident.resolve",
            object_type="incident",
            object_id=str(incident.id),
            details={"reference": incident.reference, "outcome": outcome, "false_positive": false_positive},
        )
        self._notifications.incident_alert(
            incident, kind="resolved", actor_label=principal.display_name, note=resolution
        )
        self._queue_mobile_alert(incident, kind="resolved")
        return incident

    def reopen(self, incident_id: int, principal: Principal, *, reason: str) -> Incident:
        incident = self._require(incident_id, principal, "incident.resolve")
        if incident.status not in (IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value):
            raise IncidentServiceError(
                "not_resolved", "Only a resolved or closed incident can be reopened."
            )
        incident.status = IncidentStatus.INVESTIGATING.value
        # A reopened incident is live work, so it carries no verdict. The previous outcome stays
        # readable in the activity history as the `resolved` action; leaving the columns set would
        # show the next officer a resolution date on an incident that is not finished.
        incident.outcome = None
        incident.resolution = None
        incident.resolved_at = None
        incident.actions.append(
            IncidentAction(action="reopened", note=reason, actor_id=principal.user_id)
        )
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="incident.reopen",
            object_type="incident",
            object_id=str(incident.id),
            details={"reference": incident.reference, "reason": reason},
        )
        return incident

    def close(self, incident_id: int, principal: Principal, *, note: str | None = None) -> Incident:
        incident = self._require(incident_id, principal, "incident.resolve")
        incident.status = IncidentStatus.CLOSED.value
        incident.actions.append(IncidentAction(action="closed", note=note, actor_id=principal.user_id))
        self._session.flush()
        return incident

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def list(self, principal: Principal, filters: IncidentFilters) -> list[Incident]:
        statement = self._scoped(principal, self._filtered(select(Incident), filters))
        return list(
            self._session.scalars(
                statement.order_by(Incident.occurred_at.desc()).limit(filters.limit).offset(filters.offset)
            ).all()
        )

    def get_visible(self, incident_id: int, principal: Principal) -> Incident:
        return self._require(incident_id, principal, "incident.view")

    def summary_counts(self, principal: Principal, filters: IncidentFilters) -> dict[str, int]:
        """Exact totals per status for the records this account can read under these filters.

        The status filter itself is deliberately left out: the console renders the result as
        switchable chips, and a chip row that shows one non-zero number beside empty ones would
        tell an operator the other states hold nothing when the query simply excluded them.
        """
        statement = self._scoped(
            principal, self._filtered(select(Incident.status, func.count(Incident.id)), filters, include_status=False)
        )
        return dict(self._session.execute(statement.group_by(Incident.status)).all())

    def _filtered(
        self, statement, filters: IncidentFilters, *, include_status: bool = True
    ):
        if include_status and filters.status:
            statement = statement.where(Incident.status == filters.status)
        if filters.category:
            statement = statement.where(Incident.category == filters.category)
        if filters.severity:
            statement = statement.where(Incident.severity == filters.severity)
        if filters.camera_id:
            statement = statement.where(Incident.camera_id == filters.camera_id)
        if filters.campus_location:
            statement = statement.where(Incident.campus_location.ilike(f"%{filters.campus_location}%"))
        if filters.since:
            statement = statement.where(Incident.occurred_at >= filters.since)
        if filters.until:
            statement = statement.where(Incident.occurred_at <= filters.until)
        if filters.assigned_to:
            statement = statement.where(Incident.assigned_to == filters.assigned_to)
        if filters.query:
            pattern = f"%{filters.query}%"
            statement = statement.where(
                Incident.title.ilike(pattern)
                | Incident.reference.ilike(pattern)
                | Incident.summary.ilike(pattern)
            )
        return statement

    def _scoped(self, principal: Principal, statement):
        """Restrict an incident query to the records this account is allowed to read.

        ``incident.view`` is either institution-wide or granted per camera group. This is the
        console-side twin of `cloud.views.camera_scope_condition`, mirrored on purpose: a phone
        that sees a wider archive than the console would be an access-control defect. Putting it
        in SQL rather than dropping rows afterwards is what makes ``limit``, ``offset`` and the
        status totals agree with one another - a post-query filter would quietly shorten a page
        and understate every chip. An incident with no camera stays readable, which is the same
        rule ``_require`` applies when a single record is opened.
        """
        scope = principal.camera_scope("incident.view")
        if scope is None:
            return statement
        scoped_camera_ids = select(Camera.id).where(Camera.camera_group_id.in_(scope))
        return statement.where(Incident.camera_id.is_(None) | Incident.camera_id.in_(scoped_camera_ids))

    def _require(
        self, incident_id: int, principal: Principal, permission: str
    ) -> Incident:
        incident = self._session.get(Incident, incident_id)
        if incident is None:
            raise IncidentServiceError("not_found", "No such incident.")
        camera = self._session.get(Camera, incident.camera_id) if incident.camera_id else None
        if camera is not None and not can_view_camera(principal, permission, camera):
            raise IncidentServiceError("forbidden", "You are not authorised for this incident.")
        if camera is None and not principal.allows(permission):
            raise IncidentServiceError("forbidden", "You are not authorised for this incident.")
        return incident
