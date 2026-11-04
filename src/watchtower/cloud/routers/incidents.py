"""Incidents and the response actions a duty officer takes from a phone (contract section 6).

The workflow itself is the console's `IncidentService`, deliberately not reimplemented here: one
state machine, one set of conflict rules, one audit trail. What this router adds is the mobile
shape - the acknowledgement row, the caller's own alert being marked acknowledged, and the
follow-up push to the people who have not been paged yet.

Every read and write is camera-scoped. A single record the caller may not see answers `404`, not
`403`, because a `403` on an id confirms that the incident exists.
"""

from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ...mobile.models import (
    AttemptState,
    IncidentAcknowledgement,
    NotificationAttempt,
    PersonnelPreference,
)
from ...models import (
    Camera,
    EvidenceAsset,
    Incident,
    IncidentAction,
    IncidentStatus,
    Notification,
    NotificationChannel,
    NotificationState,
    Severity,
    User,
    utcnow,
)
from ...security.audit import record as audit_record
from ...services.incidents import IncidentServiceError
from ..config import CloudSettings
from ..delivery import enqueue_alert
from ..deps import Caller, CloudContainer, get_container, get_db, get_settings, require_permission
from ..errors import CloudError
from ..ratelimit import enforce
from ..targeting import AlertIntent, quiet_hours_active
from ..views import (
    actor_name_fields,
    camera_scope_condition,
    clamp_limit,
    decode_cursor,
    detection_fields,
    detection_source_for,
    detection_sources_for,
    encode_cursor,
    incident_detail,
    incident_summary,
    timestamp,
)

LOGGER = logging.getLogger("watchtower.cloud.incidents")

router = APIRouter(prefix="/incidents", tags=["incidents"])

# The states the console's state machine treats as finished. `IncidentService.reopen()` accepts
# only `resolved` and `closed`, so a `false_positive` decision is final from a handset too.
TERMINAL_STATUSES = (
    IncidentStatus.RESOLVED.value,
    IncidentStatus.CLOSED.value,
    IncidentStatus.FALSE_POSITIVE.value,
)


class NoteBody(BaseModel):
    note: str | None = Field(default=None, max_length=4000)


class EscalateBody(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)
    to_user_id: int | None = None
    to_role: str | None = Field(default=None, max_length=48)


class AssignBody(BaseModel):
    user_id: int


class ResolveBody(BaseModel):
    outcome: str = Field(min_length=3, max_length=64)
    resolution: str = Field(min_length=3, max_length=4000)
    false_positive: bool = False


class ReopenBody(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


def _fail(exc: IncidentServiceError) -> CloudError:
    """The service's own codes, translated into the contract's status numbers."""
    if exc.code == "not_found":
        return CloudError("not_found", exc.message, status_code=404)
    if exc.code == "forbidden":
        # 404 by contract: the response must not confirm that the record exists.
        return CloudError("not_found", "No such incident for this account.", status_code=404)
    if exc.code in {"already_resolved", "not_resolved", "invalid_state", "invalid_decision"}:
        return CloudError(exc.code, exc.message, status_code=409)
    return CloudError(exc.code or "request_failed", exc.message, status_code=422)


def _get_visible(session: Session, caller: Caller, incident_id: int) -> Incident:
    incident = session.get(Incident, incident_id)
    if incident is None:
        raise CloudError("not_found", "No such incident for this account.", status_code=404)
    camera = session.get(Camera, incident.camera_id) if incident.camera_id else None
    if camera is not None:
        from ...security.rbac import can_view_camera

        if not can_view_camera(caller.principal, "incident.view", camera):
            raise CloudError("not_found", "No such incident for this account.", status_code=404)
    return incident


def _evidence_brief(session: Session, incident_id: int) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(EvidenceAsset)
        .where(EvidenceAsset.incident_id == incident_id)
        .order_by(EvidenceAsset.captured_at, EvidenceAsset.id)
    ).all()
    return [
        {
            "id": asset.id,
            "kind": asset.kind,
            "content_type": asset.content_type,
            "state": "deleted" if asset.deleted_at else "available",
        }
        for asset in rows
    ]


def _full(session: Session, incident: Incident, settings: CloudSettings) -> dict[str, Any]:
    camera = session.get(Camera, incident.camera_id) if incident.camera_id else None
    source, confidence = detection_source_for(session, incident)
    body = incident_detail(
        incident, camera, detection_source=source, confidence=confidence
    )
    body["evidence"] = _evidence_brief(session, incident.id)
    body["acknowledgements"] = _acknowledgements(session, incident.id)
    acknowledgements = body["acknowledgements"]
    # The first acknowledgement is the one that matters to a duty officer looking for an owner;
    # later ones are recorded in the same list and the console shows all of them.
    body["acknowledged_by"] = acknowledgements[0]["user_id"] if acknowledgements else None
    body.update(actor_name_fields(session, [incident])[incident.id])
    return body


def _acknowledgements(session: Session, incident_id: int) -> list[dict[str, Any]]:
    rows = session.scalars(
        select(IncidentAcknowledgement)
        .where(IncidentAcknowledgement.incident_id == incident_id)
        .order_by(IncidentAcknowledgement.acknowledged_at)
    ).all()
    names = _display_names(session, {row.user_id for row in rows})
    return [
        {
            "user_id": row.user_id,
            "display_name": names.get(row.user_id),
            "source": row.source,
            "note": row.note,
            "acknowledged_at": timestamp(row.acknowledged_at),
        }
        for row in rows
    ]


def _display_names(session: Session, user_ids: set[int]) -> dict[int, str]:
    if not user_ids:
        return {}
    rows = session.execute(select(User.id, User.display_name).where(User.id.in_(user_ids))).all()
    return {int(user_id): name for user_id, name in rows}


@router.get("")
def list_incidents(
    status: list[str] = Query(default_factory=list),
    severity: list[str] = Query(default_factory=list),
    category: str | None = None,
    camera_id: str | None = None,
    location: str | None = None,
    q: str | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    cursor: str | None = None,
    limit: int | None = None,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.view")),
):
    known_status = {item.value for item in IncidentStatus}
    for value in status:
        if value not in known_status:
            raise CloudError("status_invalid", f"Unknown incident status {value!r}.", status_code=422)
    for value in severity:
        if value not in {item.value for item in Severity}:
            raise CloudError("severity_invalid", f"Unknown severity {value!r}.", status_code=422)

    page_size = clamp_limit(limit)
    statement = select(Incident).order_by(Incident.occurred_at.desc(), Incident.id.desc())
    scope = camera_scope_condition(caller.principal, "incident.view", Incident)
    if scope is not None:
        statement = statement.where(scope)
    if status:
        statement = statement.where(Incident.status.in_(status))
    if severity:
        statement = statement.where(Incident.severity.in_(severity))
    if category:
        statement = statement.where(Incident.category == category)
    if location:
        statement = statement.where(Incident.campus_location.ilike(f"%{location}%"))
    if since:
        statement = statement.where(Incident.occurred_at >= since)
    if until:
        statement = statement.where(Incident.occurred_at <= until)
    if camera_id:
        try:
            statement = statement.where(Incident.camera_id == uuid.UUID(camera_id))
        except ValueError as exc:
            raise CloudError(
                "camera_id_invalid", "camera_id must be a UUID.", status_code=422
            ) from exc
    if q:
        pattern = f"%{q}%"
        statement = statement.where(
            Incident.title.ilike(pattern)
            | Incident.reference.ilike(pattern)
            | Incident.summary.ilike(pattern)
        )

    # Cursor pagination over a `(occurred_at, id)` ordering: the timestamp alone is not unique.
    after = decode_cursor(cursor)
    if after.get("t") and after.get("o"):
        stamp = dt.datetime.fromisoformat(str(after["t"]))
        statement = statement.where(
            (Incident.occurred_at < stamp)
            | ((Incident.occurred_at == stamp) & (Incident.id < int(after["o"])))
        )

    rows = list(session.scalars(statement.limit(page_size + 1)).all())
    has_more = len(rows) > page_size
    page = rows[:page_size]
    cameras = {
        str(camera.id): camera
        for camera in session.scalars(
            select(Camera).where(
                Camera.id.in_([row.camera_id for row in page if row.camera_id])
            )
        ).all()
    } if any(row.camera_id for row in page) else {}
    sources = detection_sources_for(session, page)
    names = actor_name_fields(session, page)
    # The detail route hides the evidence list from a caller without `evidence.view`; the queue
    # must agree with it, or a badge advertises media the same account cannot open.
    may_see_evidence = caller.principal.allows("evidence.view")
    items = [
        {
            **incident_summary(
                row, cameras.get(str(row.camera_id)) if row.camera_id else None
            ),
            # A candidate stays a candidate in the queue, not only once opened.
            **detection_fields(*sources[row.id]),
            **names[row.id],
            "evidence": _evidence_brief(session, row.id) if may_see_evidence else [],
        }
        for row in page
    ]
    return {
        "items": items,
        "next_cursor": (
            encode_cursor({"t": page[-1].occurred_at.isoformat(), "o": page[-1].id})
            if has_more and page
            else None
        ),
    }


@router.get("/{incident_id}")
def get_incident(
    incident_id: int,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.view")),
):
    incident = _get_visible(session, caller, incident_id)
    body = _full(session, incident, settings)
    camera = session.get(Camera, incident.camera_id) if incident.camera_id else None
    if camera is not None and not caller.principal.allows("evidence.view"):
        # The incident is in scope but its evidence is not: show the record, hide the media.
        body["evidence"] = []
    return body


@router.get("/{incident_id}/activity")
def activity(
    incident_id: int,
    cursor: str | None = None,
    limit: int | None = None,
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
):
    incident = _get_visible(session, caller, incident_id)
    page_size = clamp_limit(limit)
    statement = (
        select(IncidentAction)
        .where(IncidentAction.incident_id == incident.id)
        .order_by(IncidentAction.id.desc())
    )
    last_id = decode_cursor(cursor).get("o")
    if isinstance(last_id, int):
        statement = statement.where(IncidentAction.id < last_id)
    rows = list(session.scalars(statement.limit(page_size + 1)).all())
    has_more = len(rows) > page_size
    page = rows[:page_size]
    names = _display_names(session, {row.actor_id for row in page if row.actor_id})
    return {
        "items": [
            {
                "id": row.id,
                "action": row.action,
                "note": row.note,
                "actor_id": row.actor_id,
                "actor_name": names.get(row.actor_id) if row.actor_id else None,
                "created_at": timestamp(row.created_at),
            }
            for row in page
        ],
        "next_cursor": encode_cursor({"o": page[-1].id}) if has_more and page else None,
    }


def _rate_limit(container: CloudContainer, settings: CloudSettings, caller: Caller) -> None:
    enforce(
        container.limiter,
        "incident-action",
        str(caller.user_id),
        limit=settings.action_attempts_per_minute,
        window_seconds=60,
        code="too_many_actions",
    )


def _mark_caller_notified(session: Session, caller: Caller, incident: Incident) -> int:
    """The alert that reached this phone is now acknowledged, not merely read."""
    rows = session.scalars(
        select(Notification).where(
            Notification.recipient_id == caller.user_id,
            Notification.incident_id == incident.id,
            Notification.channel == NotificationChannel.MOBILE_PUSH.value,
            Notification.state.in_(
                (
                    NotificationState.PENDING.value,
                    NotificationState.DELIVERED.value,
                    NotificationState.READ.value,
                )
            ),
        )
    ).all()
    now = utcnow()
    for note in rows:
        note.state = NotificationState.ACKNOWLEDGED.value
        note.acknowledged_at = now
        attempts = session.scalars(
            select(NotificationAttempt).where(
                NotificationAttempt.notification_id == note.id
            )
        ).all()
        for attempt in attempts:
            if attempt.state == AttemptState.SUBMITTED.value:
                # The person acted on the alert, so the send evidently did reach a handset even
                # though FCM had not reported acceptance at the time it was dispatched.
                attempt.state = AttemptState.ACCEPTED.value
                attempt.accepted_at = attempt.accepted_at or now
    session.flush()
    return len(rows)


@router.post("/{incident_id}/acknowledge")
def acknowledge(
    incident_id: int,
    body: NoteBody,
    request: Request,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.acknowledge")),
):
    _rate_limit(container, settings, caller)
    incident = _get_visible(session, caller, incident_id)
    if incident.status in TERMINAL_STATUSES:
        raise CloudError(
            "incident_not_actionable",
            "This incident is already resolved or closed; reopen it before acknowledging.",
            status_code=409,
        )

    record = IncidentAcknowledgement(
        incident_id=incident.id,
        user_id=caller.user_id,
        source="mobile",
        note=body.note,
    )
    duplicate = False
    try:
        with session.begin_nested():
            session.add(record)
    except IntegrityError:
        # Two phones tapping at once: the constraint decides, and the second answer says so.
        duplicate = True
    existing = session.scalar(
        select(IncidentAcknowledgement).where(
            IncidentAcknowledgement.incident_id == incident.id,
            IncidentAcknowledgement.user_id == caller.user_id,
        )
    )
    if existing is not None:
        record = existing

    if incident.status == IncidentStatus.OPEN.value:
        incident.status = IncidentStatus.INVESTIGATING.value
    if incident.assigned_to is None:
        incident.assigned_to = caller.user_id
    if not duplicate:
        incident.actions.append(
            IncidentAction(
                action="acknowledged",
                note=body.note or "acknowledged from the mobile application",
                actor_id=caller.user_id,
            )
        )
    session.flush()

    notified = _mark_caller_notified(session, caller, incident)
    audit_record(
        session,
        principal=caller.principal,
        action="incident.acknowledge",
        object_type="incident",
        object_id=str(incident.id),
        details={"reference": incident.reference, "already_acknowledged": duplicate,
                 "notifications_acknowledged": notified},
        source_ip=caller.source_ip,
    )
    return {**_full(session, incident, settings), "already_acknowledged": duplicate}


@router.post("/{incident_id}/investigating")
def mark_investigating(
    incident_id: int,
    body: NoteBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.view")),
):
    """Working on it without claiming responsibility - the console's `note` transition."""
    _rate_limit(container, settings, caller)
    try:
        incident = container.incident_service(session).note(
            incident_id, caller.principal, text=body.note or "investigating", investigation=True
        )
    except IncidentServiceError as exc:
        raise _fail(exc) from exc
    return _full(session, incident, settings)


@router.post("/{incident_id}/notes")
def add_note(
    incident_id: int,
    body: NoteBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.view")),
):
    _rate_limit(container, settings, caller)
    if not body.note or not body.note.strip():
        raise CloudError("note_required", "A note cannot be empty.", status_code=422)
    try:
        incident = container.incident_service(session).note(
            incident_id, caller.principal, text=body.note, investigation=False
        )
    except IncidentServiceError as exc:
        raise _fail(exc) from exc
    audit_record(
        session,
        principal=caller.principal,
        action="incident.note",
        object_type="incident",
        object_id=str(incident.id),
        details={"reference": incident.reference},
        source_ip=caller.source_ip,
    )
    return _full(session, incident, settings)


@router.post("/{incident_id}/escalate")
def escalate(
    incident_id: int,
    body: EscalateBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.escalate")),
):
    _rate_limit(container, settings, caller)
    target = _escalation_target(session, body, caller)
    try:
        incident = container.incident_service(session).escalate(
            incident_id, caller.principal, to_user_id=target.id, note=body.reason
        )
    except IncidentServiceError as exc:
        raise _fail(exc) from exc

    # The console's `escalate` queues the alert into the outbox for the monitoring host to send.
    # A phone is already talking to the cloud, so the follow-up goes out from here instead.
    intent = AlertIntent(
        kind="incident.escalated",
        severity=incident.severity,
        title=f"Incident {incident.reference} escalated",
        body=body.reason,
        incident_id=incident.id,
        camera_id=incident.camera_id,
    )
    report = enqueue_alert(session, settings, intent, exclude_user_ids={caller.user_id, target.id})
    audit_record(
        session,
        principal=caller.principal,
        action="incident.escalate",
        object_type="incident",
        object_id=str(incident.id),
        details={"reference": incident.reference, "to": target.username,
                 "notifications_created": report.created},
        source_ip=caller.source_ip,
    )
    payload = _full(session, incident, settings)
    payload["notifications"] = report.as_dict()
    return payload


def _escalation_target(session: Session, body: EscalateBody, caller: Caller) -> User:
    """Who the incident goes to: a named person, or the next role up that can act."""
    if body.to_user_id is not None:
        user = session.get(User, body.to_user_id)
        if user is None or not user.is_active:
            raise CloudError("not_found", "No such user to escalate to.", status_code=404)
        return user
    role_code = body.to_role or "security_supervisor"
    from ...models import Role, UserRole

    row = session.execute(
        select(User)
        .join(UserRole, UserRole.user_id == User.id)
        .join(Role, Role.id == UserRole.role_id)
        .where(
            Role.code == role_code,
            User.is_active.is_(True),
            User.id != caller.user_id,
        )
        .order_by(User.id)
        .limit(1)
    ).scalar()
    if row is None:
        raise CloudError(
            "escalation_target_unavailable",
            f"No active account holds the {role_code} role to escalate to.",
            status_code=409,
        )
    return row


@router.post("/{incident_id}/assign")
def assign(
    incident_id: int,
    body: AssignBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.assign")),
):
    _rate_limit(container, settings, caller)
    try:
        incident = container.incident_service(session).assign(
            incident_id, caller.principal, assignee_id=body.user_id
        )
    except IncidentServiceError as exc:
        raise _fail(exc) from exc
    intent = AlertIntent(
        kind="incident.assigned",
        severity=incident.severity,
        title=f"Incident {incident.reference} assigned to you",
        body=caller.principal.display_name,
        incident_id=incident.id,
        camera_id=incident.camera_id,
    )
    report = enqueue_alert(session, settings, intent, exclude_user_ids={caller.user_id})
    payload = _full(session, incident, settings)
    payload["notifications"] = report.as_dict()
    return payload


@router.post("/{incident_id}/resolve")
def resolve(
    incident_id: int,
    body: ResolveBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.resolve")),
):
    _rate_limit(container, settings, caller)
    try:
        incident = container.incident_service(session).resolve(
            incident_id,
            caller.principal,
            outcome=body.outcome,
            resolution=body.resolution,
            false_positive=body.false_positive,
        )
    except IncidentServiceError as exc:
        raise _fail(exc) from exc
    intent = AlertIntent(
        kind="incident.resolved",
        severity=incident.severity,
        title=f"Incident {incident.reference} {incident.status}",
        body=body.resolution,
        incident_id=incident.id,
        camera_id=incident.camera_id,
        requires_action=False,
    )
    report = enqueue_alert(session, settings, intent, exclude_user_ids={caller.user_id})
    payload = _full(session, incident, settings)
    payload["notifications"] = report.as_dict()
    return payload


@router.post("/{incident_id}/reopen")
def reopen(
    incident_id: int,
    body: ReopenBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.resolve")),
):
    _rate_limit(container, settings, caller)
    try:
        incident = container.incident_service(session).reopen(
            incident_id, caller.principal, reason=body.reason
        )
    except IncidentServiceError as exc:
        raise _fail(exc) from exc
    intent = AlertIntent(
        kind="incident.created",
        severity=incident.severity,
        title=f"Incident {incident.reference} reopened",
        body=body.reason,
        incident_id=incident.id,
        camera_id=incident.camera_id,
        stage="reopened",
    )
    report = enqueue_alert(session, settings, intent, exclude_user_ids={caller.user_id})
    payload = _full(session, incident, settings)
    payload["notifications"] = report.as_dict()
    return payload


@router.get("/{incident_id}/evidence")
def evidence_list(
    incident_id: int,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("evidence.view")),
):
    from ..evidence_tokens import mint
    from ..storage import asset_state

    incident = _get_visible(session, caller, incident_id)
    rows = session.scalars(
        select(EvidenceAsset)
        .where(EvidenceAsset.incident_id == incident.id)
        .order_by(EvidenceAsset.captured_at, EvidenceAsset.id)
    ).all()
    items = []
    for asset in rows:
        state = asset_state(settings, asset)
        entry: dict[str, Any] = {
            "id": asset.id,
            "kind": asset.kind,
            "content_type": asset.content_type,
            "byte_size": asset.byte_size,
            "captured_at": timestamp(asset.captured_at),
            "expires_at": timestamp(asset.expires_at),
            "state": state,
            "sha256": asset.sha256,
            "url": None,
            "expires_at_token": None,
        }
        if state == "available":
            token, expires_at = mint(settings, asset_id=asset.id, user_id=caller.user_id)
            entry["url"] = (
                f"{settings.public_base_url.rstrip('/')}/api/v1/evidence/{asset.id}/content"
                f"?token={token}"
            )
            entry["expires_at_token"] = timestamp(
                dt.datetime.fromtimestamp(expires_at, dt.UTC)
            )
        items.append(entry)
    return {"items": items, "incident_id": incident.id, "reference": incident.reference}


@router.get("/{incident_id}/preferences-check")
def preferences_check(
    incident_id: int,
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
):
    """Diagnostics for the profile screen: would this account be paged for this incident?"""
    incident = _get_visible(session, caller, incident_id)
    preference = session.scalar(
        select(PersonnelPreference).where(PersonnelPreference.user_id == caller.user_id)
    )
    total = int(
        session.scalar(
            select(func.count()).select_from(IncidentAcknowledgement).where(
                IncidentAcknowledgement.incident_id == incident.id
            )
        )
        or 0
    )
    return {
        "incident_id": incident.id,
        "severity": incident.severity,
        "acknowledgements": total,
        "min_severity": preference.min_severity if preference else None,
        # An enabled switch, not a non-empty blob: `{enabled: false, start: ..., end: ...}` is the
        # shape the profile screen saves for an account that has never wanted silence, and the
        # answer here has to match the predicate the delivery worker applies.
        "quiet_hours": quiet_hours_active(preference.quiet_hours) if preference else False,
    }
