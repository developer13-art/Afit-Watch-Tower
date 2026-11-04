"""Response bodies for the cloud API, in one place.

The mobile app and the web console read the same database rows, so the shape of what they each
see is a decision rather than an accident. Two rules apply to everything here:

  * A field that would tell a bystander where something sensitive happens, or how the estate is
    wired, is not included. Camera connection material is not reachable from these columns at
    all, which is the point of building the views from the row's own display fields.
  * A timestamp is emitted as RFC 3339 with an explicit offset. SQLite hands back naive
    datetimes for `timestamptz` columns, so the naive ones are labelled UTC here rather than
    left ambiguous on the wire.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from ..models import Camera, Incident, IncidentStatus, Notification, User
from ..security.rbac import Principal


def camera_scope_condition(principal: Principal, permission: str, model):
    """A SQL predicate that means the same thing as the console's `can_view_camera`.

    Returns `None` when the grant is institution-wide, so callers add nothing. An incident with
    no camera - a manual report about something a camera did not record - stays visible to
    anybody who holds the permission at all, which is how `_require()` in the console treats it.
    Deliberately mirrored rather than re-implemented differently, because a phone that sees a
    wider scope than the console is an access-control defect, not a convenience.
    """
    scope = principal.camera_scope(permission)
    if scope is None:
        return None
    if not hasattr(model, "camera_id"):
        return None
    camera_ids = select(Camera.id).where(Camera.camera_group_id.in_(scope))
    return or_(model.camera_id.is_(None), model.camera_id.in_(camera_ids))


def timestamp(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    aware = value if value.tzinfo else value.replace(tzinfo=dt.UTC)
    return aware.astimezone(dt.UTC).isoformat().replace("+00:00", "Z")


def encode_cursor(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> dict[str, Any]:
    if not cursor:
        return {}
    padding = "=" * (-len(cursor) % 4)
    try:
        raw = base64.urlsafe_b64decode(cursor + padding)
        decoded = json.loads(raw)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        decoded = None
    if not isinstance(decoded, dict):
        # A malformed cursor is a client bug, not a reason to serve an unfiltered page.
        from .errors import CloudError

        raise CloudError("cursor_invalid", "The pagination cursor is not recognised.", status_code=422)
    return decoded


def clamp_limit(value: int | None, *, default: int = 25, maximum: int = 100) -> int:
    if value is None:
        return default
    return max(1, min(int(value), maximum))


def role_codes(session: Session, user_id: int) -> list[str]:
    from ..models import Role, UserRole

    rows = session.execute(
        select(Role.code)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.code)
    ).all()
    return [code for (code,) in rows]


def user_view(session: Session, user: User, principal: Principal) -> dict[str, Any]:
    """What the app needs to render itself: identity, roles, effective permissions.

    `permissions` appears here and nowhere in the access token, so the app's idea of what the
    user may do is the server's idea, read fresh, on every cold start.
    """
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "phone": user.phone,
        "roles": role_codes(session, user.id),
        "permissions": sorted(principal.permissions()),
        "is_active": user.is_active,
        "must_change_password": bool(user.must_change_password),
        "last_login_at": timestamp(user.last_login_at),
        "camera_scope": _scope(principal),
    }


def _scope(principal: Principal) -> dict[str, Any]:
    """The camera-group limitation, if any, stated as the client needs to see it."""
    scoped = principal.camera_scope("incident.view")
    return {
        "incident.view": "all" if scoped is None else sorted(scoped),
        "evidence.view": "all"
        if principal.camera_scope("evidence.view") is None
        else sorted(principal.camera_scope("evidence.view")),
    }


def camera_brief(camera: Camera | None) -> dict[str, Any]:
    if camera is None:
        return {"camera_id": None, "camera_name": None, "campus_location": None}
    return {
        "camera_id": str(camera.id),
        "camera_name": camera.display_name,
        "campus_location": camera.campus_location,
    }


def incident_summary(incident: Incident, camera: Camera | None) -> dict[str, Any]:
    return {
        "id": incident.id,
        "reference": incident.reference,
        "title": incident.title,
        "category": incident.category,
        "severity": incident.severity,
        "status": incident.status,
        "occurred_at": timestamp(incident.occurred_at),
        "created_at": timestamp(incident.created_at),
        "assigned_to": incident.assigned_to,
        "escalated_to": incident.escalated_to,
        **camera_brief(camera),
    }


def incident_detail(incident: Incident, camera: Camera | None, *, detection_source: str,
                    confidence: float | None) -> dict[str, Any]:
    return {
        **incident_summary(incident, camera),
        "summary": incident.summary,
        "resolution": incident.resolution,
        "outcome": incident.outcome,
        "resolved_at": timestamp(incident.resolved_at),
        "updated_at": timestamp(incident.updated_at),
        "origin_event_id": incident.origin_event_id,
        # An AI candidate is a prompt for a person, never a conclusion; the app renders this
        # value as an explicit "unverified" label and the API never sends a UI string.
        **detection_fields(detection_source, confidence),
        "acknowledged_by": None,
    }


def detection_fields(source: str, confidence: float | None) -> dict[str, Any]:
    """The two candidate-event fields, spelled the same in a list item and a detail body.

    Kept in one place because an app that has to guess which of the two shapes it is looking at
    is an app that drops the "unverified" label somewhere it should not be dropped.
    """
    return {"detection_source": source, "confidence": confidence}


def _confidence_of(event) -> float | None:
    metadata = dict(event.event_metadata or {})
    confidence = metadata.get("peak_confidence", event.confidence)
    return float(confidence) if isinstance(confidence, (int, float)) else None


def detection_source_for(session: Session, incident: Incident) -> tuple[str, float | None]:
    """`manual | ai_candidate`, plus the confidence that produced a candidate.

    Read from the event rather than trusted from the payload: the row the monitoring host wrote
    is the record of what was detected, and a phone must never be shown a confidence the
    detector did not produce.
    """
    from ..mobile.models import DETECTION_SOURCE_MANUAL
    from ..models import DetectionEvent

    if incident.origin_event_id is None:
        return DETECTION_SOURCE_MANUAL, None
    event = session.get(DetectionEvent, incident.origin_event_id)
    if event is None:
        # The candidate row has since been pruned; the incident stands, its origin no longer does.
        return DETECTION_SOURCE_MANUAL, None
    return "ai_candidate", _confidence_of(event)


def detection_sources_for(
    session: Session, incidents: list[Incident]
) -> dict[int, tuple[str, float | None]]:
    """`detection_source_for()` for a whole page, in one query instead of one per row.

    The list endpoint needs the same two fields the detail page sends. A queue that hid the
    candidate label would let an unread incident be judged as settled fact before anybody opened
    it, which is the exact failure §6.1 is written to prevent.
    """
    from ..mobile.models import DETECTION_SOURCE_MANUAL
    from ..models import DetectionEvent

    sources: dict[int, tuple[str, float | None]] = {
        incident.id: (DETECTION_SOURCE_MANUAL, None) for incident in incidents
    }
    event_ids = [incident.origin_event_id for incident in incidents if incident.origin_event_id]
    if not event_ids:
        return sources
    events = session.scalars(
        select(DetectionEvent).where(DetectionEvent.id.in_(event_ids))
    ).all()
    by_id = {event.id: event for event in events}
    for incident in incidents:
        event = by_id.get(incident.origin_event_id) if incident.origin_event_id else None
        if event is not None:
            sources[incident.id] = ("ai_candidate", _confidence_of(event))
    return sources


def notification_view(
    session: Session,
    note: Notification,
    *,
    settings,
    camera: Camera | None = None,
    incident_reference: str | None = None,
) -> dict[str, Any]:
    body = {
        "id": note.id,
        "kind": note.kind,
        "title": note.title,
        "body": note.body,
        "severity": note.severity,
        "state": note.state,
        "read_at": timestamp(note.read_at),
        "acknowledged_at": timestamp(note.acknowledged_at),
        "delivered_at": timestamp(note.delivered_at),
        "created_at": timestamp(note.created_at),
        "incident_id": note.incident_id,
        "incident_reference": incident_reference,
        "failure_reason": note.failure_reason if note.state == "failed" else None,
        **camera_brief(camera),
    }
    if note.incident_id is not None:
        body["deep_link"] = f"{settings.deep_link_base}incidents/{note.incident_id}"
    return body


OPEN_STATUSES = (
    IncidentStatus.OPEN.value,
    IncidentStatus.INVESTIGATING.value,
    IncidentStatus.ASSIGNED.value,
)


def actor_names(session: Session, user_ids: set[int]) -> dict[int, str]:
    if not user_ids:
        return {}
    rows = session.execute(select(User.id, User.display_name).where(User.id.in_(user_ids))).all()
    return {int(user_id): name for user_id, name in rows}


def actor_name_fields(session: Session, incidents: list[Incident]) -> dict[int, dict[str, Any]]:
    """`assigned_to_name` and `escalated_to_name` for a set of incidents, in one query.

    The columns the console writes are user ids, and a phone that shows `assigned_to: 7` has told
    the duty officer nothing they can act on. The names are added here rather than joined into
    the ORM relationship because a list page needs one read for the whole page, not one per row.
    """
    wanted = {
        user_id
        for incident in incidents
        for user_id in (incident.assigned_to, incident.escalated_to)
        if user_id is not None
    }
    names = actor_names(session, wanted)
    return {
        incident.id: {
            "assigned_to_name": names.get(incident.assigned_to) if incident.assigned_to else None,
            "escalated_to_name": names.get(incident.escalated_to) if incident.escalated_to else None,
        }
        for incident in incidents
    }
