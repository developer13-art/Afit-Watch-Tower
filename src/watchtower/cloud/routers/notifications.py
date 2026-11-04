"""The recipient's own alert list (contract section 5).

A caller only ever sees rows addressed to them: `recipient_id` is part of every query here, not a
filter the client may pass. `total_unread` is computed from the same scope as the page, so the
badge and the list cannot disagree about what is waiting.
"""

from __future__ import annotations

import datetime as dt
import logging

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...mobile.models import NotificationAttempt
from ...models import Camera, Incident, Notification, NotificationState, Severity, utcnow
from ..config import CloudSettings
from ..deps import Caller, get_db, get_settings, require_permission
from ..errors import CloudError
from ..views import clamp_limit, decode_cursor, encode_cursor, notification_view

LOGGER = logging.getLogger("watchtower.cloud.notifications")

router = APIRouter(prefix="/notifications", tags=["notifications"])

# States that still count as unread on a badge. `pending` is included: the phone is being told
# there is something waiting even while the send is in flight. `suppressed` is included because
# suppression is about noise, not hiding: a quiet-hours alert, and an alert for a handset with no
# push channel at all, are both rows the officer has not looked at yet.
UNREAD_STATES = (
    NotificationState.PENDING.value,
    NotificationState.DELIVERED.value,
    NotificationState.SUPPRESSED.value,
)

# A suppressed alert is readable for the same reason it is countable as unread: with no push
# channel it is only ever seen here, and an alert the officer has already opened must stop
# counting. `failed` stays out - the send itself is finished, and reopening it is an
# administrator's decision, not something the read button undoes.
READABLE_STATES = (
    NotificationState.DELIVERED.value,
    NotificationState.PENDING.value,
    NotificationState.SUPPRESSED.value,
)


class ReadAllBody(BaseModel):
    before: dt.datetime | None = None


def _page(
    session: Session,
    caller: Caller,
    *,
    unread_only: bool,
    severities: list[str],
    kind: str | None,
    since: dt.datetime | None,
    until: dt.datetime | None,
    cursor: str | None,
    limit: int,
    settings: CloudSettings,
) -> dict:
    statement = select(Notification).where(Notification.recipient_id == caller.user_id)
    if unread_only:
        statement = statement.where(Notification.state.in_(UNREAD_STATES))
    if severities:
        statement = statement.where(Notification.severity.in_(severities))
    if kind:
        statement = statement.where(Notification.kind == kind)
    if since:
        statement = statement.where(Notification.created_at >= since)
    if until:
        statement = statement.where(Notification.created_at <= until)
    last_id = decode_cursor(cursor).get("o")
    if isinstance(last_id, int):
        statement = statement.where(Notification.id < last_id)

    rows = list(session.scalars(statement.order_by(Notification.id.desc()).limit(limit + 1)).all())
    has_more = len(rows) > limit
    page = rows[:limit]

    items = []
    for note in page:
        camera = session.get(Camera, note.camera_id) if note.camera_id else None
        reference = None
        if note.incident_id is not None:
            reference = session.scalar(
                select(Incident.reference).where(Incident.id == note.incident_id)
            )
        items.append(
            notification_view(
                session, note, settings=settings, camera=camera, incident_reference=reference
            )
        )

    total_unread = int(
        session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.recipient_id == caller.user_id,
                Notification.state.in_(UNREAD_STATES),
            )
        )
        or 0
    )
    next_cursor = encode_cursor({"o": page[-1].id}) if has_more and page else None
    return {"items": items, "next_cursor": next_cursor, "total_unread": total_unread}


@router.get("")
def list_notifications(
    unread_only: bool = False,
    severity: list[str] = Query(default_factory=list),
    kind: str | None = None,
    from_: dt.datetime | None = Query(default=None, alias="from"),
    to: dt.datetime | None = None,
    cursor: str | None = None,
    limit: int | None = None,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("incident.view")),
):
    for value in severity:
        if value not in {item.value for item in Severity}:
            raise CloudError("severity_invalid", f"Unknown severity {value!r}.", status_code=422)
    return _page(
        session,
        caller,
        unread_only=unread_only,
        severities=list(severity),
        kind=kind,
        since=from_,
        until=to,
        cursor=cursor,
        limit=clamp_limit(limit),
        settings=settings,
    )


def _own_note(session: Session, caller: Caller, notification_id: int) -> Notification:
    note = session.get(Notification, notification_id)
    if note is None or note.recipient_id != caller.user_id:
        # Somebody else's alert, or no alert: the same answer either way.
        raise CloudError("not_found", "No such notification for this account.", status_code=404)
    return note


@router.post("/{notification_id}/read")
def mark_read(
    notification_id: int,
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
):
    note = _own_note(session, caller, notification_id)
    if note.state not in READABLE_STATES:
        # Already read, acknowledged or failed: reading is not a state machine to force, and a
        # failed send is a fact about the send, not something the read button undoes.
        return {"id": note.id, "state": note.state, "read_at": None, "unchanged": True}
    note.state = NotificationState.READ.value
    note.read_at = utcnow()
    session.flush()
    return {"id": note.id, "state": note.state, "read_at": note.read_at.isoformat()}


@router.post("/read-all")
def mark_all_read(
    body: ReadAllBody,
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
):
    statement = select(Notification).where(
        Notification.recipient_id == caller.user_id,
        Notification.state.in_(READABLE_STATES),
    )
    if body.before is not None:
        statement = statement.where(Notification.created_at <= body.before)
    now = utcnow()
    rows = list(session.scalars(statement).all())
    for note in rows:
        note.state = NotificationState.READ.value
        note.read_at = now
    session.flush()
    return {"marked_read": len(rows)}


@router.post("/{notification_id}/open")
def mark_open(
    notification_id: int,
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
):
    """The push was tapped and the screen actually rendered.

    This is the only "seen" signal the platform can honestly claim, and it is recorded per device
    on the send itself rather than mutating the alert: a recipient with two handsets opened one
    of them, and that is a fact worth keeping separate.
    """
    note = _own_note(session, caller, notification_id)
    now = utcnow()
    attempts = list(
        session.scalars(
            select(NotificationAttempt).where(
                NotificationAttempt.notification_id == note.id,
                NotificationAttempt.opened_at.is_(None),
            )
        ).all()
    )
    for attempt in attempts:
        attempt.opened_at = now
    if note.state == NotificationState.DELIVERED.value:
        note.read_at = note.read_at or now
    session.flush()
    return {"id": note.id, "attempts_marked_open": len(attempts), "opened_at": now.isoformat()}
