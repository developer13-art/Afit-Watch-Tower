"""Dashboard notification inbox endpoints (section 15)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..deps import current_principal, get_db
from ...models import Notification, NotificationState
from ...security.rbac import Principal
from ...services.notifications import NotificationService

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


def _view(row: Notification) -> dict:
    return {
        "id": row.id,
        "kind": row.kind,
        "title": row.title,
        "body": row.body,
        "severity": row.severity,
        "state": row.state,
        "camera_id": str(row.camera_id) if row.camera_id else None,
        "incident_id": row.incident_id,
        "event_id": row.event_id,
        "created_at": row.created_at.isoformat(),
        "delivered_at": row.delivered_at.isoformat() if row.delivered_at else None,
        "acknowledged_at": row.acknowledged_at.isoformat() if row.acknowledged_at else None,
        "failure_reason": row.failure_reason,
    }


@router.get("")
def inbox(
    unread_only: bool = True,
    limit: int = Query(default=100, le=500),
    session: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> dict:
    statement = (
        select(Notification)
        .where(Notification.recipient_id == principal.user_id)
        .order_by(Notification.created_at.desc())
        .limit(limit)
    )
    if unread_only:
        statement = statement.where(
            Notification.state.in_(
                [NotificationState.PENDING.value, NotificationState.DELIVERED.value]
            )
        )
    rows = session.scalars(statement).all()
    counts = {
        state.value: session.scalar(
            select(func.count(Notification.id)).where(
                Notification.recipient_id == principal.user_id,
                Notification.state == state.value,
            )
        )
        or 0
        for state in NotificationState
    }
    return {"notifications": [_view(row) for row in rows], "counts": counts}


def _owned(session: Session, notification_id: int, principal: Principal) -> Notification:
    row = session.get(Notification, notification_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such notification.")
    if row.recipient_id != principal.user_id:
        # Existence of another user's alert is not disclosed.
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such notification.")
    return row


@router.post("/{notification_id}/read")
def mark_read(
    notification_id: int,
    session: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> dict:
    row = _owned(session, notification_id, principal)
    NotificationService(session, webhook_url=None).mark_read(row.id)
    return {"status": row.state}


@router.post("/{notification_id}/acknowledge")
def mark_acknowledged(
    notification_id: int,
    session: Session = Depends(get_db),
    principal: Principal = Depends(current_principal),
) -> dict:
    row = _owned(session, notification_id, principal)
    NotificationService(session, webhook_url=None).mark_acknowledged(row.id)
    return {"status": row.state}
