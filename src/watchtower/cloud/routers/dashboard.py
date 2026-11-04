"""The phone's opening screen, computed on the server (contract section 4).

Every number is an aggregate over rows the caller is allowed to see, filtered by the same camera
scope the console uses. Nothing here is hardcoded in the client and nothing is a placeholder:
"0 active incidents" is only a reassuring answer if it means the same thing as the console's.
"""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...mobile.models import (
    IncidentAcknowledgement,
    MobileDevice,
    NotificationAttempt,
    NotificationOutbox,
    OutboxState,
)
from ...models import (
    Incident,
    IncidentStatus,
    Notification,
    NotificationChannel,
    NotificationState,
    Severity,
    User,
    utcnow,
)
from ..deps import Caller, get_db, require_permission
from ..views import OPEN_STATUSES, camera_scope_condition, role_codes, timestamp

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

ACTIVE_STATUSES = OPEN_STATUSES


@router.get("/summary")
def summary(
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
):
    now = utcnow()
    day_ago = now - dt.timedelta(hours=24)
    scope = camera_scope_condition(caller.principal, "incident.view", Incident)

    def incident_count(*conditions) -> int:
        statement = select(func.count(Incident.id))
        for condition in conditions:
            statement = statement.where(condition)
        if scope is not None:
            statement = statement.where(scope)
        return int(session.scalar(statement) or 0)

    active = incident_count(Incident.status.in_(ACTIVE_STATUSES))
    critical_open = incident_count(
        Incident.status.in_(ACTIVE_STATUSES), Incident.severity == Severity.CRITICAL.value
    )
    high_open = incident_count(
        Incident.status.in_(ACTIVE_STATUSES), Incident.severity == Severity.HIGH.value
    )

    # Acknowledged, in the mobile sense, means somebody accepted responsibility for responding.
    # An incident nobody has claimed is the queue a duty officer actually works through, so the
    # count comes from the acknowledgement rows rather than from a status that can also move for
    # other reasons.
    acknowledged_ids = select(IncidentAcknowledgement.incident_id)
    awaiting = incident_count(
        Incident.status.in_(ACTIVE_STATUSES), Incident.id.not_in(acknowledged_ids)
    )
    acknowledged_last_24h = int(
        session.scalar(
            select(func.count(func.distinct(IncidentAcknowledgement.incident_id))).where(
                IncidentAcknowledgement.acknowledged_at >= day_ago
            )
        )
        or 0
    )
    resolved_last_24h = incident_count(
        Incident.status.in_(
            (IncidentStatus.RESOLVED.value, IncidentStatus.CLOSED.value,
             IncidentStatus.FALSE_POSITIVE.value)
        ),
        Incident.resolved_at >= day_ago,
    )

    unread = int(
        session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.recipient_id == caller.user_id,
                Notification.state.in_(
                    (NotificationState.PENDING.value, NotificationState.DELIVERED.value)
                ),
            )
        )
        or 0
    )
    failed_delivery = int(
        session.scalar(
            select(func.count())
            .select_from(Notification)
            .where(
                Notification.recipient_id == caller.user_id,
                Notification.channel == NotificationChannel.MOBILE_PUSH.value,
                Notification.state == NotificationState.FAILED.value,
            )
        )
        or 0
    )

    outbox_pending = int(
        session.scalar(
            select(func.count())
            .select_from(NotificationOutbox)
            .where(
                NotificationOutbox.state.in_(
                    (OutboxState.QUEUED.value, OutboxState.PROCESSING.value)
                )
            )
        )
        or 0
    )
    outbox_failed = int(
        session.scalar(
            select(func.count())
            .select_from(NotificationOutbox)
            .where(
                NotificationOutbox.state.in_((OutboxState.FAILED.value, OutboxState.DEAD.value))
            )
        )
        or 0
    )
    # The last time FCM accepted something is evidence the send path works; the absence of one
    # is not evidence that it does not, which is why this is a timestamp and not a status word.
    last_push = session.scalar(select(func.max(NotificationAttempt.accepted_at)))

    user = session.get(User, caller.user_id)
    return {
        "generated_at": timestamp(now),
        "incidents": {
            "active": active,
            "awaiting_acknowledgement": awaiting,
            "critical_open": critical_open,
            "high_open": high_open,
            "acknowledged_last_24h": acknowledged_last_24h,
            "resolved_last_24h": resolved_last_24h,
        },
        "notifications": {"unread": unread, "failed_delivery": failed_delivery},
        "delivery": {
            "outbox_pending": outbox_pending,
            "outbox_failed": outbox_failed,
            "last_successful_push_at": timestamp(last_push),
            "active_devices": int(
                session.scalar(
                    select(func.count())
                    .select_from(MobileDevice)
                    .where(
                        MobileDevice.user_id == caller.user_id,
                        MobileDevice.push_state == "active",
                    )
                )
                or 0
            ),
        },
        "personnel": {
            "display_name": user.display_name if user else None,
            "roles": role_codes(session, caller.user_id),
            "permissions": sorted(caller.principal.permissions()),
        },
    }
