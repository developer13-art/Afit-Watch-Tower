"""The hook that turns an incident state change into an alert the cloud must receive.

Kept separate from `outbox` because it is the only part that knows about the *application*
transaction. `IncidentService` calls it before its own commit, which is what makes the
proposal's rule true: the incident row and the alert row either both exist or neither does.

Nothing here raises. A deployment with no cloud configuration is the normal case, not an
error, and a monitoring host that cannot reach its database must still keep the incident.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Camera, DetectionEvent, EvidenceAsset, Incident
from .outbox import enqueue_or_spool, intent_for_incident

LOGGER = logging.getLogger("watchtower.mobile.alerts")

# Alert kinds the mobile application recognises; see mobile-api-contract.md section 9.
KIND_CREATED = "created"
KIND_ASSIGNED = "assigned"
KIND_ESCALATED = "escalated"
KIND_RESOLVED = "resolved"
INCIDENT_KINDS = (KIND_CREATED, KIND_ASSIGNED, KIND_ESCALATED, KIND_RESOLVED)


def evidence_keys_for(session: Session, incident_id: int) -> list[str]:
    """Storage keys for the assets attached to this incident, oldest capture first.

    Deleted assets are skipped: the phone is told there is no evidence rather than handed a
    key that resolves to nothing.
    """
    return list(
        session.scalars(
            select(EvidenceAsset.storage_key)
            .where(
                EvidenceAsset.incident_id == incident_id,
                EvidenceAsset.deleted_at.is_(None),
            )
            .order_by(EvidenceAsset.captured_at, EvidenceAsset.id)
        ).all()
    )


def enqueue_incident_alert(
    settings: Settings | None,
    session: Session,
    incident: Incident,
    *,
    kind: str = KIND_CREATED,
    event: DetectionEvent | None = None,
) -> str:
    """Queue the mobile alert for one incident transition; returns the classification.

    `"disabled"` means this deployment forwards nothing, which is a configuration choice made
    in `watchtower.config._cloud_settings`, not a failure.
    """
    if settings is None or not settings.mobile_forwarding_enabled:
        return "disabled"
    if kind not in INCIDENT_KINDS:
        LOGGER.error("refusing to queue an incident alert of unknown kind %r", kind)
        return "rejected"

    camera = session.get(Camera, incident.camera_id) if incident.camera_id else None
    intent = intent_for_incident(incident, camera=camera, event=event, kind=kind)
    intent.evidence_keys = evidence_keys_for(session, incident.id)
    intent.payload["evidence_keys"] = intent.evidence_keys
    return enqueue_or_spool(settings, session, intent)
