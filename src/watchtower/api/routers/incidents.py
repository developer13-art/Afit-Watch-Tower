"""Candidate-event queue, incident workflow and evidence access (sections 12 and 13)."""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..deps import Container, current_principal, get_container, get_db, require_permission
from ...models import (
    Camera,
    DetectionEvent,
    EvidenceAsset,
    Incident,
)
from ...security.audit import record as audit_record
from ...security.rbac import Principal, can_view_camera
from ...security.secrets import client_safe
from ...services.evidence import EvidenceError, EvidenceStore
from ...services.incidents import IncidentFilters, IncidentService, IncidentServiceError
from ...services.notifications import NotificationService

router = APIRouter(prefix="/api", tags=["incidents"])


class ReviewRequest(BaseModel):
    decision: str = Field(pattern="^(acknowledge|dismiss|escalate)$")
    note: str | None = Field(default=None, max_length=2000)


class IncidentCreate(BaseModel):
    title: str = Field(min_length=5, max_length=256)
    category: str = Field(min_length=2, max_length=64)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    summary: str | None = None
    camera_id: uuid.UUID | None = None
    campus_location: str | None = None
    occurred_at: dt.datetime | None = None


class AssignRequest(BaseModel):
    assignee_id: int


class EscalateRequest(BaseModel):
    to_user_id: int
    note: str | None = None


class NoteRequest(BaseModel):
    text: str = Field(min_length=1, max_length=4000)


class ResolveRequest(BaseModel):
    outcome: str = Field(min_length=2, max_length=64)
    resolution: str = Field(min_length=2, max_length=4000)
    false_positive: bool = False


class ReopenRequest(BaseModel):
    # Reopening changes state, so it is a POST body rather than a query on a GET: a crawler,
    # a prefetch or an <img> tag must not be able to reopen an incident.
    reason: str = Field(min_length=3, max_length=2000)


def _services(
    session: Session, container: Container
) -> tuple[IncidentService, EvidenceStore, NotificationService]:
    notifications = NotificationService(session, webhook_url=container.settings.webhook_url)
    evidence = EvidenceStore(container.settings, session)
    return (
        IncidentService(session, notifications, evidence, container.settings),
        evidence,
        notifications,
    )


def _raise(err: IncidentServiceError) -> None:
    code = err.code
    http = {
        "not_found": status.HTTP_404_NOT_FOUND,
        "forbidden": status.HTTP_403_FORBIDDEN,
        "not_resolved": status.HTTP_409_CONFLICT,
    }.get(code, status.HTTP_400_BAD_REQUEST)
    raise HTTPException(http, detail={"code": code, "message": client_safe(err.message)})


def _event_view(event: DetectionEvent, camera: Camera | None) -> dict:
    return {
        "id": event.id,
        "camera_id": str(event.camera_id),
        "camera_code": camera.code if camera else None,
        "camera_name": camera.display_name if camera else None,
        "campus_location": camera.campus_location if camera else None,
        "category": event.category,
        "confidence": round(event.confidence, 3),
        "occurred_at": event.occurred_at.isoformat(),
        "status": event.status,
        "suppressed": event.suppressed,
        "metadata": event.event_metadata,
        "reviewed_at": event.reviewed_at.isoformat() if event.reviewed_at else None,
        "review_note": event.review_note,
    }


def _incident_view(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "reference": incident.reference,
        "title": incident.title,
        "summary": incident.summary,
        "category": incident.category,
        "severity": incident.severity,
        "status": incident.status,
        "camera_id": str(incident.camera_id) if incident.camera_id else None,
        "campus_location": incident.campus_location,
        "occurred_at": incident.occurred_at.isoformat(),
        "created_at": incident.created_at.isoformat(),
        "assigned_to": incident.assigned_to,
        "escalated_to": incident.escalated_to,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "resolution": incident.resolution,
        "outcome": incident.outcome,
        "origin_event_id": incident.origin_event_id,
        "actions": [
            {
                "id": action.id,
                "action": action.action,
                "note": action.note,
                "actor_id": action.actor_id,
                "created_at": action.created_at.isoformat(),
            }
            for action in incident.actions
        ],
        "evidence": [
            {
                "id": asset.id,
                "kind": asset.kind,
                "content_type": asset.content_type,
                "byte_size": asset.byte_size,
                "captured_at": asset.captured_at.isoformat(),
                "sha256": asset.sha256,
                "expires_at": asset.expires_at.isoformat() if asset.expires_at else None,
            }
            for asset in incident.evidence
            if asset.deleted_at is None
        ],
    }


# --------------------------------------------------------------------------- #
# Candidate events
# --------------------------------------------------------------------------- #


@router.get("/events")
def list_events(
    only_new: bool = True,
    limit: int = Query(default=100, le=500),
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("event.view")),
) -> dict:
    incidents, _, _ = _services(session, container)
    events = incidents.pending_events(principal, only_new=only_new)[:limit]
    return {
        "events": [
            _event_view(event, session.get(Camera, event.camera_id)) for event in events
        ]
    }


@router.post("/events/{event_id}/review")
def review_event(
    event_id: int,
    payload: ReviewRequest,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("event.review")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        event, incident = incidents.review_event(
            event_id, principal, decision=payload.decision, note=payload.note
        )
    except IncidentServiceError as err:
        _raise(err)
    return {
        "event": _event_view(event, session.get(Camera, event.camera_id)),
        "incident": _incident_view(incident) if incident else None,
    }


# --------------------------------------------------------------------------- #
# Incidents
# --------------------------------------------------------------------------- #


@router.get("/incidents")
def list_incidents(
    status_filter: str | None = Query(default=None, alias="status"),
    category: str | None = None,
    severity: str | None = None,
    camera_id: uuid.UUID | None = None,
    campus_location: str | None = None,
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    query: str | None = None,
    assigned_to: int | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.view")),
) -> dict:
    incidents, _, _ = _services(session, container)
    filters = IncidentFilters(
        status=status_filter,
        category=category,
        severity=severity,
        camera_id=camera_id,
        campus_location=campus_location,
        since=since,
        until=until,
        query=query,
        assigned_to=assigned_to,
        limit=limit,
        offset=offset,
    )
    found = incidents.list(principal, filters)
    return {"incidents": [_incident_view(incident) for incident in found], "counts": incidents.summary_counts(principal, filters)}


@router.post("/incidents", status_code=status.HTTP_201_CREATED)
def create_incident(
    payload: IncidentCreate,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.create")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.create_manual(
            principal,
            title=payload.title,
            category=payload.category,
            severity=payload.severity,
            summary=payload.summary,
            camera_id=payload.camera_id,
            campus_location=payload.campus_location,
            occurred_at=payload.occurred_at,
        )
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: int,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.view")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.get_visible(incident_id, principal)
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


@router.post("/incidents/{incident_id}/assign")
def assign_incident(
    incident_id: int,
    payload: AssignRequest,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.assign")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.assign(incident_id, principal, assignee_id=payload.assignee_id)
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


@router.post("/incidents/{incident_id}/escalate")
def escalate_incident(
    incident_id: int,
    payload: EscalateRequest,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.escalate")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.escalate(
            incident_id, principal, to_user_id=payload.to_user_id, note=payload.note
        )
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


@router.post("/incidents/{incident_id}/notes")
def add_note(
    incident_id: int,
    payload: NoteRequest,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.view")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.note(incident_id, principal, text=payload.text)
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


@router.post("/incidents/{incident_id}/resolve")
def resolve_incident(
    incident_id: int,
    payload: ResolveRequest,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.resolve")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.resolve(
            incident_id,
            principal,
            outcome=payload.outcome,
            resolution=payload.resolution,
            false_positive=payload.false_positive,
        )
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


@router.post("/incidents/{incident_id}/reopen")
def reopen_incident(
    incident_id: int,
    payload: ReopenRequest,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("incident.resolve")),
) -> dict:
    incidents, _, _ = _services(session, container)
    try:
        incident = incidents.reopen(incident_id, principal, reason=payload.reason)
    except IncidentServiceError as err:
        _raise(err)
    return {"incident": _incident_view(incident)}


# --------------------------------------------------------------------------- #
# Evidence (section 12: access, export and deletion are audited)
# --------------------------------------------------------------------------- #


@router.get("/evidence/{asset_id}")
def download_evidence(
    asset_id: int,
    request: Request,
    export: bool = Query(default=False),
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> Response:
    asset = session.get(EvidenceAsset, asset_id)
    if asset is None or asset.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such evidence asset.")
    permission = "evidence.export" if export else "evidence.view"
    if not principal.allows(permission):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": f"Missing permission {permission}."},
        )
    # Section 14 scopes reviewers to camera groups, so the group check applies with or without an incident.
    if asset.camera_id is not None:
        camera = session.get(Camera, asset.camera_id)
        if camera is not None and not can_view_camera(principal, permission, camera):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"code": "forbidden", "message": "This camera is outside your scope."},
            )
    if asset.incident_id is not None:
        incidents, _, _ = _services(session, container)
        try:
            incidents.get_visible(asset.incident_id, principal)
        except IncidentServiceError as err:
            _raise(err)

    _, evidence, _ = _services(session, container)
    try:
        data = evidence.read(asset)
    except EvidenceError as exc:
        audit_record(
            session,
            principal=principal,
            action="evidence.export" if export else "evidence.view",
            object_type="evidence",
            object_id=str(asset.id),
            details={"error": client_safe(str(exc))},
            outcome="failure",
        )
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"code": "evidence_unreadable", "message": client_safe(str(exc))},
        ) from exc

    audit_record(
        session,
        principal=principal,
        action="evidence.export" if export else "evidence.view",
        object_type="evidence",
        object_id=str(asset.id),
        details={"sha256": asset.sha256, "bytes": asset.byte_size, "camera_id": str(asset.camera_id)},
        source_ip=request.client.host if request.client else None,
    )
    headers = {
        "Content-Disposition": f'{"attachment" if export else "inline"}; filename="{asset.filename}"',
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
    }
    return Response(content=data, media_type=asset.content_type, headers=headers)
