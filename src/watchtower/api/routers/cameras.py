"""Camera registration, testing, activation and health endpoints (sections 6, 7, 10)."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..deps import Container, get_container, get_db, require_permission
from ...ingest.supervisor import StreamCapacityError
from ...models import Camera, CameraHealthEvent, CameraStatus, MonitoringPolicy
from ...security.rbac import Principal, can_view_camera
from ...security.secrets import client_safe
from ...services.cameras import CameraService, CameraServiceError, build_draft

router = APIRouter(prefix="/api/cameras", tags=["cameras"])


class RegistrationPayload(BaseModel):
    """Either registration method from section 6.1, discriminated by `method`."""

    method: Literal["rtsp_string", "structured"]
    display_name: str = Field(min_length=2, max_length=128)
    code: str = Field(min_length=2, max_length=64)
    campus_location: str = Field(min_length=1, max_length=256)
    camera_group_id: int | None = None
    model: str | None = None
    description: str | None = None
    monitoring_policy_id: int | None = None
    recording_policy: dict[str, Any] = Field(default_factory=dict)
    verified_in_vlc: bool = False

    # Method A
    rtsp_url: str | None = None

    # Method B
    host: str | None = None
    port: int | str | None = None
    stream_path: str | None = None
    username: str | None = None
    password: str | None = Field(default=None, max_length=256)
    transport: str = "tcp"


class ProbeView(BaseModel):
    result: str
    message: str
    frames_decoded: int
    measured_fps: float
    width: int
    height: int
    elapsed_seconds: float

    @classmethod
    def from_outcome(cls, outcome: Any) -> ProbeView:
        return cls(
            result=outcome.result.value,
            message=client_safe(outcome.message),
            frames_decoded=outcome.frames_decoded,
            measured_fps=outcome.measured_fps,
            width=outcome.width,
            height=outcome.height,
            elapsed_seconds=outcome.elapsed_seconds,
        )


class CameraView(BaseModel):
    id: str
    code: str
    display_name: str
    campus_location: str
    camera_group_id: int | None
    model: str | None
    description: str | None
    status: str
    desired_state: str
    is_registered: bool
    monitoring_policy_id: int | None
    last_successful_frame_at: str | None
    last_error_code: str | None
    host: str | None
    port: int | None
    stream_path: str | None
    username: str | None
    transport: str | None
    verified_in_vlc: bool
    has_secret: bool
    last_probe_result: str | None
    live_view_available: bool
    measured_fps: float
    viewers: int
    retry_count: int

    @classmethod
    def of(cls, camera: Camera, container: Container) -> CameraView:
        profile = camera.connection_profile
        stats = container.supervisor.stats(str(camera.id))
        return cls(
            id=str(camera.id),
            code=camera.code,
            display_name=camera.display_name,
            campus_location=camera.campus_location,
            camera_group_id=camera.camera_group_id,
            model=camera.model,
            description=camera.description,
            status=camera.status,
            desired_state=camera.desired_state,
            is_registered=camera.is_registered,
            monitoring_policy_id=camera.monitoring_policy_id,
            last_successful_frame_at=(
                camera.last_successful_frame_at.isoformat()
                if camera.last_successful_frame_at
                else None
            ),
            last_error_code=camera.last_error_code,
            host=profile.host if profile else None,
            port=profile.port if profile else None,
            stream_path=profile.stream_path if profile else None,
            username=profile.username if profile else None,
            transport=profile.transport if profile else None,
            verified_in_vlc=bool(profile.verified_in_vlc) if profile else False,
            # A boolean only - the credential itself never leaves the backend (section 8.3).
            has_secret=bool(profile.secret_reference) if profile else False,
            last_probe_result=profile.last_probe_result if profile else None,
            live_view_available=stats is not None and stats.state not in ("failed", "stopped"),
            measured_fps=stats.measured_fps if stats else 0.0,
            viewers=stats.viewers if stats else 0,
            retry_count=stats.retry_count if stats else 0,
        )


def _service(
    session: Session = Depends(get_db), container: Container = Depends(get_container)
) -> CameraService:
    return CameraService(session, container.settings, container.secret_store, container.supervisor)


def _camera_or_403(
    camera_id: str, principal: Principal, session: Session, permission: str
) -> Camera:
    try:
        parsed = uuid.UUID(camera_id)
    except ValueError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such camera.") from exc
    camera = session.get(Camera, parsed)
    if camera is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such camera.")
    if not can_view_camera(principal, permission, camera):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "forbidden", "message": "This camera is outside your scope."},
        )
    return camera


def _raise(err: CameraServiceError) -> None:
    code = err.code
    http = status.HTTP_400_BAD_REQUEST
    if code == "not_found":
        http = status.HTTP_404_NOT_FOUND
    elif code in {"secret_unavailable", "test_not_passed", "test_required"} or code in {"duplicate_code"}:
        http = status.HTTP_409_CONFLICT
    elif code in {"stream_capacity"}:
        http = status.HTTP_503_SERVICE_UNAVAILABLE
    raise HTTPException(
        http,
        detail={
            "code": code,
            "message": client_safe(err.message),
            "field": getattr(err, "field", None),
        },
    )


@router.get("", response_model=list[CameraView])
def list_cameras(
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.list")),
) -> list[CameraView]:
    service = _service(session, container)
    return [CameraView.of(camera, container) for camera in service.list_visible(principal)]


@router.get("/groups")
def list_groups(
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("camera.list")),
) -> list[dict]:
    from ...models import CameraGroup

    return [
        {"id": group.id, "code": group.code, "name": group.name}
        for group in session.scalars(select(CameraGroup).order_by(CameraGroup.code)).all()
    ]


@router.get("/policies")
def list_policies(
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("camera.list")),
) -> list[dict]:
    return [
        {
            "id": policy.id,
            "code": policy.code,
            "name": policy.name,
            "enabled": policy.enabled,
            "detector_codes": policy.detector_codes,
            "severity": policy.severity,
        }
        for policy in session.scalars(select(MonitoringPolicy).order_by(MonitoringPolicy.code)).all()
    ]


@router.post("/test-draft", response_model=ProbeView)
def test_draft(
    payload: RegistrationPayload,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.configure")),
) -> ProbeView:
    """Verify a connection before anything is written, so the operator sees the failure
    reason from section 6.5 without creating a broken camera record."""
    service = _service(session, container)
    try:
        outcome = service.test_draft(payload.model_dump())
    except StreamCapacityError as exc:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "code": "stream_capacity",
                "message": client_safe(str(exc)),
            },
        ) from exc
    except CameraServiceError as err:
        _raise(err)
    return ProbeView.from_outcome(outcome)


@router.post("", response_model=dict, status_code=status.HTTP_201_CREATED)
def register_camera(
    payload: RegistrationPayload,
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.register")),
) -> dict:
    service = _service(session, container)
    try:
        draft = build_draft(payload.model_dump())
        camera, outcome = service.register(draft, principal)
    except CameraServiceError as err:
        _raise(err)
    return {
        "camera": CameraView.of(camera, container).model_dump(),
        "connection_test": ProbeView.from_outcome(outcome).model_dump() if outcome else None,
        "activatable": bool(outcome and outcome.success),
        "message": (
            "Connection verified. Confirm registration to start the managed live stream."
            if outcome and outcome.success
            else "The camera record was created as pending, but the connection test did not "
            "pass, so it has not been activated."
        ),
    }


@router.get("/{camera_id}", response_model=CameraView)
def get_camera(
    camera_id: str,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.list")),
) -> CameraView:
    camera = _camera_or_403(camera_id, principal, session, "camera.list")
    return CameraView.of(camera, container)


@router.post("/{camera_id}/test", response_model=ProbeView)
def test_camera(
    camera_id: str,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.configure")),
) -> ProbeView:
    camera = _camera_or_403(camera_id, principal, session, "camera.configure")
    service = _service(session, container)
    try:
        outcome = service.run_connection_test(camera, principal)
    except CameraServiceError as err:
        _raise(err)
    return ProbeView.from_outcome(outcome)


@router.post("/{camera_id}/activate", response_model=CameraView)
def activate_camera(
    camera_id: str,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.configure")),
) -> CameraView:
    camera = _camera_or_403(camera_id, principal, session, "camera.configure")
    service = _service(session, container)
    try:
        camera = service.activate(camera.id, principal)
    except CameraServiceError as err:
        if err.code == "stream_capacity":
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": err.code, "message": client_safe(err.message)},
            ) from err
        _raise(err)
    return CameraView.of(camera, container)


@router.post("/{camera_id}/disable", response_model=CameraView)
def disable_camera(
    camera_id: str,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.disable")),
) -> CameraView:
    camera = _camera_or_403(camera_id, principal, session, "camera.disable")
    service = _service(session, container)
    return CameraView.of(service.disable(camera.id, principal), container)


@router.patch("/{camera_id}", response_model=dict)
def update_camera(
    camera_id: str,
    payload: dict[str, Any],
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.configure")),
) -> dict:
    camera = _camera_or_403(camera_id, principal, session, "camera.configure")
    service = _service(session, container)
    try:
        camera, outcome = service.update(camera.id, payload, principal)
    except CameraServiceError as err:
        _raise(err)
    return {
        "camera": CameraView.of(camera, container).model_dump(),
        "connection_test": ProbeView.from_outcome(outcome).model_dump() if outcome else None,
    }


@router.post("/{camera_id}/refresh", response_model=dict)
def refresh_health(
    camera_id: str,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.list")),
) -> dict:
    """Poll the managed session now and persist any state transition."""
    camera = _camera_or_403(camera_id, principal, session, "camera.list")
    service = _service(session, container)
    previous_status = camera.status
    assessment = service.sync_stream_state(camera)
    return {
        "status": assessment.status.value,
        "reason": assessment.reason_code,
        "detail": client_safe(assessment.detail),
        "changed": assessment.status.value != previous_status,
        "seconds_since_frame": assessment.seconds_since_frame,
    }


@router.get("/{camera_id}/health", response_model=list[dict])
def health_history(
    camera_id: str,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("health.view")),
    limit: int = 50,
) -> list[dict]:
    camera = _camera_or_403(camera_id, principal, session, "health.view")
    events = session.scalars(
        select(CameraHealthEvent)
        .where(CameraHealthEvent.camera_id == camera.id)
        .order_by(CameraHealthEvent.observed_at.desc())
        .limit(min(limit, 500))
    ).all()
    return [
        {
            "observed_at": event.observed_at.isoformat(),
            "from": event.previous_status,
            "to": event.status,
            "reason": event.reason_code,
            "detail": client_safe(event.detail or ""),
            "duration_seconds": event.duration_seconds,
        }
        for event in events
    ]


@router.get("/summary/overview", response_model=dict)
def overview(
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("camera.list")),
) -> dict:
    """The Overview Dashboard counters from section 13."""
    from ...models import DetectionEvent, Incident, IncidentStatus

    service = _service(session, container)
    cameras = service.list_visible(principal)
    counts = {state.value: 0 for state in CameraStatus}
    for camera in cameras:
        counts[camera.status] = counts.get(camera.status, 0) + 1

    return {
        "registered_cameras": sum(1 for camera in cameras if camera.is_registered),
        "total_cameras": len(cameras),
        "online": counts.get(CameraStatus.ONLINE.value, 0),
        "offline": counts.get(CameraStatus.OFFLINE.value, 0),
        "degraded": counts.get(CameraStatus.DEGRADED.value, 0),
        "reconnecting": counts.get(CameraStatus.RECONNECTING.value, 0),
        "pending_setup": counts.get(CameraStatus.PENDING_SETUP.value, 0),
        "authentication_failed": counts.get(CameraStatus.AUTHENTICATION_FAILED.value, 0),
        "by_status": counts,
        "open_incidents": session.scalar(
            select(func.count(Incident.id)).where(
                Incident.status.in_(
                    [IncidentStatus.OPEN.value, IncidentStatus.INVESTIGATING.value, IncidentStatus.ASSIGNED.value]
                )
            )
        )
        or 0,
        "candidate_events": session.scalar(
            select(func.count(DetectionEvent.id)).where(
                DetectionEvent.status == "new", DetectionEvent.suppressed.is_(False)
            )
        )
        or 0,
        "managed_sessions": len(container.supervisor.snapshot_all()),
    }
