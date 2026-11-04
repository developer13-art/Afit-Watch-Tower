"""Live-view delivery (proposal section 9).

Browsers do not play RTSP, so the ingestion worker's newest decoded frame is relayed to
authorized viewers as an HTTP multipart stream. Two properties from section 9 are enforced
here:

  * the raw RTSP URL and the camera password never reach the browser - the client only ever
    sees a server-issued live-session token and JPEG bytes;
  * several viewers of the same camera attach to one managed source stream instead of each
    opening their own RTSP connection.

WebRTC is the preferred interactive transport for the deployment (see
`docs/media-gateway.md`); this relay is the transport that works without extra infrastructure
and it shares the same session-authorization path.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import asdict

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..deps import (
    Container,
    LiveViewSession,
    current_principal,
    get_container,
    get_db,
)
from ...ingest.supervisor import StreamCapacityError
from ...models import Camera, CameraStatus
from ...security.audit import record as audit_record
from ...security.rbac import Principal, can_view_camera
from ...security.secrets import client_safe
from ...services.cameras import CameraService, CameraServiceError

router = APIRouter(prefix="/api/live", tags=["live"])
BOUNDARY = "watchtower-frame"


class SessionRequest(BaseModel):
    camera_id: str


def _authorize_camera(session: Session, principal: Principal, camera_id: str, permission: str) -> Camera:
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


def _session_or_404(container: Container, token: str) -> LiveViewSession:
    live = container.live_sessions.get(token)
    if live is None or live.released:
        raise HTTPException(
            status.HTTP_410_GONE, detail="This live viewing session has been released."
        )
    return live


@router.post("/sessions", status_code=status.HTTP_201_CREATED)
def open_live_session(
    payload: SessionRequest,
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> dict:
    """Steps 1-5 of the section 9 workflow: select, request, authorize, reuse-or-start, deliver."""
    camera = _authorize_camera(session, principal, payload.camera_id, "camera.view_live")

    if camera.status == CameraStatus.DISABLED.value:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "camera_disabled", "message": "This camera is disabled."},
        )
    if camera.status == CameraStatus.PENDING_SETUP.value and camera.desired_state != "running":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={
                "code": "not_activated",
                "message": (
                    "This camera has not been activated. A verified connection test must "
                    "pass and an operator must confirm registration before a live feed "
                    "exists."
                ),
            },
        )

    # Reuse the managed stream when one already exists (section 9).
    if container.supervisor.stats(str(camera.id)) is None:
        service = CameraService(session, container.settings, container.secret_store, container.supervisor)
        try:
            spec = service.spec_for(camera)
        except CameraServiceError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": exc.code, "message": client_safe(exc.message)},
            ) from exc
        try:
            container.supervisor.ensure(str(camera.id), spec)
        except StreamCapacityError as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                detail={"code": "stream_capacity", "message": str(exc)},
            ) from exc

    token = uuid.uuid4().hex
    now = time.time()
    container.live_sessions[token] = LiveViewSession(
        camera_id=str(camera.id),
        user_id=principal.user_id,
        token=token,
        started_at=now,
        last_seen=now,
    )
    audit_record(
        session,
        principal=principal,
        action="camera.live_view.start",
        object_type="camera",
        object_id=str(camera.id),
        details={"live_session": token, "camera_code": camera.code},
        source_ip=request.client.host if request.client else None,
    )
    return {
        "live_session": token,
        "camera_id": str(camera.id),
        "status": camera.status,
        "transport": "multipart-jpeg-relay",
    }


@router.get("/sessions/{token}/mjpeg")
async def stream_mjpeg(
    token: str,
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> Response:
    live = _session_or_404(container, token)
    if live.user_id != principal.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="This session belongs to another user.")
    container.supervisor.attach_viewer(live.camera_id)

    async def frames():
        last_timestamp = 0.0
        try:
            while True:
                if await request.is_disconnected():
                    break
                delivered = container.supervisor.latest_frame(live.camera_id)
                if delivered is None or delivered[0] == last_timestamp:
                    await asyncio.sleep(0.08)
                    continue
                last_timestamp, payload, fps = delivered
                live.last_seen = time.time()
                yield (
                    f"--{BOUNDARY}\r\n"
                    f"Content-Type: image/jpeg\r\n"
                    f"Content-Length: {len(payload)}\r\n"
                    f"X-Measured-Fps: {fps:.2f}\r\n\r\n"
                ).encode() + payload + b"\r\n"
        finally:
            container.supervisor.detach_viewer(live.camera_id)

    return StreamingResponse(
        frames(),
        media_type=f"multipart/x-mixed-replace; boundary={BOUNDARY}",
        headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY"},
    )


@router.get("/sessions/{token}/snapshot")
def snapshot(
    token: str,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> Response:
    live = _session_or_404(container, token)
    if live.user_id != principal.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="This session belongs to another user.")
    delivered = container.supervisor.latest_frame(live.camera_id)
    if delivered is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={"code": "no_frame", "message": "No video frame has arrived for this camera yet."},
        )
    return Response(
        content=delivered[1],
        media_type="image/jpeg",
        headers={"Cache-Control": "no-store"},
    )


@router.get("/sessions/{token}/state")
def session_state(
    token: str,
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> dict:
    """Drives the loading / live / reconnecting / offline states in section 9 step 7."""
    live = _session_or_404(container, token)
    if live.user_id != principal.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="This session belongs to another user.")
    stats = container.supervisor.stats(live.camera_id)
    if stats is None:
        return {"view_state": "offline", "detail": "no managed stream session", "session": None}
    view_state = {
        "starting": "loading",
        "connecting": "loading",
        "online": "live",
        "reconnecting": "reconnecting",
        "failed": "offline",
        "stopped": "offline",
    }.get(stats.state, "loading")
    payload = asdict(stats)
    payload.pop("last_error", None)
    return {
        "view_state": view_state,
        "detail": client_safe(stats.last_error or stats.state),
        "session": payload,
        "seconds_since_frame": round(time.time() - stats.last_frame_at, 1) if stats.last_frame_at else None,
    }


@router.delete("/sessions/{token}")
def release_session(
    token: str,
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> dict:
    """Section 9 step 8: when the viewer closes the player the session is released."""
    live = container.live_sessions.get(token)
    if live is None:
        return {"status": "already_released"}
    if live.user_id != principal.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="This session belongs to another user.")
    live.released = True
    container.supervisor.detach_viewer(live.camera_id)
    container.live_sessions.pop(token, None)
    audit_record(
        session,
        principal=principal,
        action="camera.live_view.stop",
        object_type="camera",
        object_id=live.camera_id,
        details={"live_session": token, "watched_seconds": round(time.time() - live.started_at)},
        source_ip=request.client.host if request.client else None,
    )
    return {"status": "released"}
