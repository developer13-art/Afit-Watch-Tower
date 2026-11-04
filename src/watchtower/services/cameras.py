"""Camera registration, testing and activation (proposal sections 6.2, 6.3, 6.5, 6.6, 7).

The sequence here deliberately mirrors section 6.2's numbered steps. Two properties are
load-bearing:

  * A camera is never marked online because a form was submitted. Activation starts a
    managed session; `Online` arrives only when the health layer confirms frames.
  * Credentials are sealed into `camera_secrets` and are never written to the camera row,
    a log line, an error message or an API response.
"""

from __future__ import annotations

import datetime as dt
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..config import Settings
from ..health import evaluator
from ..ingest.supervisor import StreamCapacityError, StreamSupervisor
from ..models import (
    Camera,
    CameraConnectionProfile,
    CameraGroup,
    CameraHealthEvent,
    CameraSecret,
    CameraStatus,
    CameraStreamSession,
    MonitoringPolicy,
    ProbeResult,
)
from ..rtsp import probe as rtsp_probe
from ..rtsp.parser import ConnectionSpec, RTSPSpecError, build_spec, parse_connection_string
from ..security.audit import record as audit_record
from ..security.rbac import Principal
from ..security.secrets import SecretStore, fingerprint, redact

CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,63}$")


class CameraServiceError(Exception):
    """Carries a machine-readable code plus a safe, credential-free message."""

    def __init__(self, code: str, message: str, *, field_name: str | None = None) -> None:
        super().__init__(redact(message))
        self.code = code
        self.message = redact(message)
        self.field = field_name


@dataclass(slots=True)
class CameraDraft:
    """Everything section 6.2/6.3 asks the operator to supply."""

    display_name: str
    code: str
    campus_location: str
    connection: ConnectionSpec
    method: Literal["rtsp_string", "structured"]
    camera_group_id: int | None = None
    model: str | None = None
    description: str | None = None
    monitoring_policy_id: int | None = None
    recording_policy: dict[str, Any] = field(default_factory=dict)
    verified_in_vlc: bool = False


def build_draft(payload: dict[str, Any]) -> CameraDraft:
    """Accept either registration method and converge on one validated spec (section 6.1)."""
    method = (payload.get("method") or "").strip()
    raw_code = str(payload.get("code", "")).strip()
    if not CODE_RE.match(raw_code):
        raise CameraServiceError(
            "invalid_camera_code",
            "Camera Code must be 2-64 characters using letters, digits, dot, underscore "
            "or hyphen, for example AFIT-GATE-001.",
            field_name="code",
        )

    try:
        if method == "rtsp_string":
            connection = parse_connection_string(str(payload.get("rtsp_url", "")))
        elif method == "structured":
            connection = build_spec(
                host=str(payload.get("host", "")),
                port=payload.get("port"),
                stream_path=str(payload.get("stream_path", "")),
                username=payload.get("username"),
                password=payload.get("password"),
                transport=str(payload.get("transport", "tcp")),
            )
        else:
            raise CameraServiceError(
                "unknown_method",
                "Choose the RTSP connection-string method or the structured form.",
                field_name="method",
            )
    except RTSPSpecError as exc:
        raise CameraServiceError("invalid_connection", exc.message, field_name=exc.field) from exc

    display_name = str(payload.get("display_name", "")).strip()
    location = str(payload.get("campus_location", "")).strip()
    if len(display_name) < 2:
        raise CameraServiceError(
            "invalid_name", "Camera Name is required.", field_name="display_name"
        )
    if not location:
        raise CameraServiceError(
            "invalid_location", "Campus Location is required.", field_name="campus_location"
        )

    return CameraDraft(
        display_name=display_name,
        code=raw_code,
        campus_location=location,
        connection=connection,
        method=method,
        camera_group_id=payload.get("camera_group_id"),
        model=payload.get("model"),
        description=payload.get("description"),
        monitoring_policy_id=payload.get("monitoring_policy_id"),
        recording_policy=payload.get("recording_policy") or {},
        verified_in_vlc=bool(payload.get("verified_in_vlc")),
    )


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


class CameraService:
    def __init__(
        self,
        session: Session,
        settings: Settings,
        secrets: SecretStore,
        supervisor: StreamSupervisor,
    ) -> None:
        self._session = session
        self._settings = settings
        self._secrets = secrets
        self._supervisor = supervisor

    # ------------------------------------------------------------------ #
    # Registration
    # ------------------------------------------------------------------ #

    def register(
        self, draft: CameraDraft, principal: Principal, *, run_test: bool = True
    ) -> tuple[Camera, rtsp_probe.ProbeOutcome | None]:
        """Steps 1-10 of section 6.2. Step 11 (activation) is a separate call."""
        if draft.camera_group_id is not None and self._session.get(
            CameraGroup, draft.camera_group_id
        ) is None:
            raise CameraServiceError(
                "unknown_group", "That camera group does not exist.", field_name="camera_group_id"
            )
        if draft.monitoring_policy_id is not None and self._session.get(
            MonitoringPolicy, draft.monitoring_policy_id
        ) is None:
            raise CameraServiceError(
                "unknown_policy",
                "That monitoring policy does not exist.",
                field_name="monitoring_policy_id",
            )

        if self._session.scalar(select(Camera.id).where(Camera.code == draft.code)) is not None:
            raise CameraServiceError(
                "duplicate_code",
                f"Camera Code {draft.code!r} is already registered.",
                field_name="code",
            )

        camera = Camera(
            id=uuid.uuid4(),
            code=draft.code,
            display_name=draft.display_name,
            campus_location=draft.campus_location,
            camera_group_id=draft.camera_group_id,
            model=draft.model,
            description=draft.description,
            monitoring_policy_id=draft.monitoring_policy_id,
            recording_policy=draft.recording_policy,
            status=CameraStatus.PENDING_SETUP.value,
            desired_state="stopped",
            is_registered=False,
            created_by=principal.user_id,
            modified_by=principal.user_id,
        )
        camera.connection_profile = self._profile_from(draft)
        self._session.add(camera)
        try:
            self._session.flush()
        except IntegrityError as exc:
            self._session.rollback()
            raise CameraServiceError("duplicate_code", f"Camera Code {draft.code!r} already exists.") from exc

        audit_record(
            self._session,
            principal=principal,
            action="camera.register",
            object_type="camera",
            object_id=str(camera.id),
            details={
                "code": camera.code,
                "method": draft.method,
                "connection": draft.connection.non_secret_dict(),
                "network_review": draft.connection.requires_network_review,
            },
        )

        outcome = self.run_connection_test(camera, principal) if run_test else None
        return camera, outcome

    def _profile_from(self, draft: CameraDraft) -> CameraConnectionProfile:
        profile = CameraConnectionProfile(
            host=draft.connection.host,
            port=draft.connection.port,
            stream_path=draft.connection.path,
            username=draft.connection.username,
            transport=draft.connection.transport,
            verified_in_vlc=draft.verified_in_vlc,
        )
        if draft.connection.password:
            profile.secret_reference = self._seal_new_secret(draft.connection.password)
        return profile

    def _seal_new_secret(self, plaintext: str) -> str:
        sealed = self._secrets.seal(plaintext)
        self._session.add(
            CameraSecret(
                reference=sealed.reference,
                ciphertext=sealed.ciphertext,
                key_id=sealed.key_id,
            )
        )
        self._session.flush()
        return sealed.reference

    # ------------------------------------------------------------------ #
    # Connection testing (section 6.5)
    # ------------------------------------------------------------------ #

    def run_connection_test(
        self, camera: Camera, principal: Principal | None = None
    ) -> rtsp_probe.ProbeOutcome:
        spec = self.spec_for(camera)
        profile = camera.connection_profile

        # Section 6.5 lists `testing` as a result the operator should be able to see. A probe
        # blocks for up to `probe_timeout_seconds`, so the in-progress state is committed
        # before it starts; otherwise a dashboard polling this camera would show the previous
        # test's verdict while a new one is running, and the state would be unreachable.
        profile.last_probe_result = ProbeResult.TESTING.value
        profile.last_probe_at = _utcnow()
        self._session.commit()

        with self._supervisor.acquire_test_slot():
            outcome = rtsp_probe.run_probe(
                spec,
                timeout=self._settings.probe_timeout_seconds,
                frame_count=self._settings.probe_frame_count,
                sustain_seconds=self._settings.probe_sustain_seconds,
            )
        camera.connection_profile.last_probe_result = outcome.result.value
        camera.connection_profile.last_probe_at = _utcnow()
        camera.last_error_code = None if outcome.success else outcome.result.value
        self._session.flush()

        if camera.status in (CameraStatus.PENDING_SETUP.value, CameraStatus.TESTING.value):
            camera.status = (
                CameraStatus.PENDING_SETUP.value
                if outcome.success
                else CameraStatus.OFFLINE.value
            )
        audit_record(
            self._session,
            principal=principal,
            action="camera.connection_test",
            object_type="camera",
            object_id=str(camera.id),
            details={
                "result": outcome.result.value,
                "stage": outcome.stage,
                "frames_decoded": outcome.frames_decoded,
                "resolution": f"{outcome.width}x{outcome.height}" if outcome.width else None,
                "message": outcome.message,
            },
            outcome="success" if outcome.success else "failure",
        )
        return outcome

    def test_draft(self, payload: dict[str, Any]) -> rtsp_probe.ProbeOutcome:
        """Test a connection before anything is written, for the wizard's Test button.

        The test-slot ceiling is applied here rather than in the router so that every probe
        path is bounded by `WATCHTOWER_MAX_CONNECTION_TESTS`, not only the saved-camera one.
        """
        draft = build_draft(payload)
        with self._supervisor.acquire_test_slot():
            return rtsp_probe.run_probe(
                draft.connection,
                timeout=self._settings.probe_timeout_seconds,
                frame_count=self._settings.probe_frame_count,
                sustain_seconds=self._settings.probe_sustain_seconds,
            )

    def spec_for(self, camera: Camera) -> ConnectionSpec:
        """Reassemble the connection spec, sealing the password only in-process."""
        profile = camera.connection_profile
        if profile is None:
            raise CameraServiceError("no_profile", f"{camera.code} has no connection profile.")
        password = self._secrets.reveal(profile.secret) if profile.secret_reference else None
        if profile.secret_reference and password is None:
            raise CameraServiceError(
                "secret_unavailable",
                "The stored camera credential cannot be decrypted; re-enter the password "
                "or restore the matching key ring.",
            )
        return build_spec(
            host=profile.host,
            port=profile.port,
            stream_path=profile.stream_path,
            username=profile.username,
            password=password,
            transport=profile.transport,
        )

    # ------------------------------------------------------------------ #
    # Activation (section 6.6)
    # ------------------------------------------------------------------ #

    def activate(self, camera_id: uuid.UUID, principal: Principal) -> Camera:
        camera = self.get(camera_id)
        profile = camera.connection_profile
        last_result = profile.last_probe_result if profile else None
        if last_result is None:
            raise CameraServiceError(
                "test_required",
                "Run a connection test before activating this camera.",
            )
        if last_result != ProbeResult.CONNECTED.value:
            raise CameraServiceError(
                "test_not_passed",
                f"The last connection test ended with {ProbeResult(last_result).value!r}. "
                "Correct the configuration and test again before activating.",
            )

        spec = self.spec_for(camera)
        try:
            self._supervisor.ensure(str(camera_id), spec)
        except StreamCapacityError as exc:
            # A full host is a retryable operational condition, not a crash: the router maps
            # this code to 503 so the operator is told to retire streams or raise the ceiling.
            raise CameraServiceError("stream_capacity", str(exc)) from exc
        camera.desired_state = "running"
        camera.is_registered = True
        if camera.status in (
            CameraStatus.PENDING_SETUP.value,
            CameraStatus.OFFLINE.value,
            CameraStatus.DISABLED.value,
        ):
            # The managed session has started but frames are not confirmed yet, so the
            # state is Testing rather than Online (section 6.6).
            camera.status = CameraStatus.TESTING.value
        camera.modified_by = principal.user_id
        self._session.add(
            CameraStreamSession(
                camera_id=camera.id,
                state="starting",
                started_at=_utcnow(),
            )
        )
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="camera.activate",
            object_type="camera",
            object_id=str(camera.id),
            details={"code": camera.code, "transport": spec.transport},
        )
        return camera

    def disable(self, camera_id: uuid.UUID, principal: Principal) -> Camera:
        """Stop the worker and release video resources, keep history (section 7)."""
        camera = self.get(camera_id)
        self._supervisor.stop(str(camera_id), reason="disabled")
        previous = CameraStatus(camera.status)
        camera.status = CameraStatus.DISABLED.value
        camera.desired_state = "stopped"
        camera.is_registered = True
        self._session.add(
            CameraHealthEvent(
                camera_id=camera.id,
                previous_status=previous.value,
                status=camera.status,
                reason_code="operator_disabled",
                detail="disabled from the dashboard",
            )
        )
        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="camera.disable",
            object_type="camera",
            object_id=str(camera.id),
            details={"code": camera.code},
        )
        return camera

    def update(
        self, camera_id: uuid.UUID, payload: dict[str, Any], principal: Principal
    ) -> tuple[Camera, rtsp_probe.ProbeOutcome | None]:
        """Edit configuration; a changed connection forces re-verification."""
        camera = self.get(camera_id)
        for attribute in ("display_name", "campus_location", "model", "description"):
            if attribute in payload and payload[attribute] is not None:
                setattr(camera, attribute, str(payload[attribute]).strip())
        if "camera_group_id" in payload:
            camera.camera_group_id = payload["camera_group_id"]
        if "monitoring_policy_id" in payload:
            camera.monitoring_policy_id = payload["monitoring_policy_id"]
        if "recording_policy" in payload:
            camera.recording_policy = payload["recording_policy"] or {}
        camera.modified_by = principal.user_id

        outcome: rtsp_probe.ProbeOutcome | None = None
        if payload.get("rtsp_url") or payload.get("host"):
            draft = build_draft(
                {
                    "method": "rtsp_string" if payload.get("rtsp_url") else "structured",
                    "code": camera.code,
                    "display_name": camera.display_name,
                    "campus_location": camera.campus_location,
                    "rtsp_url": payload.get("rtsp_url"),
                    "host": payload.get("host"),
                    "port": payload.get("port"),
                    "stream_path": payload.get("stream_path"),
                    "username": payload.get("username"),
                    "password": payload.get("password"),
                    "transport": payload.get("transport", "tcp"),
                    "verified_in_vlc": payload.get("verified_in_vlc", camera.connection_profile.verified_in_vlc),
                }
            )
            profile = camera.connection_profile
            if profile is None:
                camera.connection_profile = self._profile_from(draft)
            else:
                profile.host = draft.connection.host
                profile.port = draft.connection.port
                profile.stream_path = draft.connection.path
                profile.username = draft.connection.username
                profile.transport = draft.connection.transport
                profile.verified_in_vlc = draft.verified_in_vlc
                profile.last_probe_result = None
                if draft.connection.password:
                    if profile.secret is not None:
                        self._secrets.replace(profile.secret, draft.connection.password)
                        audit_record(
                            self._session,
                            principal=principal,
                            action="camera.secret.rotate",
                            object_type="camera",
                            object_id=str(camera.id),
                            details={"fingerprint": fingerprint(draft.connection.password)},
                        )
                    else:
                        profile.secret_reference = self._seal_new_secret(
                            draft.connection.password
                        )
            # Configuration changed, so the camera is no longer verified and must be
            # re-tested before it can be activated again.
            self._session.flush()
            camera.status = CameraStatus.PENDING_SETUP.value
            camera.desired_state = "stopped"
            self._supervisor.stop(str(camera_id), reason="reconfigured")
            outcome = self.run_connection_test(camera, principal)

        self._session.flush()
        audit_record(
            self._session,
            principal=principal,
            action="camera.update",
            object_type="camera",
            object_id=str(camera.id),
            details={"changed_fields": sorted(payload.keys()), "retest": outcome is not None},
        )
        return camera, outcome

    # ------------------------------------------------------------------ #
    # Queries
    # ------------------------------------------------------------------ #

    def get(self, camera_id: uuid.UUID | str) -> Camera:
        camera = self._session.get(Camera, uuid.UUID(str(camera_id)))
        if camera is None:
            raise CameraServiceError("not_found", "No such camera.")
        return camera

    def list_visible(self, principal: Principal) -> list[Camera]:
        from ..security.rbac import filter_cameras_by_permission

        cameras = self._session.scalars(select(Camera).order_by(Camera.code)).all()
        return filter_cameras_by_permission(principal, "camera.list", cameras)

    def sync_stream_state(self, camera: Camera) -> evaluator.HealthAssessment:
        """Poll the supervisor and persist any health transition (sections 7 and 10)."""
        stats = self._supervisor.stats(str(camera.id))
        assessment = evaluator.HealthEvaluator(self._settings).evaluate(camera, stats)
        evaluator.record_transition(self._session, camera, assessment)
        if stats is not None:
            camera.last_successful_frame_at = (
                dt.datetime.fromtimestamp(stats.last_frame_at, dt.UTC)
                if stats.last_frame_at
                else camera.last_successful_frame_at
            )
            open_session = self._session.scalar(
                select(CameraStreamSession)
                .where(
                    CameraStreamSession.camera_id == camera.id,
                    CameraStreamSession.terminal.is_(False),
                )
                .order_by(CameraStreamSession.id.desc())
            )
            if open_session is None and stats.state not in ("failed", "stopped"):
                open_session = CameraStreamSession(camera_id=camera.id, state=stats.state)
                self._session.add(open_session)
            if open_session is not None:
                open_session.state = stats.state
                open_session.pid = stats.pid
                open_session.frames_received = stats.frames_received
                open_session.frames_dropped = stats.frames_dropped
                open_session.decode_failures = stats.decode_failures
                open_session.retry_count = stats.retry_count
                open_session.viewer_count = stats.viewers
                open_session.measured_fps = stats.measured_fps
                open_session.last_frame_at = (
                    dt.datetime.fromtimestamp(stats.last_frame_at, dt.UTC)
                    if stats.last_frame_at
                    else None
                )
                if stats.state in ("failed", "stopped"):
                    open_session.terminal = True
                    open_session.termination_reason = stats.last_error or stats.state
        self._session.flush()
        return assessment
