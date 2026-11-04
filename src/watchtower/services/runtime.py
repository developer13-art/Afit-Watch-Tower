"""The supervision loop.

Section 17 keeps continuous video processing in dedicated services rather than a job queue,
but something still has to observe the managed sessions and turn telemetry into persisted
health state, alerts and analysis. That is this loop: it runs on its own thread inside the
application process for the prototype, and it is the component that separates onto its own
host when ingestion, media delivery and inference move onto dedicated servers.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from dataclasses import dataclass
from typing import Protocol

from sqlalchemy import select

from ..config import Settings
from ..db import session_scope
from ..health.evaluator import HealthEvaluator
from ..models import Camera, CameraStatus
from ..security.secrets import redact
from ..services.cameras import CameraService
from ..services.notifications import NotificationRequest, NotificationService

log = logging.getLogger("watchtower.runtime")

ACTIVE_STATES = {
    CameraStatus.ONLINE.value,
    CameraStatus.DEGRADED.value,
    CameraStatus.RECONNECTING.value,
    CameraStatus.TESTING.value,
    CameraStatus.AUTHENTICATION_FAILED.value,
    CameraStatus.OFFLINE.value,
}


class AnalysisRunner(Protocol):
    def run_enabled_cameras(self, session, cameras) -> list:
        ...


@dataclass(slots=True)
class LoopCounters:
    cycles: int = 0
    health_transitions: int = 0
    restarted_sessions: int = 0
    analysis_failures: int = 0
    last_cycle_seconds: float = 0.0
    last_cycle_at: float = 0.0


class SupervisionLoop:
    def __init__(
        self,
        settings: Settings,
        session_factory,
        supervisor,
        *,
        analysis: AnalysisRunner | None = None,
        interval_seconds: float = 2.0,
    ) -> None:
        self._settings = settings
        self._session_factory = session_factory
        self._supervisor = supervisor
        self._analysis = analysis
        self._interval = interval_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._evaluator = HealthEvaluator(settings)
        self.counters = LoopCounters()

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="supervision-loop", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=10)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self._interval):
            started = time.monotonic()
            try:
                self.cycle()
            except Exception as exc:  # noqa: BLE001 - pragma: no cover
                # A loop fault is logged and the next cycle runs; silence is the only failure.
                log.error("supervision cycle failed: %s", redact(str(exc)))
            self.counters.last_cycle_seconds = round(time.monotonic() - started, 3)
            self.counters.last_cycle_at = time.time()

    def cycle(self) -> dict[str, int]:
        """One pass: sync health, restart dropped sessions, run analysis.

        Each camera is handled independently so one bad row or one dead decoder cannot stop
        the rest of the estate from being monitored.
        """
        transitions = 0
        restarts = 0
        with session_scope(self._session_factory) as session:
            service = CameraService(
                session, self._settings, self._build_secret_store(), self._supervisor
            )
            notifications = NotificationService(session, webhook_url=self._settings.webhook_url)
            cameras = session.scalars(
                select(Camera).where(Camera.desired_state == "running")
            ).all()

            for camera in cameras:
                try:
                    previous = camera.status
                    assessment = service.sync_stream_state(camera)
                    if assessment.status.value != previous:
                        transitions += 1
                        self._notify_health(notifications, camera, assessment)
                    if self._should_restart(camera, assessment):
                        self._restart(service, camera)
                        restarts += 1
                except Exception as exc:  # noqa: BLE001 - per-camera isolation is the point
                    log.warning(
                        "health sync failed for %s: %s", camera.code, redact(str(exc))
                    )

            if self._analysis is not None:
                analysable = [
                    camera
                    for camera in cameras
                    if camera.monitoring_policy_id is not None
                    and camera.status in ACTIVE_STATES
                ]
                try:
                    self._analysis.run_enabled_cameras(session, analysable)
                except Exception as exc:  # noqa: BLE001 - one bad analysis pass must not end the loop
                    self.counters.analysis_failures += 1
                    log.error("analysis pass failed: %s", redact(str(exc)))

            session.commit()

        self.counters.cycles += 1
        self.counters.health_transitions += transitions
        self.counters.restarted_sessions += restarts
        return {"transitions": transitions, "restarts": restarts}

    def _build_secret_store(self):
        # The key ring is constructed once per process; re-reading it here keeps this loop
        # usable when it is started before the web container exists (tests, CLI).
        from ..security.secrets import KeyRing, SecretStore

        if not hasattr(self, "_secret_store"):
            self._secret_store = SecretStore(KeyRing(self._settings.secret_key_path, create_if_missing=True))
        return self._secret_store

    def _should_restart(self, camera: Camera, assessment) -> bool:
        """Restart only when the operator still wants the stream and none is running."""
        if self._supervisor.stats(str(camera.id)) is not None:
            return False
        if camera.desired_state != "running":
            return False
        grace = self._settings.reconnecting_grace_seconds
        last = camera.last_successful_frame_at
        if last is not None:
            age = (dt.datetime.now(dt.UTC) - last).total_seconds()
            if age < grace:
                return False
        return True

    def _restart(self, service: CameraService, camera: Camera) -> None:
        try:
            spec = service.spec_for(camera)
            self._supervisor.ensure(str(camera.id), spec, restart=True)
        except Exception as exc:  # noqa: BLE001 - a restart fault is reported, not raised
            log.warning("restart failed for %s: %s", camera.code, redact(str(exc)))

    def _notify_health(
        self, notifications: NotificationService, camera: Camera, assessment
    ) -> None:
        status = assessment.status.value
        if status == CameraStatus.ONLINE.value:
            notifications.dispatch(
                NotificationRequest(
                    kind="camera.restored",
                    title=f"Camera {camera.display_name} is back online",
                    body=f"{camera.code} at {camera.campus_location} is delivering video again.",
                    severity="low",
                    dedupe_key=f"camera-restored:{camera.id}:{int(time.time() // 3600)}",
                    camera_id=camera.id,
                ),
                notifications.recipients_for("health.view", camera),
            )
            return
        if status in {
            CameraStatus.OFFLINE.value,
            CameraStatus.AUTHENTICATION_FAILED.value,
            CameraStatus.DEGRADED.value,
        }:
            notifications.camera_health_alert(
                camera,
                status=status,
                reason=assessment.reason_code,
                detail=assessment.detail,
            )
