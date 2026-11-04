"""Analysis engine: throttled sampling, detector fan-out and candidate events (section 11).

The engine never concludes anything. It samples the supervisor's newest frame at the policy's
analysis rate, runs only the detectors the policy names, and hands the raw findings to
`events.submit_findings` so a human reviewer sees candidates rather than verdicts. A camera
that cannot be analysed is skipped with its reason recorded; it must never stop the poller or
the other cameras.
"""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Protocol

import cv2
import numpy as np
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import Camera, DetectionEvent, MonitoringPolicy
from ..security.secrets import redact
from . import detectors as D
from .events import EventOutcome, EvidenceWriter, submit_findings

LOGGER = logging.getLogger("watchtower.analysis")

MIN_SAMPLE_FPS = 0.1
STALE_GAP_MULTIPLIER = 4.0  # a stream gap this long means the background baseline no longer describes the scene


class FrameSource(Protocol):
    """The slice of `StreamSupervisor` the engine needs."""

    def latest_frame(self, camera_id: str) -> tuple[float, bytes, float] | None: ...


@dataclass(slots=True)
class FrameSample:
    captured_at: float
    jpeg: bytes
    gray: np.ndarray
    measured_fps: float


@dataclass(slots=True)
class CameraMemory:
    last_sample_at: float = 0.0
    decode_failures: int = 0
    model: D.MotionModel = field(default_factory=D.MotionModel)
    states: dict[str, D.DetectorState] = field(default_factory=dict)


@dataclass(slots=True)
class DetectorSet:
    codes: tuple[str, ...]
    ready: dict[str, D.Detector]
    status: dict[str, str]


class AnalysisEngine:
    """Drives per-camera classical-CV analysis for a background poll."""

    def __init__(
        self,
        settings: Settings,
        supervisor: FrameSource,
        *,
        evidence_writer: EvidenceWriter | None = None,
        on_alert: Callable[[Session, Camera, DetectionEvent], None] | None = None,
    ) -> None:
        self._settings = settings
        self._supervisor = supervisor
        self._evidence_writer = evidence_writer
        self._on_alert = on_alert
        self._memory: dict[str, CameraMemory] = {}
        self._policies: dict[int, DetectorSet] = {}
        self._status: dict[str, dict[str, str]] = {}

    # ------------------------------------------------------------------ #
    # Public surface
    # ------------------------------------------------------------------ #

    def run(self, session: Session, camera: Camera, policy: MonitoringPolicy) -> list[DetectionEvent]:
        """Analyse this camera's newest frame and persist the candidate events it produced."""
        camera_id = str(camera.id)
        bundle = self._detector_set(policy)
        self._status[camera_id] = bundle.status
        if not bundle.ready:
            return []

        sample = self._sample(camera_id, policy)
        if sample is None:
            return []

        zones = D.zones_from_policy(policy.zones)
        zone_source = "policy"
        if not zones:
            # A detector enabled without approved geometry watches the whole frame, and a
            # reviewer has to be able to tell that configuration apart from a real zone.
            zones = [D.full_frame_zone()]
            zone_source = "full_frame_fallback"

        findings = self._detect(camera_id, bundle, sample, zones)
        if not findings:
            return []

        outcomes = submit_findings(
            session,
            camera=camera,
            policy=policy,
            settings=self._settings,
            findings=findings,
            occurred_at=dt.datetime.fromtimestamp(sample.captured_at, dt.UTC),
            measured_fps=sample.measured_fps,
            snapshot=sample.jpeg,
            evidence_writer=self._evidence_writer,
            zone_source=zone_source,
        )
        self._log(camera.code, outcomes)
        if self._on_alert is not None:
            for outcome in outcomes:
                if outcome.alert:
                    self._on_alert(session, camera, outcome.event)
        return [outcome.event for outcome in outcomes]

    def run_enabled_cameras(self, session: Session, cameras: Iterable[Camera]) -> list[DetectionEvent]:
        """Poll every camera whose policy is enabled, one savepoint per camera."""
        created: list[DetectionEvent] = []
        for camera in cameras:
            policy = self._policy_for(session, camera)
            if policy is None or not policy.enabled:
                continue
            try:
                # The savepoint discards only this camera's rows, so one failing camera cannot
                # unwind the events already gathered for the others.
                with session.begin_nested():
                    created.extend(self.run(session, camera, policy))
            except Exception as exc:  # noqa: BLE001 - a camera failure must not end the poll
                LOGGER.warning(redact(f"{camera.code}: analysis pass skipped: {exc}"))
        return created

    def reset(self, camera_id: str) -> None:
        """Drop motion baselines and zone counters after a stream reconnect."""
        self._memory.pop(camera_id, None)

    def detector_status(self, camera_id: str) -> dict[str, str]:
        """Whether each detector code in the last analysed policy ran, and if not, why."""
        return dict(self._status.get(str(camera_id), {}))

    # ------------------------------------------------------------------ #
    # Sampling
    # ------------------------------------------------------------------ #

    def _sample_interval(self, policy: MonitoringPolicy) -> float:
        fps = float(policy.analysis_fps)
        ceiling = float(self._settings.analysis_fps)
        if fps <= 0:
            fps = ceiling
        if ceiling > 0:
            # The platform ceiling bounds decode cost across all enabled cameras.
            fps = min(fps, ceiling)
        return 1.0 / max(MIN_SAMPLE_FPS, fps)

    def _sample(self, camera_id: str, policy: MonitoringPolicy) -> FrameSample | None:
        raw = self._supervisor.latest_frame(camera_id)
        if raw is None:
            return None
        captured_at, jpeg, measured_fps = raw
        memory = self._memory.setdefault(camera_id, CameraMemory())

        interval = self._sample_interval(policy)
        if captured_at <= memory.last_sample_at:
            return None
        if captured_at - memory.last_sample_at < interval:
            return None
        if memory.last_sample_at and captured_at - memory.last_sample_at > interval * STALE_GAP_MULTIPLIER:
            self.reset(camera_id)
            memory = self._memory.setdefault(camera_id, CameraMemory())

        decoded = cv2.imdecode(np.frombuffer(jpeg, dtype=np.uint8), cv2.IMREAD_COLOR)
        if decoded is None:
            memory.decode_failures += 1
            LOGGER.warning(redact(f"{camera_id}: frame decode failed ({memory.decode_failures} this session)"))
            return None

        memory.last_sample_at = captured_at
        return FrameSample(
            captured_at=captured_at,
            jpeg=jpeg,
            gray=cv2.cvtColor(decoded, cv2.COLOR_BGR2GRAY),
            measured_fps=float(measured_fps),
        )

    # ------------------------------------------------------------------ #
    # Detectors
    # ------------------------------------------------------------------ #

    def _detect(
        self, camera_id: str, bundle: DetectorSet, sample: FrameSample, zones: Sequence[D.Zone]
    ) -> list[D.RawFinding]:
        findings: list[D.RawFinding] = []
        for code, detector in bundle.ready.items():
            state = self._state_for(camera_id, code, sample.captured_at)
            try:
                findings.extend(detector.detect(sample.gray, zones, state))
            except D.DetectorUnavailableError as exc:
                bundle.status[code] = f"not analysed: {redact(exc.reason)}"
        return findings

    def _state_for(self, camera_id: str, code: str, timestamp: float) -> D.DetectorState:
        memory = self._memory.setdefault(camera_id, CameraMemory())
        state = memory.states.get(code)
        if state is None:
            state = D.DetectorState(camera_id=camera_id, detector_code=code, model=memory.model)
            memory.states[code] = state
        state.timestamp = timestamp
        return state

    def _detector_set(self, policy: MonitoringPolicy) -> DetectorSet:
        """Resolve a policy's detector codes, rebuilding only when the policy changed."""
        codes = tuple(str(code).strip() for code in (policy.detector_codes or []) if str(code).strip())
        cached = self._policies.get(policy.id)
        if cached is not None and cached.codes == codes:
            return cached

        ready: dict[str, D.Detector] = {}
        status: dict[str, str] = {}
        for code in codes:
            if code in ready or code in status:
                continue
            try:
                detector = D.build_detector(code)
            except KeyError:
                status[code] = "unknown detector code; nothing analysed"
                continue
            if not detector.available:
                status[code] = f"not analysed: {D.unavailable_reason(code)}"
                continue
            ready[code] = detector
            status[code] = "active"
        bundle = DetectorSet(codes=codes, ready=ready, status=status)
        self._policies[policy.id] = bundle
        if not ready and set(codes).isdisjoint(D.available_detector_codes()):
            LOGGER.warning(
                "policy %s names no detector this deployment can run: %s",
                policy.code,
                ", ".join(codes),
            )
        return bundle

    def _policy_for(self, session: Session, camera: Camera) -> MonitoringPolicy | None:
        """The camera's policy, loaded through the relationship or by id when it is detached."""
        if camera.monitoring_policy is not None:
            return camera.monitoring_policy
        if camera.monitoring_policy_id is None:
            return None
        return session.get(MonitoringPolicy, camera.monitoring_policy_id)

    # ------------------------------------------------------------------ #
    # Logging
    # ------------------------------------------------------------------ #

    def _log(self, camera_code: str, outcomes: Sequence[EventOutcome]) -> None:
        label = redact(camera_code)
        for outcome in outcomes:
            event = outcome.event
            zone = redact(str((event.event_metadata or {}).get("zone_id", "")))
            if outcome.alert:
                LOGGER.info(
                    "candidate event %s %s zone=%s confidence=%.2f", label, event.category, zone, event.confidence
                )
            elif outcome.duplicate:
                LOGGER.debug(
                    "suppressed repeat %s %s zone=%s (%s)", label, event.category, zone, outcome.reason
                )
