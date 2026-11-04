"""Camera health evaluation (proposal section 10).

The evaluator turns raw worker telemetry into one of the nine documented states. The
important part is the distinction between a temporary interruption and a sustained failure:
a single dropped second must not page anyone, while a camera that has genuinely gone away
must produce a health event exactly once.

Health events are recorded in `camera_health_events` and are kept separate from
AI-detected security incidents, as section 10 requires.
"""

from __future__ import annotations

import datetime as dt
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

from ..config import Settings
from ..ingest.worker import StreamStats
from ..models import Camera, CameraHealthEvent, CameraStatus

if TYPE_CHECKING:  # pragma: no cover
    from sqlalchemy.orm import Session

# Reason codes are stable strings so notifications can be deduplicated and operators can
# distinguish causes without parsing prose.
REASON_FRAME_GAP = "frame_gap"
REASON_WORKER_EXITED = "worker_exited"
REASON_RECONNECTING = "reconnecting"
REASON_AUTHENTICATION = "authentication_error"
REASON_LOW_FRAME_RATE = "low_frame_rate"
REASON_DECODER_FAILURES = "decoder_failures"
REASON_NO_SESSION = "no_managed_session"
REASON_RESTORED = "stream_restored"
REASON_MANUAL = "manual_state"


@dataclass(slots=True)
class HealthAssessment:
    status: CameraStatus
    reason_code: str
    detail: str
    seconds_since_frame: float | None
    changed: bool = False


class HealthEvaluator:
    def __init__(self, settings: Settings) -> None:
        self._settings = settings

    def evaluate(
        self,
        camera: Camera,
        stats: StreamStats | None,
        *,
        now: float | None = None,
    ) -> HealthAssessment:
        now = now if now is not None else time.time()
        current = CameraStatus(camera.status)

        # Manual and lifecycle states are authoritative; the evaluator does not override an
        # operator's Maintenance flag or a Disabled camera.
        if current in (
            CameraStatus.DISABLED,
            CameraStatus.MAINTENANCE,
            CameraStatus.PENDING_SETUP,
            CameraStatus.TESTING,
        ):
            return HealthAssessment(current, REASON_MANUAL, "operator-set state", None)

        if stats is None:
            # Registered and expected to run, but no managed session exists.
            last_frame = _frame_timestamp(camera)
            gap = now - last_frame if last_frame else None
            sustained = gap is None or gap > self._settings.reconnecting_grace_seconds
            return HealthAssessment(
                CameraStatus.OFFLINE if sustained else CameraStatus.RECONNECTING,
                REASON_NO_SESSION,
                "no managed stream session exists for this camera",
                gap,
            )

        if stats.last_error and "authentication" in stats.last_error:
            return HealthAssessment(
                CameraStatus.AUTHENTICATION_FAILED,
                REASON_AUTHENTICATION,
                "the camera rejected the stored credentials",
                _gap(stats.last_frame_at, now),
            )

        if stats.state == "failed":
            return HealthAssessment(
                CameraStatus.OFFLINE,
                REASON_WORKER_EXITED,
                f"the stream worker exhausted its retry budget ({stats.retry_count} attempts)",
                _gap(stats.last_frame_at, now),
            )

        gap = _gap(stats.last_frame_at, now)
        grace_open = gap is not None and gap <= self._settings.reconnecting_grace_seconds

        # The worker's own state outranks the frame clock: it says what the session is doing,
        # while a stale `last_frame_at` only says how long ago video last arrived. Deciding on
        # the gap alone would let a session that has never delivered a frame look healthy, and
        # section 6.6 does not allow that.
        if stats.state in ("starting", "connecting", "reconnecting"):
            if grace_open:
                return HealthAssessment(
                    CameraStatus.RECONNECTING,
                    REASON_RECONNECTING,
                    f"{stats.state} (reconnect attempt {stats.retry_count})",
                    gap,
                )
            return HealthAssessment(
                CameraStatus.OFFLINE,
                REASON_RECONNECTING,
                "reconnection has exceeded the grace period"
                if gap is not None
                else "this session has never delivered a frame",
                gap,
            )

        if stats.state == "stopped":
            return HealthAssessment(
                CameraStatus.OFFLINE,
                REASON_WORKER_EXITED,
                stats.last_error or "the stream session stopped",
                gap,
            )

        # The session claims to be delivering. A gap longer than the offline threshold is a
        # sustained failure; between the degraded and offline thresholds it is a hiccup.
        if gap is None or gap > self._settings.offline_after_seconds:
            return HealthAssessment(
                CameraStatus.OFFLINE,
                REASON_FRAME_GAP,
                "no video frame has ever arrived from this session"
                if gap is None
                else f"no video frame for {gap:.0f}s",
                gap,
            )

        if gap > self._settings.degraded_after_seconds:
            return HealthAssessment(
                CameraStatus.DEGRADED,
                REASON_FRAME_GAP,
                f"frame delivery is intermittent ({gap:.1f}s since the last frame)",
                gap,
            )
        if stats.decode_failures > 20:
            return HealthAssessment(
                CameraStatus.DEGRADED,
                REASON_DECODER_FAILURES,
                f"{stats.decode_failures} decode failures recorded",
                gap,
            )
        if stats.measured_fps < 1.0 and stats.frames_received > 0:
            return HealthAssessment(
                CameraStatus.DEGRADED,
                REASON_LOW_FRAME_RATE,
                f"measured frame rate is {stats.measured_fps} fps",
                gap,
            )

        # Section 6.6: Online means confirmed video delivery.
        return HealthAssessment(
            CameraStatus.ONLINE,
            REASON_RESTORED if current is not CameraStatus.ONLINE else "stream_healthy",
            f"{stats.frames_received} frames delivered at {stats.measured_fps} fps",
            gap,
        )


def _gap(last_frame_at: float, now: float) -> float | None:
    if not last_frame_at:
        return None
    return max(0.0, now - last_frame_at)


def _frame_timestamp(camera: Camera) -> float | None:
    stamp = camera.last_successful_frame_at
    if stamp is None:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=dt.UTC)
    return stamp.timestamp()


def record_transition(
    session: Session,
    camera: Camera,
    assessment: HealthAssessment,
    *,
    now: float | None = None,
) -> CameraHealthEvent | None:
    """Persist a health event only when the state genuinely changed.

    Returning the row only on change is what keeps section 15's alert deduplication honest:
    an unchanged Degraded camera cannot generate a new notification every poll.
    """
    previous = CameraStatus(camera.status)
    if assessment.status is previous:
        return None

    event = CameraHealthEvent(
        camera_id=camera.id,
        previous_status=previous.value,
        status=assessment.status.value,
        reason_code=assessment.reason_code,
        detail=assessment.detail,
        duration_seconds=assessment.seconds_since_frame,
    )
    session.add(event)
    camera.status = assessment.status.value
    camera.last_error_code = None if assessment.status is CameraStatus.ONLINE else assessment.reason_code
    if assessment.status is CameraStatus.ONLINE:
        camera.last_successful_frame_at = _utcnow()
    session.flush()
    return event


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)
