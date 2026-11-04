"""Camera health evaluation (proposal section 10).

The thresholds exist to separate a hiccup from a failure: one lost second must not page
anybody, while a camera that has genuinely gone away must produce exactly one health event.
`create_app(..., start_supervision=False)` lets these tests drive one cycle on demand
instead of racing a background thread.
"""

from __future__ import annotations

import datetime as dt
import time

import pytest
from sqlalchemy import func, select

from watchtower import models as wt_models
from watchtower.health import evaluator
from watchtower.health.evaluator import HealthEvaluator, CameraStatus
from watchtower.ingest.worker import StreamStats
from watchtower.models import CameraHealthEvent

DEGRADED_AFTER = 4.0
OFFLINE_AFTER = 15.0
RECONNECT_GRACE = 20.0


def stats(camera_id: str, **overrides) -> StreamStats:
    base = {
        "camera_id": camera_id,
        "state": "online",
        "pid": 1234,
        "started_at": time.time() - 60,
        "last_frame_at": time.time(),
        "frames_received": 600,
        "measured_fps": 12.0,
        "width": 1920,
        "height": 1080,
    }
    base.update(overrides)
    return StreamStats(**base)


@pytest.fixture
def evaluate(settings):
    assess = HealthEvaluator(settings).evaluate

    def _run(camera, stream_stats=None, *, now=None):
        return assess(camera, stream_stats, now=now if now is not None else time.time())

    return _run


def online_camera(factory):
    return factory.camera(
        status=CameraStatus.ONLINE.value,
        is_registered=True,
        desired_state="running",
        last_frame_at=dt.datetime.now(dt.UTC),
    )


# --------------------------------------------------------------------------- #
# Missing managed session: grace period first, then offline
# --------------------------------------------------------------------------- #


def test_a_missing_session_is_reconnecting_while_the_grace_period_is_open(evaluate, factory):
    camera = online_camera(factory)
    camera.last_successful_frame_at = dt.datetime.now(dt.UTC) - dt.timedelta(seconds=5)

    assessment = evaluate(camera, None)

    assert assessment.status is CameraStatus.RECONNECTING
    assert assessment.reason_code == evaluator.REASON_NO_SESSION
    assert assessment.seconds_since_frame == pytest.approx(5.0, abs=1.0)


def test_a_missing_session_becomes_offline_once_the_grace_period_passes(evaluate, factory):
    camera = online_camera(factory)
    camera.last_successful_frame_at = dt.datetime.now(dt.UTC) - dt.timedelta(
        seconds=RECONNECT_GRACE + 5
    )

    assessment = evaluate(camera, None)

    assert assessment.status is CameraStatus.OFFLINE
    assert assessment.reason_code == evaluator.REASON_NO_SESSION


def test_a_camera_that_never_delivered_a_frame_is_offline_without_a_session(evaluate, factory):
    """No last-frame stamp means there is nothing to be generous about."""
    camera = factory.camera(status=CameraStatus.OFFLINE.value, is_registered=True)
    camera.last_successful_frame_at = None

    assert evaluate(camera, None).status is CameraStatus.OFFLINE


# --------------------------------------------------------------------------- #
# Frame gaps
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "gap, expected",
    [
        (1.0, CameraStatus.ONLINE),
        (DEGRADED_AFTER - 1.0, CameraStatus.ONLINE),
        (DEGRADED_AFTER + 1.0, CameraStatus.DEGRADED),
        (OFFLINE_AFTER - 1.0, CameraStatus.DEGRADED),
        (OFFLINE_AFTER + 1.0, CameraStatus.OFFLINE),
        (OFFLINE_AFTER * 4, CameraStatus.OFFLINE),
    ],
)
def test_the_frame_gap_thresholds_pick_the_state(evaluate, factory, gap, expected):
    camera = online_camera(factory)
    now = time.time()

    assessment = evaluate(camera, stats(str(camera.id), last_frame_at=now - gap), now=now)

    assert assessment.status is expected
    if expected is CameraStatus.DEGRADED:
        assert assessment.reason_code == evaluator.REASON_FRAME_GAP
    if expected is CameraStatus.OFFLINE:
        assert assessment.reason_code == evaluator.REASON_FRAME_GAP
        assert f"{gap:.0f}s" in assessment.detail


def test_a_sustained_low_frame_rate_is_degraded_not_online(evaluate, factory):
    camera = online_camera(factory)

    assessment = evaluate(camera, stats(str(camera.id), measured_fps=0.4, frames_received=100))

    assert assessment.status is CameraStatus.DEGRADED
    assert assessment.reason_code == evaluator.REASON_LOW_FRAME_RATE


def test_decoder_trouble_is_degraded(evaluate, factory):
    camera = online_camera(factory)

    assessment = evaluate(camera, stats(str(camera.id), decode_failures=25))

    assert assessment.status is CameraStatus.DEGRADED
    assert assessment.reason_code == evaluator.REASON_DECODER_FAILURES


def test_an_exhausted_worker_reports_offline(evaluate, factory):
    camera = online_camera(factory)

    assessment = evaluate(camera, stats(str(camera.id), state="failed", retry_count=10))

    assert assessment.status is CameraStatus.OFFLINE
    assert assessment.reason_code == evaluator.REASON_WORKER_EXITED
    assert "10" in assessment.detail


def test_credentials_rejected_by_the_camera_is_its_own_state(evaluate, factory):
    """Section 10 keeps `authentication_failed` distinct so operators can tell a bad
    password apart from a dead cable."""
    camera = online_camera(factory)

    assessment = evaluate(
        camera, stats(str(camera.id), state="reconnecting", last_error="authentication failed")
    )

    assert assessment.status is CameraStatus.AUTHENTICATION_FAILED
    assert assessment.reason_code == evaluator.REASON_AUTHENTICATION


def test_reconnecting_within_the_grace_period_stays_reconnecting(evaluate, factory):
    camera = online_camera(factory)
    now = time.time()

    assessment = evaluate(
        camera, stats(str(camera.id), state="reconnecting", last_frame_at=now - 6), now=now
    )

    assert assessment.status is CameraStatus.RECONNECTING
    assert assessment.reason_code == evaluator.REASON_RECONNECTING


def test_reconnecting_past_the_grace_period_becomes_offline(evaluate, factory):
    camera = online_camera(factory)
    now = time.time()

    assessment = evaluate(
        camera,
        stats(str(camera.id), state="reconnecting", last_frame_at=now - (RECONNECT_GRACE + 2)),
        now=now,
    )

    assert assessment.status is CameraStatus.OFFLINE
    assert "grace" in assessment.detail


@pytest.mark.parametrize("state", ["starting", "connecting"])
def test_a_session_that_has_not_delivered_a_frame_is_never_online(evaluate, factory, state):
    """Section 6.6: online requires confirmed video delivery, not a live worker process.

    The supervisor fake creates exactly this telemetry when a stream is activated, so the
    first poll after activation cannot report the camera as healthy.
    """
    camera = online_camera(factory)
    now = time.time()

    assessment = evaluate(
        camera,
        stats(str(camera.id), state=state, last_frame_at=0.0, frames_received=0, measured_fps=0.0),
        now=now,
    )

    assert assessment.status is CameraStatus.OFFLINE
    assert assessment.reason_code == evaluator.REASON_RECONNECTING
    assert "never delivered a frame" in assessment.detail


def test_a_starting_session_within_the_grace_period_is_reconnecting(evaluate, factory):
    camera = online_camera(factory)
    now = time.time()

    assessment = evaluate(
        camera,
        stats(str(camera.id), state="starting", last_frame_at=now - 3, frames_received=1),
        now=now,
    )

    assert assessment.status is CameraStatus.RECONNECTING


# --------------------------------------------------------------------------- #
# Operator-set states are authoritative
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "manual_status",
    [
        CameraStatus.DISABLED,
        CameraStatus.MAINTENANCE,
        CameraStatus.PENDING_SETUP,
        CameraStatus.TESTING,
    ],
)
def test_a_manual_state_is_never_overridden_by_the_evaluator(evaluate, factory, manual_status):
    camera = factory.camera(code=f"CAM-{manual_status.value[:6].upper()}", status=manual_status.value)
    now = time.time()

    dead = stats(str(camera.id), state="failed", last_frame_at=now - 600, retry_count=9)
    assessment = evaluate(camera, dead, now=now)

    assert assessment.status is manual_status
    assert assessment.reason_code == evaluator.REASON_MANUAL


@pytest.mark.parametrize("manual_status", [CameraStatus.DISABLED, CameraStatus.MAINTENANCE])
def test_a_manual_state_survives_a_refresh_call(manual_status, admin, factory, db):
    """The HTTP refresh path must not silently switch a disabled camera back to online."""
    camera = factory.camera(status=manual_status.value, is_registered=True)
    factory.session.commit()
    db.commit()

    response = admin.client.post(f"/api/cameras/{camera.id}/refresh")

    assert response.status_code == 200, response.text
    assert response.json()["status"] == manual_status.value
    db.commit()
    assert db.get(wt_models.Camera, camera.id).status == manual_status.value


# --------------------------------------------------------------------------- #
# record_transition(): one row per genuine change
# --------------------------------------------------------------------------- #


def test_record_transition_writes_one_row_and_only_on_a_change(db, factory, settings):
    camera = online_camera(factory)
    assess = HealthEvaluator(settings).evaluate

    offline = assess(
        camera,
        stats(str(camera.id), state="failed", last_frame_at=time.time() - 600, retry_count=5),
    )

    first = evaluator.record_transition(db, camera, offline)
    db.commit()
    assert first is not None
    assert first.previous_status == CameraStatus.ONLINE.value
    assert first.status == CameraStatus.OFFLINE.value

    # the same verdict again must not add a second event - section 15's dedup depends on it
    repeat = evaluator.record_transition(db, camera, offline)
    db.commit()
    assert repeat is None

    rows = db.scalars(
        select(CameraHealthEvent).where(CameraHealthEvent.camera_id == camera.id)
    ).all()
    assert len(rows) == 1


def test_record_transition_moves_the_camera_row_and_clears_the_error_on_online(
    db, factory, settings
):
    camera = factory.camera(status=CameraStatus.OFFLINE.value, is_registered=True)
    camera.last_error_code = "frame_gap"
    db.flush()

    healthy = HealthEvaluator(settings).evaluate(
        camera, stats(str(camera.id), last_frame_at=time.time())
    )
    event = evaluator.record_transition(db, camera, healthy)
    db.commit()

    assert event.status == CameraStatus.ONLINE.value
    assert event.reason_code == evaluator.REASON_RESTORED
    assert camera.last_error_code is None
    assert camera.last_successful_frame_at is not None


def test_a_health_transition_is_visible_in_the_history_endpoint(admin, factory, db, supervisor):
    """`POST /refresh` then `GET /health` is the operator's view of section 10."""
    camera = online_camera(factory)
    supervisor.stats_by_camera[str(camera.id)] = StreamStats(
        camera_id=str(camera.id),
        state="failed",
        pid=4242,
        last_frame_at=time.time() - 3600,
        retry_count=6,
        frames_received=10,
        measured_fps=1.0,
    )
    factory.session.commit()
    db.commit()

    refreshed = admin.client.post(f"/api/cameras/{camera.id}/refresh")
    assert refreshed.status_code == 200, refreshed.text
    assert refreshed.json()["status"] == "offline"
    assert refreshed.json()["changed"] is True

    history = admin.client.get(f"/api/cameras/{camera.id}/health")
    assert history.status_code == 200, history.text
    entries = history.json()
    assert entries[0]["to"] == "offline"
    assert entries[0]["from"] == "online"

    again = admin.client.post(f"/api/cameras/{camera.id}/refresh")
    assert again.json()["changed"] is False
    db.commit()
    assert db.scalar(
        select(func.count(CameraHealthEvent.id)).where(
            CameraHealthEvent.camera_id == camera.id
        )
    ) == 1


def test_the_supervision_loop_evaluates_registered_cameras_without_a_background_thread(
    settings, factory, db, session_factory, supervisor
):
    """`start_supervision=False` exists so a test can run exactly one cycle."""
    from watchtower.services.runtime import SupervisionLoop

    camera = online_camera(factory)
    factory.session.commit()
    db.commit()
    supervisor.stats_by_camera[str(camera.id)] = StreamStats(
        camera_id=str(camera.id),
        state="online",
        last_frame_at=time.time() - 400,
        frames_received=50,
        measured_fps=2.0,
        retry_count=3,
    )

    loop = SupervisionLoop(settings, session_factory, supervisor)
    result = loop.cycle()

    # The loop writes on its own session; this harness session holds the row in its identity
    # map with `expire_on_commit=False`, so it has to be told to read again.
    db.expire_all()
    row = db.get(wt_models.Camera, camera.id)
    assert row.status == CameraStatus.OFFLINE.value
    assert result["transitions"] == 1
    # exactly one health event for one genuine change
    assert (
        db.scalar(
            select(func.count(CameraHealthEvent.id)).where(
                CameraHealthEvent.camera_id == camera.id
            )
        )
        == 1
    )
