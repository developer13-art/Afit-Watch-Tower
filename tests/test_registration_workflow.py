"""Registration workflow gating (proposal sections 6.2, 6.5, 6.6 and 7).

The load-bearing promises:

  * registering a camera does not start its stream;
  * `activatable` is True only when the connection test returned `connection_successful`;
  * activation is refused (409) unless the last test passed, and it never claims `online`
    because frames are not confirmed yet - only `testing`;
  * a camera with no probe history cannot be activated;
  * every state change is audited.
"""

from __future__ import annotations

import contextlib
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from watchtower.ingest.supervisor import StreamCapacityError
from watchtower.models import (
    Camera,
    CameraSecret,
    CameraStreamSession,
    ProbeResult,
)
from watchtower.rtsp.probe import ProbeOutcome

RTSP_OK = "rtsp://admin:sup3r-secret-pw@10.20.0.7:554/cam/realmonitor"


def payload(code: str, *, url: str = RTSP_OK, **overrides) -> dict:
    body = {
        "method": "rtsp_string",
        "display_name": "Main Gate Camera",
        "code": code,
        "campus_location": "Main gate, inbound lane",
        "rtsp_url": url,
        "verified_in_vlc": True,
    }
    body.update(overrides)
    return body


def connect_outcome(message: str | None = None) -> ProbeOutcome:
    return ProbeOutcome(
        result=ProbeResult.CONNECTED,
        message=message or "Connection successful - 40 frames decoded at 1920x1080",
        frames_decoded=40,
        measured_fps=12.5,
        width=1920,
        height=1080,
        stage="complete",
    )


def failed_outcome(result: ProbeResult = ProbeResult.AUTH_FAILED) -> ProbeOutcome:
    return ProbeOutcome(
        result=result,
        message=f"synthetic failure: {result.value}",
        stage="handshake",
    )


# --------------------------------------------------------------------------- #
# Step 1-10: registration
# --------------------------------------------------------------------------- #


def test_registering_a_camera_does_not_activate_it(admin, fake_probe, supervisor, read_audit):
    fake_probe(ProbeResult.CONNECTED)

    response = admin.client.post("/api/cameras", json=payload("AFIT-GATE-001"))

    assert response.status_code == 201, response.text
    camera = response.json()["camera"]
    assert camera["status"] != "online"
    assert camera["desired_state"] == "stopped"
    assert camera["is_registered"] is False
    assert camera["live_view_available"] is False
    # nothing was handed to the stream supervisor
    assert supervisor.ensure_calls == []
    assert supervisor.snapshot_all() == {}
    assert "camera.register" in read_audit(actions=True)


def test_registration_reports_activatable_only_after_a_passing_test(admin, fake_probe):
    fake_probe(connect_outcome())
    response = admin.client.post("/api/cameras", json=payload("AFIT-GATE-002"))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["activatable"] is True
    assert body["connection_test"]["result"] == ProbeResult.CONNECTED.value
    assert body["camera"]["status"] == "pending_setup"


@pytest.mark.parametrize(
    "result",
    [
        ProbeResult.AUTH_FAILED,
        ProbeResult.HOST_UNREACHABLE,
        ProbeResult.PATH_INVALID,
        ProbeResult.DECODE_FAILED,
        ProbeResult.TIMED_OUT,
        ProbeResult.CANCELLED,
    ],
)
def test_activatable_is_false_when_the_connection_test_failed(admin, fake_probe, result):
    fake_probe(result)
    response = admin.client.post("/api/cameras", json=payload(f"AFIT-GATE-{result.value[:4]}-X"))
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["activatable"] is False
    assert body["connection_test"]["result"] == result.value
    assert body["camera"]["status"] != "online"
    assert body["camera"]["is_registered"] is False
    assert "has not been activated" in body["message"]


def test_a_failed_draft_test_writes_no_camera_record(admin, fake_probe, db):
    fake_probe(ProbeResult.HOST_UNREACHABLE)
    response = admin.client.post("/api/cameras/test-draft", json=payload("AFIT-DRAFT-001"))
    assert response.status_code == 200, response.text
    assert response.json()["result"] == ProbeResult.HOST_UNREACHABLE.value
    db.commit()
    assert db.scalar(select(func.count(Camera.id))) == 0


def test_a_passing_draft_test_also_writes_no_camera_record(admin, fake_probe, db):
    """The wizard's Test button previews the verdict; it must not register anything."""
    fake_probe(connect_outcome())
    response = admin.client.post("/api/cameras/test-draft", json=payload("AFIT-DRAFT-002"))
    assert response.status_code == 200, response.text
    assert response.json()["result"] == ProbeResult.CONNECTED.value
    db.commit()
    assert db.scalar(select(func.count(Camera.id))) == 0
    # and the credential the draft carried was never sealed into camera_secrets
    assert db.scalar(select(func.count(CameraSecret.id))) == 0


def test_duplicate_camera_code_is_refused(admin, fake_probe):
    fake_probe(connect_outcome())
    first = admin.client.post("/api/cameras", json=payload("AFIT-GATE-DUP"))
    assert first.status_code == 201, first.text

    second = admin.client.post("/api/cameras", json=payload("AFIT-GATE-DUP"))
    assert second.status_code == 409
    assert second.json()["detail"]["code"] == "duplicate_code"


def test_an_invalid_camera_code_is_rejected_with_the_offending_field(admin, fake_probe):
    fake_probe(connect_outcome())
    response = admin.client.post("/api/cameras", json=payload("-not a code-"))
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_camera_code"
    assert detail["field"] == "code"


def test_an_unsupported_protocol_is_rejected_on_the_rtsp_url_field(admin, fake_probe):
    fake_probe(connect_outcome())
    response = admin.client.post(
        "/api/cameras", json=payload("AFIT-GATE-HTTP", url="http://admin:pw@10.20.0.7/live")
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert detail["code"] == "invalid_connection"
    assert detail["field"] == "rtsp_url"


# --------------------------------------------------------------------------- #
# Step 11: activation
# --------------------------------------------------------------------------- #


def _register(admin, fake_probe, code: str, outcome_value=ProbeResult.CONNECTED) -> str:
    fake_probe(outcome_value)
    response = admin.client.post("/api/cameras", json=payload(code))
    assert response.status_code == 201, response.text
    return response.json()["camera"]["id"]


def test_activation_moves_a_verified_camera_to_testing_and_never_straight_to_online(
    admin, fake_probe, supervisor, db, read_audit
):
    camera_id = _register(admin, fake_probe, "AFIT-GATE-003")
    fake_probe(connect_outcome())

    response = admin.client.post(f"/api/cameras/{camera_id}/activate")
    assert response.status_code == 200, response.text
    camera = response.json()
    assert camera["status"] == "testing"
    assert camera["status"] != "online"
    assert camera["is_registered"] is True
    assert camera["desired_state"] == "running"

    # a managed session record exists, but no frames are claimed
    db.commit()
    sessions = db.scalars(
        select(CameraStreamSession).where(CameraStreamSession.camera_id == uuid.UUID(camera_id))
    ).all()
    assert len(sessions) == 1
    assert sessions[0].state == "starting"
    assert sessions[0].last_frame_at is None
    assert supervisor.stats(camera_id) is not None
    assert "camera.activate" in read_audit(actions=True)


@pytest.mark.parametrize(
    "result",
    [
        ProbeResult.AUTH_FAILED,
        ProbeResult.HOST_UNREACHABLE,
        ProbeResult.PATH_INVALID,
        ProbeResult.DECODE_FAILED,
        ProbeResult.TIMED_OUT,
        ProbeResult.CANCELLED,
    ],
)
def test_activate_returns_409_when_the_last_probe_was_not_a_success(
    admin, fake_probe, supervisor, db, result
):
    # registration itself runs the connection test, so the failing verdict is the last
    # probe history this camera has
    camera_id = _register(admin, fake_probe, f"AFIT-ACT-{result.value[:5]}", result)

    response = admin.client.post(f"/api/cameras/{camera_id}/activate")
    assert response.status_code == 409
    detail = response.json()["detail"]
    assert detail["code"] == "test_not_passed"
    assert result.value in detail["message"]
    # refused activations must not touch the supervisor or set any live state
    assert supervisor.ensure_calls == []
    current = admin.client.get(f"/api/cameras/{camera_id}")
    assert current.status_code == 200, current.text
    assert current.json()["status"] != "online"
    assert current.json()["is_registered"] is False
    assert current.json()["desired_state"] == "stopped"
    db.commit()
    assert db.scalar(
        select(func.count(CameraStreamSession.id)).where(
            CameraStreamSession.camera_id == uuid.UUID(camera_id)
        )
    ) == 0


def test_a_camera_with_no_probe_history_cannot_be_activated(admin, fake_probe, factory):
    camera = factory.camera(probe_result=None)
    factory.session.commit()

    response = admin.client.post(f"/api/cameras/{camera.id}/activate")
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "test_required"


def test_a_retest_that_passes_makes_the_camera_activable(admin, fake_probe, supervisor):
    camera_id = _register(admin, fake_probe, "AFIT-GATE-004", ProbeResult.AUTH_FAILED)
    assert (
        admin.client.post(f"/api/cameras/{camera_id}/activate").status_code == 409
    )

    # the operator fixes the password, so the next probe succeeds
    fake_probe(connect_outcome())
    test = admin.client.post(f"/api/cameras/{camera_id}/test")
    assert test.status_code == 200, test.text
    assert test.json()["result"] == ProbeResult.CONNECTED.value

    activate = admin.client.post(f"/api/cameras/{camera_id}/activate")
    assert activate.status_code == 200, activate.text
    assert activate.json()["status"] == "testing"
    assert supervisor.ensure_calls.count(str(camera_id)) == 1


def test_a_connection_test_records_its_result_and_is_audited(admin, fake_probe, read_audit):
    camera_id = _register(admin, fake_probe, "AFIT-GATE-005")
    fake_probe(failed_outcome(ProbeResult.PATH_INVALID))

    response = admin.client.post(f"/api/cameras/{camera_id}/test")
    assert response.status_code == 200, response.text
    assert response.json()["result"] == ProbeResult.PATH_INVALID.value

    probes = [row for row in read_audit() if row.action == "camera.connection_test"]
    assert len(probes) == 2  # the registration test and this one
    assert probes[-1].outcome == "failure"
    assert probes[-1].details["result"] == ProbeResult.PATH_INVALID.value


def test_updating_a_connection_forces_reverification(admin, fake_probe, db, read_audit):
    camera_id = _register(admin, fake_probe, "AFIT-GATE-006")
    fake_probe(ProbeResult.HOST_UNREACHABLE)

    response = admin.client.patch(
        f"/api/cameras/{camera_id}",
        json={"rtsp_url": "rtsp://admin:newpw@10.20.0.9:554/media/video1"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["connection_test"]["result"] == ProbeResult.HOST_UNREACHABLE.value
    assert body["camera"]["host"] == "10.20.0.9"
    assert body["camera"]["port"] == 554
    assert body["camera"]["stream_path"] == "/media/video1"
    assert body["camera"]["has_secret"] is True
    # the edit invalidates the previous verdict, so the camera is not treated as live and
    # cannot be activated until the new connection passes
    assert body["camera"]["status"] != "online"
    assert body["camera"]["live_view_available"] is False
    assert body["camera"]["last_probe_result"] == ProbeResult.HOST_UNREACHABLE.value

    refused = admin.client.post(f"/api/cameras/{camera_id}/activate")
    assert refused.status_code == 409
    assert refused.json()["detail"]["code"] == "test_not_passed"

    # a name-only edit must not force a re-test
    name_only = admin.client.patch(f"/api/cameras/{camera_id}", json={"display_name": "Gate 1"})
    assert name_only.status_code == 200, name_only.text
    assert name_only.json()["connection_test"] is None

    updates = [row.action for row in read_audit()]
    assert "camera.update" in updates


def test_register_test_activate_disable_and_update_are_each_audited(admin, fake_probe, read_audit):
    camera_id = _register(admin, fake_probe, "AFIT-GATE-007")
    admin.client.post(f"/api/cameras/{camera_id}/test")
    admin.client.post(f"/api/cameras/{camera_id}/activate")
    admin.client.patch(f"/api/cameras/{camera_id}", json={"display_name": "Gate 7"})

    actions = read_audit(actions=True)
    assert "camera.register" in actions
    assert "camera.connection_test" in actions
    assert "camera.activate" in actions
    assert "camera.update" in actions
    for action in ("camera.register", "camera.connection_test", "camera.activate", "camera.update"):
        row = [entry for entry in read_audit() if entry.action == action][-1]
        assert row.outcome == "success"
        assert row.actor_username == admin.username


def test_disabling_a_camera_stops_the_stream_and_is_audited(admin, fake_probe, supervisor, read_audit):
    """Section 7: disabling releases the worker and records the transition.

    Found while writing this suite: `disable()` used `CameraHealthEvent` without importing
    it (NameError -> 500). `src/watchtower/services/cameras.py` now imports the model, so
    this asserts the promised behaviour instead of xfailing.
    """
    camera_id = _register(admin, fake_probe, "AFIT-GATE-008")
    admin.client.post(f"/api/cameras/{camera_id}/activate")

    response = admin.client.post(f"/api/cameras/{camera_id}/disable")
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "disabled"
    assert response.json()["desired_state"] == "stopped"
    assert (str(camera_id), "disabled") in supervisor.stop_calls
    assert "camera.disable" in read_audit(actions=True)


def test_activation_reports_stream_capacity_instead_of_an_internal_error(
    make_app, settings, factory, fake_probe, dashboard_for
):
    """A full host is a 503 `stream_capacity`, not a 500.

    Found while writing this suite: `activate()` let `StreamCapacityError` escape, so the
    operator got `internal_error`. `services/cameras.py` now converts it to the
    `stream_capacity` code that `routers/cameras.py` maps to 503.
    """
    launched = make_app(settings, supervisor_obj=_CapacityBlockedSupervisor())
    user = factory.user(username="capacity-admin", roles=("system_administrator",))
    factory.session.commit()
    actor = SimpleNamespace(client=dashboard_for(launched.client, user.username))
    camera_id = _register(actor, fake_probe, "AFIT-GATE-009")

    response = actor.client.post(f"/api/cameras/{camera_id}/activate")
    assert response.status_code == 503, response.text
    assert response.json()["detail"]["code"] == "stream_capacity"


class _CapacityBlockedSupervisor:
    """Every activation attempt hits the configured stream ceiling."""

    def ensure(self, camera_id, spec, *, restart=False):
        raise StreamCapacityError("the configured ceiling has been reached")

    def stop(self, camera_id, *, reason="disabled"):
        return False

    def stats(self, camera_id):
        return None

    def snapshot_all(self):
        return {}

    def acquire_test_slot(self):
        return contextlib.nullcontext(None)

    def latest_frame(self, camera_id):
        return None

    def attach_viewer(self, camera_id):
        pass

    def detach_viewer(self, camera_id):
        pass

    def shutdown(self):
        pass
