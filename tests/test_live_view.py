"""Live-view delivery (proposal section 9).

The browser must only ever see a server-issued token and JPEG bytes. Everything here runs
against the in-process `FakeSupervisor`, which publishes frames on demand: no camera, no
network, no decoder.
"""

from __future__ import annotations

import time

import pytest
from sqlalchemy import select

from watchtower import models as wt_models
from watchtower.ingest.worker import StreamStats

JPEG = b"\xff\xd8\xff\xe0tiny-jpeg\xff\xd9"


def running_camera(
    factory,
    *,
    status: str = wt_models.CameraStatus.ONLINE.value,
    desired_state: str = "running",
    **overrides,
):
    camera = factory.camera(
        status=status,
        desired_state=desired_state,
        is_registered=True,
        **overrides,
    )
    factory.session.commit()
    return camera


def open_session(client, camera_id: str):
    response = client.post("/api/live/sessions", json={"camera_id": str(camera_id)})
    assert response.status_code == 201, response.text
    return response.json()["live_session"]


# --------------------------------------------------------------------------- #
# Authorization is what opens a session
# --------------------------------------------------------------------------- #


def test_opening_live_view_starts_the_managed_stream_it_reuses_later(
    launched, supervisor, factory, actor
):
    camera = running_camera(factory)
    viewer = actor("security_operator")

    token = open_session(viewer.client, camera.id)

    assert supervisor.ensure_calls == [str(camera.id)]
    assert supervisor.stats(str(camera.id)).state == "starting"
    # a second session for the same camera must not open a second RTSP connection
    open_session(viewer.client, camera.id)
    assert supervisor.ensure_calls == [str(camera.id)]
    assert len(supervisor.stats_by_camera) == 1
    assert token


def test_a_role_without_live_rights_cannot_open_a_session(launched, factory, actor):
    camera = running_camera(factory)
    auditor = actor("auditor_read_only")

    response = auditor.client.post("/api/live/sessions", json={"camera_id": str(camera.id)})

    assert response.status_code == 403


def test_a_camera_outside_the_viewers_group_is_invisible(launched, factory, actor):
    inside = running_camera(factory, code="CAM-IN")
    outside = running_camera(factory, code="CAM-OUT")
    group = factory.group(code="GATE")
    for camera in (inside, outside):
        camera.camera_group_id = group.id if camera is inside else None
    factory.session.commit()

    scoped = actor("security_supervisor", group_id=group.id)

    assert scoped.client.post("/api/live/sessions", json={"camera_id": str(inside.id)}).status_code == 201
    out = scoped.client.post("/api/live/sessions", json={"camera_id": str(outside.id)})
    assert out.status_code == 403


@pytest.mark.parametrize(
    ("status_value", "desired_state", "code"),
    [
        (wt_models.CameraStatus.DISABLED.value, "stopped", "camera_disabled"),
        (wt_models.CameraStatus.PENDING_SETUP.value, "stopped", "not_activated"),
    ],
)
def test_a_camera_that_is_not_running_is_refused_with_a_reason(
    launched, factory, actor, status_value, desired_state, code
):
    camera = running_camera(factory, status=status_value, desired_state=desired_state)
    viewer = actor("security_operator")

    response = viewer.client.post("/api/live/sessions", json={"camera_id": str(camera.id)})

    assert response.status_code == 409
    assert response.json()["detail"]["code"] == code


def test_a_malformed_camera_id_is_not_an_existence_oracle(launched, actor):
    response = actor("security_operator").client.post(
        "/api/live/sessions", json={"camera_id": "not-a-uuid"}
    )

    assert response.status_code == 404


# --------------------------------------------------------------------------- #
# Delivery
# --------------------------------------------------------------------------- #


def test_the_first_viewer_waits_for_a_frame_instead_of_inventing_one(
    app, supervisor, factory, actor
):
    camera = running_camera(factory)
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)

    empty = viewer.client.get(f"/api/live/sessions/{token}/snapshot")

    assert empty.status_code == 503
    assert empty.json()["detail"]["code"] == "no_frame"
    assert app.state.container.live_sessions[token].camera_id == str(camera.id)


def test_the_snapshot_returns_only_jpeg_bytes(app, supervisor, factory, actor):
    camera = running_camera(factory)
    supervisor.publish_frame(str(camera.id), payload=JPEG, fps=11.5)
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)

    response = viewer.client.get(f"/api/live/sessions/{token}/snapshot")

    assert response.status_code == 200
    assert response.content == JPEG
    assert response.headers["content-type"] == "image/jpeg"
    assert response.headers["cache-control"] == "no-store"


def test_the_relay_streams_the_newest_frame_and_detaches_when_the_viewer_leaves(
    app, supervisor, factory, actor
):
    camera = running_camera(factory)
    supervisor.publish_frame(str(camera.id), payload=JPEG, fps=12.0)
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)

    with viewer.client.client.stream("GET", f"/api/live/sessions/{token}/mjpeg") as response:
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("multipart/x-mixed-replace")
        assert response.headers["x-frame-options"] == "DENY"
        first_part = next(response.iter_raw())
        assert supervisor.viewers(str(camera.id)) == 1

    assert b"--watchtower-frame" in first_part
    assert JPEG in first_part
    deadline = time.time() + 2.0
    while supervisor.viewers(str(camera.id)) != 0 and time.time() < deadline:
        time.sleep(0.02)
    assert supervisor.viewers(str(camera.id)) == 0


def test_the_view_state_follows_the_worker_not_the_wish(
    app, supervisor, factory, actor
):
    camera = running_camera(factory)
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)
    session = app.state.container.live_sessions[token]
    session.camera_id = str(camera.id)

    expected = {
        "starting": "loading",
        "connecting": "loading",
        "online": "live",
        "reconnecting": "reconnecting",
        "failed": "offline",
        "stopped": "offline",
    }
    for worker_state, view_state in expected.items():
        supervisor.stats_by_camera[str(camera.id)] = StreamStats(
            camera_id=str(camera.id), state=worker_state, last_frame_at=time.time()
        )
        response = viewer.client.get(f"/api/live/sessions/{token}/state")
        assert response.status_code == 200, response.text
        assert response.json()["view_state"] == view_state, worker_state


def test_the_state_response_carries_no_worker_error_text(app, supervisor, factory, actor):
    """`last_error` can quote a driver message containing the credential-bearing URL."""
    camera = running_camera(factory)
    supervisor.stats_by_camera[str(camera.id)] = StreamStats(
        camera_id=str(camera.id),
        state="reconnecting",
        last_frame_at=time.time(),
        last_error="rtsp://admin:sup3r-secret-pw@10.20.0.5/cam/realmonitor refused",
    )
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)

    body = viewer.client.get(f"/api/live/sessions/{token}/state").text

    assert "sup3r-secret-pw" not in body
    assert "rtsp://" not in body
    assert "connection address withheld" in body
    assert "reconnecting" in body


# --------------------------------------------------------------------------- #
# Ownership and release
# --------------------------------------------------------------------------- #


def test_a_token_issued_to_one_viewer_is_not_a_pass_for_another(
    launched, supervisor, factory, actor
):
    camera = running_camera(factory)
    supervisor.publish_frame(str(camera.id), payload=JPEG)
    owner = actor("security_operator", username="owner")
    intruder = actor("security_operator", username="intruder")
    token = open_session(owner.client, camera.id)

    for path in (f"/api/live/sessions/{token}/snapshot", f"/api/live/sessions/{token}/state"):
        assert intruder.client.get(path).status_code == 403
    assert intruder.client.delete(f"/api/live/sessions/{token}").status_code == 403


def test_a_released_session_is_gone_and_the_release_is_audited(
    app, launched, supervisor, factory, actor, db
):
    camera = running_camera(factory)
    supervisor.publish_frame(str(camera.id), payload=JPEG)
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)

    released = viewer.client.delete(f"/api/live/sessions/{token}")
    assert released.status_code == 200
    assert released.json() == {"status": "released"}

    assert viewer.client.get(f"/api/live/sessions/{token}/snapshot").status_code == 410
    assert supervisor.viewers(str(camera.id)) == 0
    # releasing twice is not an error and does not invent a second audit row
    assert viewer.client.delete(f"/api/live/sessions/{token}").json() == {"status": "already_released"}

    db.commit()
    actions = db.scalars(
        select(wt_models.AuditLog.action).where(wt_models.AuditLog.action.like("camera.live_view%"))
    ).all()
    assert sorted(actions) == ["camera.live_view.start", "camera.live_view.stop"]


def test_live_view_starts_and_stops_are_audited_without_the_token_being_a_secret(
    app, factory, actor, db
):
    camera = running_camera(factory)
    viewer = actor("security_operator")
    token = open_session(viewer.client, camera.id)
    viewer.client.delete(f"/api/live/sessions/{token}")

    db.commit()
    rows = db.scalars(
        select(wt_models.AuditLog).where(wt_models.AuditLog.action == "camera.live_view.start")
    ).all()
    assert len(rows) == 1
    assert rows[0].details["live_session"] == token
    assert rows[0].details["camera_code"] == camera.code
    assert str(camera.id) == rows[0].object_id
