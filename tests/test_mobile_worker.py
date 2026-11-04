"""The drain thread and the console's view of the mobile link.

The worker owns two promises: a queued alert leaves the host within its poll interval, and the
console reports the queue honestly - including the case where nothing is configured.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from sqlalchemy import select

from conftest import TEST_PASSWORD
from watchtower import models as wt_models
from watchtower.mobile import outbox
from watchtower.mobile.models import NotificationOutbox, OutboxState
from watchtower.mobile.worker import OutboxWorker, build_evidence_reader
from watchtower.services.evidence import EvidenceStore

CLOUD = {
    "cloud_api_url": "https://tower.example.edu/api",
    "cloud_key_id": "mon-host-1",
    "cloud_key_secret": "a-service-secret-that-is-long-enough-32",
}


@pytest.fixture
def cloud(settings):
    return dataclasses.replace(settings, **CLOUD)


class RecordingSender:
    def __init__(self, status_code=200):
        self.status_code = status_code
        self.bodies: list[bytes] = []

    def __call__(self, url, body, headers):
        self.bodies.append(body)
        return outbox.SendResult(status=self.status_code)


def _worker(cloud_settings, session_factory, sender):
    forwarder = outbox.OutboxForwarder(cloud_settings, session_factory, sender=sender)
    return OutboxWorker(
        cloud_settings, session_factory, forwarder=forwarder, poll_seconds=0.01
    )


def _queue(db, session_factory, key="incident:1:created"):
    db.add(
        NotificationOutbox(
            idempotency_key=key,
            kind="incident.created",
            severity=wt_models.Severity.HIGH.value,
            title="Person at the gate",
            body="Candidate restricted-zone entry",
            payload={"idempotency_key": key},
            evidence_keys=[],
            state=OutboxState.QUEUED.value,
            next_retry_at=wt_models.utcnow() - dt.timedelta(seconds=1),
        )
    )
    db.flush()
    db.commit()


def test_a_worker_without_cloud_settings_never_sends(session_factory, settings):
    sender = RecordingSender()
    worker = OutboxWorker(
        settings,
        session_factory,
        forwarder=outbox.OutboxForwarder(settings, session_factory, sender=sender),
    )
    assert worker.enabled is False
    worker.run_once()
    assert sender.bodies == []
    assert worker.status()["state"] == "disabled"


def test_run_once_drains_a_queued_alert(db, session_factory, cloud):
    _queue(db, session_factory)
    worker = _worker(cloud, session_factory, RecordingSender())

    report = worker.run_once()

    assert report.delivered == 1
    db.expire_all()
    assert db.scalar(select(NotificationOutbox)).state == OutboxState.DELIVERED.value


def test_status_reports_the_queue_shape(db, session_factory, cloud):
    _queue(db, session_factory, "incident:1:created")
    _queue(db, session_factory, "incident:2:created")
    worker = _worker(cloud, session_factory, RecordingSender(status_code=500))

    worker.run_once()
    status = worker.status()

    assert status["enabled"] is True
    assert status["pending"] == 2, "both rows are still owed a send"
    assert status["delivered"] == 0
    assert status["dead"] == 0
    assert status["last_error"] is not None


def test_status_never_leaks_the_service_secret(db, session_factory, cloud):
    _queue(db, session_factory)
    worker = _worker(cloud, session_factory, RecordingSender(status_code=0))
    worker.run_once()
    assert cloud.cloud_key_secret not in str(worker.status())


def test_a_heartbeat_is_sent_once_per_interval(db, session_factory, cloud):
    sender = RecordingSender()
    worker = OutboxWorker(
        cloud,
        session_factory,
        forwarder=outbox.OutboxForwarder(cloud, session_factory, sender=sender),
        heartbeat_seconds=3600,
    )
    worker.run_once()
    worker.run_once()

    bodies = [item for item in sender.bodies if b"monitoring_host" in item]
    assert len(bodies) == 1, "the second pass is inside the heartbeat interval"


def test_the_thread_starts_and_stops_cleanly(session_factory, cloud):
    worker = _worker(cloud, session_factory, RecordingSender())
    worker.start()
    assert worker._thread is not None
    worker.start()  # idempotent
    worker.stop()
    assert worker._thread is None


def test_a_drain_exception_is_counted_not_raised(session_factory, cloud, monkeypatch):
    """A drain fault is swallowed by the cycle wrapper, so the thread cannot die on it."""
    worker = _worker(cloud, session_factory, RecordingSender())

    def explode():
        raise RuntimeError("socket closed")

    monkeypatch.setattr(worker._forwarder, "run_once", explode)

    assert worker._safe_cycle() is None
    assert worker._failures == 1


def test_the_thread_body_keeps_cycling_after_a_fault(session_factory, cloud, monkeypatch):
    worker = _worker(cloud, session_factory, RecordingSender())
    cycles: list[int] = []
    monkeypatch.setattr(worker, "_safe_cycle", lambda: cycles.append(1))

    # The stop event's wait() is both the pause and the exit condition; end the loop after 3.
    waits = iter([False, False, False, True])
    monkeypatch.setattr(worker._stop, "wait", lambda _timeout: next(waits))
    worker._run()

    assert cycles == [1, 1, 1]


def test_evidence_reader_returns_the_file_bytes(cloud, session_factory, db, factory):
    camera = factory.camera()
    incident = factory.incident(camera)
    db.commit()

    written = EvidenceStore(cloud, db).write_snapshot(
        camera.id, b"jpeg!!", incident_id=incident.id
    )
    db.commit()

    reader = build_evidence_reader(cloud, session_factory)
    assert reader(written.asset.storage_key) == b"jpeg!!"


def test_evidence_reader_reports_nothing_for_a_missing_key(cloud, session_factory):
    reader = build_evidence_reader(cloud, session_factory)
    assert reader("2026/01/01/never-written.jpg") is None


def test_evidence_reader_reports_nothing_when_the_bytes_are_gone(cloud, session_factory, db, factory):
    camera = factory.camera()
    db.commit()
    written = EvidenceStore(cloud, db).write_snapshot(camera.id, b"jpeg!!")
    db.commit()
    written.path.unlink()

    reader = build_evidence_reader(cloud, session_factory)
    assert reader(written.asset.storage_key) is None


# --------------------------------------------------------------------------- #
# The console's system panel
# --------------------------------------------------------------------------- #


def _system_panel(make_app, settings, factory, *, cloud: bool) -> dict:
    user = factory.user(
        username=f"console.{'cloud' if cloud else 'local'}", roles=("system_administrator",)
    )
    factory.session.commit()
    values = dataclasses.replace(settings, **CLOUD) if cloud else settings
    launched = make_app(values)
    client = launched.client
    headers = {"X-Watchtower-Client": "dashboard"}
    login = client.post(
        "/api/auth/login",
        json={"username": user.username, "password": TEST_PASSWORD},
        headers=headers,
    )
    assert login.status_code == 200, login.text
    response = client.get("/api/admin/system", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def test_the_system_panel_shows_the_mobile_link_as_disabled(make_app, settings, factory):
    body = _system_panel(make_app, settings, factory, cloud=False)
    assert body["mobile"]["state"] == "disabled"
    assert body["mobile"]["enabled"] is False


def test_the_system_panel_shows_a_configured_link(make_app, settings, factory):
    body = _system_panel(make_app, settings, factory, cloud=True)
    assert body["mobile"]["state"] == "connected"
    assert body["mobile"]["pending"] == 0
    assert CLOUD["cloud_key_secret"] not in str(body)
    assert CLOUD["cloud_api_url"] not in str(body["mobile"])
