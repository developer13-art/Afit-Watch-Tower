"""The transactional outbox: enqueue in the caller's transaction, drain with retries.

These tests drive the real SQLite harness and a fake HTTP sender. No test here opens a
network connection, and no test lets an alert be sent without its outbox row existing first.
"""

from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import json

import pytest
from sqlalchemy import func, select
from sqlalchemy.exc import SQLAlchemyError

from watchtower import models as wt_models
from watchtower.mobile import outbox
from watchtower.mobile.models import NotificationOutbox, OutboxState

SECRET = "sup3r-secret-pw"
CLOUD = {
    "cloud_api_url": "https://tower.example.edu/api",
    "cloud_key_id": "mon-host-1",
    "cloud_key_secret": "a-service-secret-that-is-long-enough-32",
}


@pytest.fixture
def cloud_settings(settings):
    return dataclasses.replace(settings, **CLOUD)


@pytest.fixture
def row_for():
    def _make(**overrides):
        values = {
            "idempotency_key": "incident:1:created",
            "kind": "incident.created",
            "severity": wt_models.Severity.HIGH.value,
            "title": "Person at the gate",
            "body": "Candidate restricted-zone entry",
            "payload": {"hello": "world"},
            "evidence_keys": [],
            "state": OutboxState.QUEUED.value,
            "next_retry_at": wt_models.utcnow() - dt.timedelta(seconds=1),
        }
        values.update(overrides)
        return NotificationOutbox(**values)

    return _make


def add_and_commit(db, *rows):
    db.add_all(rows)
    db.flush()
    db.commit()


def _instant(value: dt.datetime) -> dt.datetime:
    """SQLite hands back naive datetimes for a timestamptz column; PostgreSQL does not."""
    return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value


# --------------------------------------------------------------------------- #
# Intent construction
# --------------------------------------------------------------------------- #


def test_intent_for_a_manual_incident_carries_the_contract_fields(factory):
    incident = factory.incident(title="Gate alarm raised by operator", severity="critical")
    intent = outbox.intent_for_incident(incident)

    assert intent.idempotency_key == outbox.incident_key(incident_id=incident.id)
    assert intent.kind == "incident.created"
    assert intent.severity == "critical"
    assert intent.payload["incident"]["detection_source"] == "manual"
    assert intent.payload["incident"]["reference"] == incident.reference
    assert intent.payload["incident"]["id"] == incident.id


def test_intent_for_an_ai_finding_is_labelled_a_candidate(factory):
    camera = factory.camera()
    event = factory.event(camera)
    incident = factory.incident(camera)
    intent = outbox.intent_for_incident(incident, camera=camera, event=event)

    assert intent.payload["incident"]["detection_source"] == "ai_candidate"
    assert intent.payload["incident"]["camera_id"] == str(camera.id)
    assert intent.event_id == event.id


def test_the_intent_never_contains_a_camera_credential(factory):
    """Section 13: the payload is display data, not connection data."""
    camera = factory.camera(password=SECRET)
    intent = outbox.intent_for_incident(factory.incident(camera), camera=camera)
    blob = json.dumps(intent.payload) + intent.body + intent.title
    assert SECRET not in blob
    assert "realmonitor" not in blob
    assert "rtsp://" not in blob


# --------------------------------------------------------------------------- #
# Enqueue
# --------------------------------------------------------------------------- #


def test_enqueue_writes_the_row_and_is_idempotent(db, factory):
    intent = outbox.intent_for_incident(factory.incident())

    first = outbox.enqueue(db, intent)
    second = outbox.enqueue(db, intent)

    assert first.id == second.id, "the same key must not produce a second push"
    assert db.scalar(select(func.count()).select_from(NotificationOutbox)) == 1


def test_enqueue_leaves_the_commit_to_the_caller(db, session_factory, factory):
    """The outbox row is only durable when the incident it describes is durable."""
    incident = factory.incident()
    db.commit()
    outbox.enqueue(db, outbox.intent_for_incident(incident))
    db.rollback()

    with session_factory() as check:
        assert check.scalar(select(NotificationOutbox)) is None
        assert check.scalar(select(wt_models.Incident).limit(1)) is not None


def test_enqueue_or_spool_distinguishes_queued_from_duplicate(db, settings, factory):
    intent = outbox.intent_for_incident(factory.incident())
    assert outbox.enqueue_or_spool(settings, db, intent) == "queued"
    assert outbox.enqueue_or_spool(settings, db, intent) == "duplicate"


def test_enqueue_or_spool_falls_back_to_the_spool_when_the_database_is_down(settings):
    intent = outbox.EnqueueIntent(
        kind="incident.created",
        severity=wt_models.Severity.HIGH.value,
        title="Gate",
        body="Person at the gate",
        idempotency_key="incident:4242:created",
        payload={},
    )

    class BrokenSession:
        def scalar(self, *_a, **_k):
            raise SQLAlchemyError("psycopg: could not connect to server")

    assert outbox.enqueue_or_spool(settings, BrokenSession(), intent) == "spooled"
    spooled = outbox.Spool(settings.spool_dir).pending()
    assert [item.idempotency_key for item in spooled] == [intent.idempotency_key]


# --------------------------------------------------------------------------- #
# Spool
# --------------------------------------------------------------------------- #


def _intent(key: str) -> outbox.EnqueueIntent:
    return outbox.EnqueueIntent(
        kind="incident.created",
        severity="high",
        title="Gate",
        body="Person at the gate",
        idempotency_key=key,
        payload={"incident": {"id": 1}},
    )


def test_spool_deduplicates_and_skips_a_torn_line(settings):
    spool = outbox.Spool(settings.spool_dir)
    spool.append(_intent("incident:1:created"))
    spool.append(_intent("incident:1:created"))
    with spool.path.open("a", encoding="utf-8") as handle:
        handle.write('{"kind": "incident.created", "idem')  # a crash mid-write

    assert [item.idempotency_key for item in spool.pending()] == ["incident:1:created"]


def test_spool_replay_moves_rows_into_the_outbox(settings, db):
    spool = outbox.Spool(settings.spool_dir)
    spool.append(_intent("incident:7:created"))

    assert spool.replay(db) == 1
    assert db.scalar(select(NotificationOutbox)).idempotency_key == "incident:7:created"
    assert spool.pending() == []


def test_spool_round_trips_the_payload_exactly():
    intent = outbox.EnqueueIntent(
        kind="incident.created",
        severity="high",
        title="Gate",
        body="Person at the gate",
        idempotency_key="incident:9:created",
        payload={"incident": {"id": 9}},
        incident_id=9,
        evidence_keys=["evidence/a.jpg"],
    )
    assert outbox.EnqueueIntent.from_json(intent.as_json()) == intent


# --------------------------------------------------------------------------- #
# Claiming, retrying, dying
# --------------------------------------------------------------------------- #


def test_claim_due_takes_only_rows_that_are_ready(db, row_for):
    due = row_for(idempotency_key="incident:1:created")
    later = row_for(
        idempotency_key="incident:2:created",
        next_retry_at=wt_models.utcnow() + dt.timedelta(minutes=5),
    )
    db.add_all([due, later])
    db.flush()

    claimed = outbox.claim_due(db, now=wt_models.utcnow(), limit=10)

    assert [row.idempotency_key for row in claimed] == ["incident:1:created"]
    assert due.state == OutboxState.PROCESSING.value


def test_claim_does_not_steal_a_row_another_worker_is_sending(db, row_for):
    live = row_for(idempotency_key="incident:3:created", state=OutboxState.PROCESSING.value)
    live.processing_at = wt_models.utcnow()
    db.add(live)
    db.flush()

    assert outbox.claim_due(db, now=wt_models.utcnow(), limit=10) == []


def test_a_stale_processing_row_is_reclaimed(db, row_for):
    abandoned = row_for(idempotency_key="incident:4:created", state=OutboxState.PROCESSING.value)
    abandoned.processing_at = wt_models.utcnow() - dt.timedelta(
        seconds=outbox.STALE_PROCESSING_SECONDS + 60
    )
    db.add(abandoned)
    db.flush()

    claimed = outbox.claim_due(db, now=wt_models.utcnow(), limit=10)
    assert [row.idempotency_key for row in claimed] == ["incident:4:created"]


def test_backoff_follows_the_configured_table(settings):
    table = settings.outbox_backoff_seconds
    delays = [outbox.backoff_for(settings, attempt).total_seconds() for attempt in range(1, len(table) + 3)]
    assert delays[:3] == [5, 15, 60]
    assert delays[-1] == table[-1], "the last entry is the ceiling, not an index error"


def test_a_row_dies_after_the_configured_attempts(db, row_for, settings):
    row = row_for(idempotency_key="incident:5:created")
    db.add(row)
    db.flush()
    row.attempts = settings.outbox_max_attempts - 1

    outbox.mark_retry(db, settings, row, error="connection refused", now=wt_models.utcnow())

    assert row.state == OutboxState.DEAD.value
    assert row.completed_at is not None


def test_the_last_error_is_redacted(db, row_for, settings):
    """An RTSP URL in a transport error must not survive into a database column."""
    row = row_for(idempotency_key="incident:6:created")
    db.add(row)
    db.flush()

    outbox.mark_retry(
        db,
        settings,
        row,
        error=f"rtsp://admin:{SECRET}@10.20.0.5:554/cam/realmonitor failed",
        now=wt_models.utcnow(),
    )

    assert SECRET not in row.last_error
    assert "***" in row.last_error


# --------------------------------------------------------------------------- #
# Forwarder
# --------------------------------------------------------------------------- #


class RecordingSender:
    """Stands in for `urllib_sender`; records the exact bytes that would have gone out."""

    def __init__(self, *results):
        self.results = list(results)
        self.calls: list[tuple[str, dict, bytes]] = []

    def __call__(self, url, body, headers):
        self.calls.append((url, headers, body))
        if self.results:
            result = self.results.pop(0)
            return result if isinstance(result, outbox.SendResult) else outbox.SendResult(status=result)
        return outbox.SendResult(status=200)


def _forwarder(cloud_settings, session_factory, sender):
    return outbox.OutboxForwarder(
        cloud_settings, session_factory, sender=sender, evidence_reader=lambda _key: b"jpeg-bytes"
    )


def test_forwarder_is_disabled_without_cloud_configuration(settings, session_factory):
    forwarder = outbox.OutboxForwarder(settings, session_factory, sender=RecordingSender())
    assert forwarder.enabled is False
    assert forwarder.run_once().attempted == 0


def test_run_once_delivers_a_signed_request(db, session_factory, cloud_settings, row_for):
    sender = RecordingSender()
    add_and_commit(db, row_for(idempotency_key="incident:11:created"))

    report = _forwarder(cloud_settings, session_factory, sender).run_once()

    assert report.delivered == 1
    url, headers, body = sender.calls[0]
    assert url == "https://tower.example.edu/api/api/v1/ingest/incident"
    assert headers["x-watchtower-key-id"] == "mon-host-1"
    assert json.loads(body)["idempotency_key"] == "incident:11:created"
    assert headers["authorization"].startswith("WATCHTOWER-HMAC-SHA256 mon-host-1:")


def test_a_server_error_is_retried_with_backoff(db, session_factory, cloud_settings, row_for):
    sender = RecordingSender(outbox.SendResult(status=503, error="HTTP 503"))
    add_and_commit(db, row_for(idempotency_key="incident:12:created"))

    report = _forwarder(cloud_settings, session_factory, sender).run_once()

    assert (report.retrying, report.delivered) == (1, 0)
    db.expire_all()
    row = db.scalar(select(NotificationOutbox))
    assert row.state == OutboxState.FAILED.value
    assert row.attempts == 1
    assert _instant(row.next_retry_at) > wt_models.utcnow()


def test_a_permanent_status_stops_retrying_for_a_day(db, session_factory, cloud_settings, row_for):
    sender = RecordingSender(outbox.SendResult(status=422, error="HTTP 422"))
    add_and_commit(db, row_for(idempotency_key="incident:13:created"))

    report = _forwarder(cloud_settings, session_factory, sender).run_once()

    assert report.permanent_failures == 1
    db.expire_all()
    row = db.scalar(select(NotificationOutbox))
    assert row.state == OutboxState.FAILED.value
    assert _instant(row.next_retry_at) > wt_models.utcnow() + dt.timedelta(hours=12)


def test_evidence_bytes_are_relayed_after_the_alert(
    db, session_factory, cloud_settings, row_for, factory
):
    camera = factory.camera()
    asset = wt_models.EvidenceAsset(
        incident_id=factory.incident(camera).id,
        camera_id=camera.id,
        kind="snapshot",
        filename="a.jpg",
        storage_key="evidence/a.jpg",
        content_type="image/jpeg",
        byte_size=9,
        sha256="c" * 64,
    )
    add_and_commit(
        db, asset, row_for(idempotency_key="incident:14:created", evidence_keys=["evidence/a.jpg"])
    )

    sender = RecordingSender()
    report = _forwarder(cloud_settings, session_factory, sender).run_once()

    assert report.evidence_uploaded == 1
    url, _, body = sender.calls[1]
    assert url.endswith(f"/api/v1/ingest/evidence/{asset.id}")
    payload = json.loads(body)
    assert payload["sha256"] == "c" * 64
    assert payload["data_base64"] == base64.b64encode(b"jpeg-bytes").decode()
    assert payload["byte_size"] == len(b"jpeg-bytes")


def test_a_deleted_asset_is_not_relayed(db, session_factory, cloud_settings, row_for, factory):
    camera = factory.camera()
    asset = wt_models.EvidenceAsset(
        incident_id=factory.incident(camera).id,
        camera_id=camera.id,
        kind="snapshot",
        filename="gone.jpg",
        storage_key="evidence/gone.jpg",
        content_type="image/jpeg",
        byte_size=9,
        sha256="d" * 64,
        deleted_at=wt_models.utcnow(),
    )
    add_and_commit(
        db,
        asset,
        row_for(idempotency_key="incident:15:created", evidence_keys=["evidence/gone.jpg"]),
    )

    sender = RecordingSender()
    report = _forwarder(cloud_settings, session_factory, sender).run_once()

    assert report.evidence_uploaded == 0
    assert len(sender.calls) == 1, "only the alert, no upload attempt"


def test_heartbeat_reports_the_queue_shape(db, session_factory, cloud_settings, row_for):
    add_and_commit(
        db,
        row_for(idempotency_key="incident:16:created"),
        row_for(idempotency_key="incident:17:created", state=OutboxState.DEAD.value),
    )

    sender = RecordingSender()
    result = _forwarder(cloud_settings, session_factory, sender).send_heartbeat(
        monitoring_host="tower-host-1", app_version="1.4.0"
    )

    assert result is not None
    payload = json.loads(sender.calls[0][2])
    assert payload["monitoring_host"] == "tower-host-1"
    assert payload["outbox_pending"] == 1
    assert payload["outbox_failed"] == 1


def test_a_transport_failure_does_not_lose_the_row(db, session_factory, cloud_settings, row_for):
    sender = RecordingSender(outbox.SendResult(status=0, error="timed out"))
    add_and_commit(db, row_for(idempotency_key="incident:18:created"))

    report = _forwarder(cloud_settings, session_factory, sender).run_once()

    assert report.retrying == 1
    db.expire_all()
    assert db.scalar(select(NotificationOutbox)).state == OutboxState.FAILED.value


def test_pending_count_and_summary_agree(db, session_factory, row_for):
    add_and_commit(
        db,
        row_for(idempotency_key="incident:19:created"),
        row_for(idempotency_key="incident:20:created", state=OutboxState.DELIVERED.value),
    )

    with session_factory() as session:
        assert outbox.pending_count(session) == 1
        summary = outbox.queue_summary(session)
        assert summary[OutboxState.QUEUED.value] == 1
        assert summary[OutboxState.DELIVERED.value] == 1
        assert sum(summary.values()) == 2


def test_run_once_is_a_no_op_when_nothing_is_due(session_factory, cloud_settings):
    forwarder = _forwarder(cloud_settings, session_factory, RecordingSender())
    for _ in range(3):
        assert forwarder.run_once().attempted == 0


def test_a_malformed_spool_line_does_not_wedge_the_drain(db, session_factory, cloud_settings, row_for):
    forwarder = _forwarder(cloud_settings, session_factory, RecordingSender())
    forwarder.spool.directory.mkdir(parents=True, exist_ok=True)
    forwarder.spool.path.write_text(
        json.dumps({"kind": "incident.created"}) + "\n",  # no idempotency key at all
        encoding="utf-8",
    )
    add_and_commit(db, row_for(idempotency_key="incident:22:created"))

    report = forwarder.run_once()

    assert report.attempted == 1
    assert report.spooled_replayed == 0
