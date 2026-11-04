"""The incident -> outbox hook: the alert exists because the incident exists.

These tests exercise `IncidentService` through the HTTP surface the dashboard uses, with cloud
settings present and absent, because the difference between those two configurations is the
whole point of the hook.
"""

from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from sqlalchemy import func, select

from watchtower import models as wt_models
from watchtower.mobile import alerts
from watchtower.mobile.models import NotificationOutbox, OutboxState  # noqa: F401
from watchtower.services.incidents import IncidentService


class _RecordingNotifications:
    """The dashboard notifier, reduced to what these tests must not crash on.

    The in-app notification path already has its own suite; here the question is only whether
    the mobile queue got its row, so this records the calls instead of making them.
    """

    def __init__(self):
        self.alerts: list[str] = []
        self.dispatches: list[str] = []

    def incident_alert(self, incident, *, kind, actor_label, note=None):
        self.alerts.append(kind)

    def dispatch(self, request, recipients):
        self.dispatches.append(request.kind)

    def recipients_for(self, permission, camera):
        return []


class _RecordingEvidence:
    def __init__(self):
        self.links: list[tuple[int, int]] = []

    def link_to_incident(self, *, detection_event_id: int, incident_id: int) -> int:
        self.links.append((detection_event_id, incident_id))
        return 1


def _service(db, settings=None):
    return IncidentService(db, _RecordingNotifications(), _RecordingEvidence(), settings)


@pytest.fixture
def cloud(settings):
    return dataclasses.replace(
        settings,
        cloud_api_url="https://tower.example.edu/api",
        cloud_key_id="mon-host-1",
        cloud_key_secret="a-service-secret-that-is-long-enough-32",
    )


def rows_in(db):
    return db.scalars(select(NotificationOutbox).order_by(NotificationOutbox.id)).all()


# --------------------------------------------------------------------------- #
# The hook itself
# --------------------------------------------------------------------------- #


def test_no_cloud_configuration_queues_nothing(db, factory, settings):
    incident = factory.incident()
    assert alerts.enqueue_incident_alert(settings, db, incident) == "disabled"
    assert rows_in(db) == []


def test_a_deployment_without_settings_queues_nothing(db, factory):
    incident = factory.incident()
    assert alerts.enqueue_incident_alert(None, db, incident) == "disabled"


def test_an_alert_is_queued_in_the_same_transaction_as_the_incident(
    db, factory, cloud, session_factory
):
    camera = factory.camera()
    event = factory.event(camera)
    service = _service(db, cloud)

    incident = service.create_from_event(event, camera, factory.principal(factory.user()))
    # No commit yet: the queue row already exists inside the caller's transaction.
    queued = rows_in(db)
    assert [row.kind for row in queued] == ["incident.created"]
    assert queued[0].incident_id == incident.id

    db.commit()
    with session_factory() as check:
        assert check.scalar(select(func.count()).select_from(NotificationOutbox)) == 1


def test_rolling_the_incident_back_removes_the_alert_too(db, factory, cloud):
    camera = factory.camera()
    event = factory.event(camera)
    service = _service(db, cloud)
    principal = factory.principal(factory.user())

    service.create_from_event(event, camera, principal)
    db.rollback()

    assert rows_in(db) == []


def test_the_queued_alert_lists_the_evidence_that_was_just_linked(db, factory, cloud):
    camera = factory.camera()
    event = factory.event(camera)
    incident = factory.incident(camera)
    now = wt_models.utcnow()
    for offset, key in ((9, "evidence/second.jpg"), (1, "evidence/first.jpg")):
        db.add(
            wt_models.EvidenceAsset(
                incident_id=incident.id,
                camera_id=camera.id,
                detection_event_id=event.id,
                kind="snapshot",
                filename=key.split("/")[-1],
                storage_key=key,
                content_type="image/jpeg",
                byte_size=11,
                sha256="e" * 64,
                captured_at=now + dt.timedelta(seconds=offset),
            )
        )
    db.flush()

    service = _service(db, cloud)
    service._queue_mobile_alert(incident, kind="created", event=event)

    row = rows_in(db)[0]
    assert row.evidence_keys == ["evidence/first.jpg", "evidence/second.jpg"], "capture order"
    assert row.payload["evidence_keys"] == row.evidence_keys


def test_deleted_evidence_is_not_offered_to_the_cloud(db, factory, cloud):
    camera = factory.camera()
    incident = factory.incident(camera)
    db.add(
        wt_models.EvidenceAsset(
            incident_id=incident.id,
            camera_id=camera.id,
            kind="snapshot",
            filename="gone.jpg",
            storage_key="evidence/gone.jpg",
            content_type="image/jpeg",
            byte_size=11,
            sha256="f" * 64,
            deleted_at=wt_models.utcnow(),
        )
    )
    db.flush()

    IncidentService(db, _RecordingNotifications(), _RecordingEvidence(), cloud)._queue_mobile_alert(
        incident, kind="created"
    )
    assert rows_in(db)[0].evidence_keys == []


@pytest.mark.parametrize("kind", ["created", "assigned", "escalated", "resolved"])
def test_each_transition_gets_its_own_queue_row(db, factory, cloud, kind):
    incident = factory.incident()
    alerts.enqueue_incident_alert(cloud, db, incident, kind=kind)
    row = rows_in(db)[0]
    assert row.kind == f"incident.{kind}"
    assert row.idempotency_key == f"incident:{incident.id}:{kind}"


def test_an_unknown_kind_is_refused_rather_than_forwarded(db, factory, cloud):
    incident = factory.incident()
    assert (
        alerts.enqueue_incident_alert(cloud, db, incident, kind="deleted") == "rejected"
    )
    assert rows_in(db) == []


def test_a_cloud_payload_never_contains_the_service_secret(db, factory, cloud):
    incident = factory.incident()
    alerts.enqueue_incident_alert(cloud, db, incident)
    import json

    assert cloud.cloud_key_secret not in json.dumps(rows_in(db)[0].payload)


def test_repeating_the_same_transition_does_not_queue_twice(db, factory, cloud):
    incident = factory.incident()
    assert alerts.enqueue_incident_alert(cloud, db, incident) == "queued"
    assert alerts.enqueue_incident_alert(cloud, db, incident) == "duplicate"
    assert len(rows_in(db)) == 1


# --------------------------------------------------------------------------- #
# Every service transition the console can perform
# --------------------------------------------------------------------------- #


def test_the_workflow_transitions_each_queue_exactly_one_alert(db, factory, cloud):
    camera = factory.camera()
    supervisor = factory.user(roles=("security_supervisor",))
    principal = factory.principal(supervisor)
    service = _service(db, cloud)

    created = service.create_manual(
        principal,
        title="Gate left open",
        category="physical_alteration",
        severity="high",
        summary="Door found unlatched",
        camera_id=camera.id,
        campus_location=None,
        occurred_at=None,
    )
    service.assign(created.id, principal, assignee_id=supervisor.id)
    service.escalate(created.id, principal, to_user_id=supervisor.id, note="call the CGS")
    service.resolve(created.id, principal, outcome="secured", resolution="Door latched")
    db.commit()

    kinds = [row.kind for row in rows_in(db)]
    assert kinds == [
        "incident.created",
        "incident.assigned",
        "incident.escalated",
        "incident.resolved",
    ]


def test_a_transition_without_cloud_settings_leaves_the_queue_empty(db, factory, settings):
    camera = factory.camera()
    supervisor = factory.user(roles=("security_supervisor",))
    principal = factory.principal(supervisor)
    service = _service(db, settings)

    created = service.create_manual(
        principal,
        title="Gate left open",
        category="physical_alteration",
        severity="high",
        summary=None,
        camera_id=camera.id,
        campus_location=None,
        occurred_at=None,
    )
    service.assign(created.id, principal, assignee_id=supervisor.id)
    assert rows_in(db) == []
