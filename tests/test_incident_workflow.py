"""The incident workflow (proposal section 12).

Every transition must leave an `incident_actions` row and an audit row, and every transition
must be reachable through the HTTP API the dashboard actually uses. Reopening is asserted as
POST-only: a state change on a GET can be triggered by a crawler or a prefetch.
"""

from __future__ import annotations

from sqlalchemy import select

from watchtower import models as wt_models
from watchtower.models import IncidentStatus

SUPERVISOR = "security_supervisor"
OPERATOR = "security_operator"


def create_incident(client, camera, **overrides):
    payload = {
        "title": "Person loitering at the main gate",
        "category": "loitering",
        "severity": "medium",
        "camera_id": str(camera.id),
        "campus_location": camera.campus_location,
    }
    payload.update(overrides)
    response = client.post("/api/incidents", json=payload)
    assert response.status_code == 201, response.text
    return response.json()["incident"]


def actions_for(db, incident_id: int) -> list[str]:
    db.commit()
    return list(
        db.scalars(
            select(wt_models.IncidentAction.action)
            .where(wt_models.IncidentAction.incident_id == incident_id)
            .order_by(wt_models.IncidentAction.id)
        ).all()
    )


def audits_for(db, action: str) -> list[dict]:
    db.commit()
    return [
        row.details
        for row in db.scalars(select(wt_models.AuditLog).where(wt_models.AuditLog.action == action)).all()
    ]


# --------------------------------------------------------------------------- #
# Creation and the happy path
# --------------------------------------------------------------------------- #


def test_a_manual_incident_gets_a_reference_and_starts_open(launched, factory, actor, db):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)

    incident = create_incident(supervisor.client, camera)

    assert incident["status"] == wt_models.IncidentStatus.OPEN.value
    assert incident["reference"]
    assert incident["camera_id"] == str(camera.id)
    assert [action["action"] for action in incident["actions"]] == ["created"]
    assert audits_for(db, "incident.create")


def test_assign_escalate_note_resolve_each_record_an_action(launched, factory, actor, db):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    assignee = factory.user(username="responder", roles=(OPERATOR,))
    factory.session.commit()

    incident = create_incident(supervisor.client, camera)
    incident_id = incident["id"]

    assigned = supervisor.client.post(
        f"/api/incidents/{incident_id}/assign", json={"assignee_id": assignee.id}
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["incident"]["assigned_to"] == assignee.id

    escalated = supervisor.client.post(
        f"/api/incidents/{incident_id}/escalate",
        json={"to_user_id": supervisor.user.id, "note": "Gate response team"},
    )
    assert escalated.status_code == 200, escalated.text
    assert escalated.json()["incident"]["escalated_to"] == supervisor.user.id

    noted = supervisor.client.post(
        f"/api/incidents/{incident_id}/notes", json={"text": "Operator called the gate post."}
    )
    assert noted.status_code == 200, noted.text

    resolved = supervisor.client.post(
        f"/api/incidents/{incident_id}/resolve",
        json={"outcome": "handled_on_site", "resolution": "Person left after being challenged."},
    )
    assert resolved.status_code == 200, resolved.text
    body = resolved.json()["incident"]
    assert body["status"] == IncidentStatus.RESOLVED.value
    assert body["outcome"] == "handled_on_site"
    assert body["resolved_at"] is not None

    assert actions_for(db, incident_id) == [
        "created",
        "assigned",
        "escalated",
        "investigation_note",
        "resolved",
    ]


def test_a_resolved_incident_notifies_the_reviewers(launched, factory, actor, db):
    """Section 12: the resolution is announced, not silently written."""
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    incident = create_incident(supervisor.client, camera)

    supervisor.client.post(
        f"/api/incidents/{incident['id']}/resolve",
        json={"outcome": "false_alarm", "resolution": "Contractor working late."},
    )

    db.commit()
    rows = db.scalars(
        select(wt_models.Notification)
        .where(wt_models.Notification.incident_id == incident["id"])
        .order_by(wt_models.Notification.id)
    ).all()
    # opening an incident and resolving it are both announced (section 12)
    assert [row.kind for row in rows] == ["incident.created", "incident.resolved"]
    resolved = rows[1]
    assert resolved.state == wt_models.NotificationState.DELIVERED.value
    assert "Contractor working late." in resolved.body


def test_marking_a_false_positive_changes_the_status_not_just_a_flag(
    launched, factory, actor, db
):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    incident = create_incident(supervisor.client, camera)

    resolved = supervisor.client.post(
        f"/api/incidents/{incident['id']}/resolve",
        json={
            "outcome": "false_positive",
            "resolution": "A dog crossed the zone.",
            "false_positive": True,
        },
    )

    assert resolved.json()["incident"]["status"] == IncidentStatus.FALSE_POSITIVE.value
    assert audits_for(db, "incident.resolve")[0]["false_positive"] is True


# --------------------------------------------------------------------------- #
# Reopening
# --------------------------------------------------------------------------- #


def test_reopen_is_a_post_and_only_a_ended_incident_can_be_reopened(
    launched, factory, actor, db
):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    incident = create_incident(supervisor.client, camera)

    still_open = supervisor.client.post(
        f"/api/incidents/{incident['id']}/reopen", json={"reason": "Same person returned"}
    )
    assert still_open.status_code == 409
    assert still_open.json()["detail"]["code"] == "not_resolved"

    supervisor.client.post(
        f"/api/incidents/{incident['id']}/resolve",
        json={"outcome": "handled", "resolution": "Escorted off the premises."},
    )
    reopened = supervisor.client.post(
        f"/api/incidents/{incident['id']}/reopen", json={"reason": "Same person returned"}
    )

    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["incident"]["status"] == IncidentStatus.INVESTIGATING.value
    assert "reopened" in actions_for(db, incident["id"])
    assert audits_for(db, "incident.reopen")[0]["reason"] == "Same person returned"


def test_a_get_cannot_reopen_an_incident(launched, factory, actor):
    """A crawler, a prefetch or an <img> tag must not be able to change incident state."""
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    incident = create_incident(supervisor.client, camera)

    response = supervisor.client.get(
        f"/api/incidents/{incident['id']}/reopen?reason=from-a-crawler"
    )

    assert response.status_code == 405


def test_reopen_requires_a_reason(launched, factory, actor):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    incident = create_incident(supervisor.client, camera)
    supervisor.client.post(
        f"/api/incidents/{incident['id']}/resolve",
        json={"outcome": "handled", "resolution": "Escorted off the premises."},
    )

    short = supervisor.client.post(f"/api/incidents/{incident['id']}/reopen", json={"reason": "x"})

    assert short.status_code == 422


# --------------------------------------------------------------------------- #
# Candidate-event review (section 12: AI output is a candidate, not a verdict)
# --------------------------------------------------------------------------- #


def test_reviewing_a_candidate_event_records_the_decision(launched, factory, actor, db):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    operator = actor(OPERATOR)
    event = factory.event(camera, category="loitering", confidence=0.72)
    factory.session.commit()

    acknowledged = operator.client.post(
        f"/api/events/{event.id}/review", json={"decision": "acknowledge", "note": "Noted"}
    )

    assert acknowledged.status_code == 200, acknowledged.text
    body = acknowledged.json()["event"]
    assert body["status"] == wt_models.EventStatus.ACKNOWLEDGED.value
    assert body["review_note"] == "Noted"
    assert body["reviewed_at"] is not None
    db.expire_all()
    row = db.get(wt_models.DetectionEvent, event.id)
    assert row.reviewed_by == operator.user.id
    assert audits_for(db, "event.acknowledge")[0]["category"] == "loitering"


def test_dismiss_and_invalid_decision_are_distinguished(launched, factory, actor):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    operator = actor(OPERATOR)
    dismissed_event = factory.event(camera, category="loitering")
    other = factory.event(camera, category="intrusion")
    factory.session.commit()

    ok = operator.client.post(f"/api/events/{dismissed_event.id}/review", json={"decision": "dismiss"})
    assert ok.status_code == 200
    assert ok.json()["event"]["status"] == wt_models.EventStatus.DISMISSED.value

    rejected = operator.client.post(f"/api/events/{other.id}/review", json={"decision": "ignore"})
    assert rejected.status_code == 422


def test_escalating_a_candidate_event_opens_an_incident_linked_to_it(launched, factory, actor, db):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    supervisor = actor(SUPERVISOR)
    event = factory.event(camera, category="intrusion", confidence=0.91)
    factory.session.commit()

    response = supervisor.client.post(
        f"/api/events/{event.id}/review",
        json={"decision": "escalate", "note": "Inside the fence line"},
    )

    assert response.status_code == 200, response.text
    incident = response.json()["incident"]
    assert incident["origin_event_id"] == event.id
    assert incident["camera_id"] == str(camera.id)
    assert incident["campus_location"] == camera.campus_location
    assert actions_for(db, incident["id"]) == ["created_from_event"]

    listed = supervisor.client.get("/api/events?only_new=true").json()["events"]
    assert event.id not in [row["id"] for row in listed]


def test_an_event_review_without_resolve_authority_cannot_close_the_incident(
    launched, factory, actor
):
    camera = factory.camera(status=wt_models.CameraStatus.ONLINE.value, is_registered=True)
    factory.session.commit()
    operator = actor(OPERATOR)
    supervisor = actor(SUPERVISOR)
    event = factory.event(camera)
    factory.session.commit()

    incident = operator.client.post(
        f"/api/events/{event.id}/review", json={"decision": "escalate"}
    ).json()["incident"]

    blocked = operator.client.post(
        f"/api/incidents/{incident['id']}/resolve",
        json={"outcome": "handled", "resolution": "closed by the operator"},
    )
    assert blocked.status_code == 403

    allowed = supervisor.client.post(
        f"/api/incidents/{incident['id']}/resolve",
        json={"outcome": "handled", "resolution": "closed by the supervisor"},
    )
    assert allowed.status_code == 200, allowed.text
