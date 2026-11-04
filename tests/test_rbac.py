"""Role-based access control over HTTP (proposal section 14).

Each of the five documented roles gets to do exactly what section 14 says and nothing it
does not. The assertions are made through the real endpoints, because the permission a
route demands is part of the promise; a unit test on `Principal.allows()` alone would not
notice a router that forgot to ask.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from watchtower import models as wt_models
from watchtower.models import CameraStatus, ProbeResult
from watchtower.security.rbac import ROLE_DEFINITIONS

RTSP_OK = "rtsp://admin:sup3r-secret-pw@10.20.0.7:554/cam/realmonitor"


def registration_payload(code: str) -> dict:
    return {
        "method": "rtsp_string",
        "display_name": "Gate Camera",
        "code": code,
        "campus_location": "Main gate",
        "rtsp_url": RTSP_OK,
        "verified_in_vlc": True,
    }


@pytest.fixture
def world(factory, evidence_store):
    """One group pair, two cameras, one candidate event, one incident, one evidence asset."""
    group_a = factory.group(code="GRP-A", name="Main gate")
    group_b = factory.group(code="GRP-B", name="Armoury")
    camera_a = factory.camera(
        code="CAM-A01",
        group_id=group_a.id,
        status=CameraStatus.ONLINE.value,
        desired_state="running",
        is_registered=True,
        probe_result=ProbeResult.CONNECTED.value,
    )
    camera_b = factory.camera(
        code="CAM-B01",
        group_id=group_b.id,
        status=CameraStatus.ONLINE.value,
        desired_state="running",
        is_registered=True,
        probe_result=ProbeResult.CONNECTED.value,
    )
    policy = factory.policy()
    event = factory.event(camera_a)
    incident = factory.incident(camera_a, title="Person at the gate after hours")
    ungrouped = factory.camera(code="CAM-FREE", status=CameraStatus.ONLINE.value, is_registered=True)
    written = evidence_store.write_snapshot(
        camera_a.id, b"\xff\xd8\xff\xe0jpeg-payload", incident_id=incident.id
    )
    factory.session.commit()

    return SimpleNamespace(
        group_a=group_a,
        group_b=group_b,
        camera_a=camera_a,
        camera_b=camera_b,
        policy=policy,
        event=event,
        incident=incident,
        evidence_id=written.asset.id,
        ungrouped=ungrouped,
    )


def forbidden(response):
    assert response.status_code == 403, response.text
    assert response.json()["detail"]["code"] == "forbidden"


# --------------------------------------------------------------------------- #
# Auditor / read-only reviewer
# --------------------------------------------------------------------------- #


def test_the_auditor_can_read_every_record_it_is_granted(world, actor, read_audit):
    auditor = actor("auditor_read_only", username="actor.auditor")

    assert auditor.client.get("/api/cameras").status_code == 200
    assert auditor.client.get(f"/api/cameras/{world.camera_a.id}").status_code == 200
    assert auditor.client.get(f"/api/cameras/{world.camera_a.id}/health").status_code == 200
    assert auditor.client.get("/api/events").status_code == 200
    assert auditor.client.get("/api/incidents").status_code == 200
    assert auditor.client.get(f"/api/incidents/{world.incident.id}").status_code == 200
    assert auditor.client.get("/api/admin/audit").status_code == 200
    assert auditor.client.get("/api/admin/reports/operations").status_code == 200


def test_the_auditor_cannot_register_a_camera(world, actor, fake_probe):
    fake_probe(ProbeResult.CONNECTED)
    auditor = actor("auditor_read_only", username="actor.auditor2")

    response = auditor.client.post("/api/cameras", json=registration_payload("AFIT-AUD-001"))
    forbidden(response)


def test_the_auditor_cannot_export_evidence(world, actor):
    auditor = actor("auditor_read_only", username="actor.auditor3")

    # section 14 gives the auditor incident visibility, not evidence custody
    forbidden(auditor.client.get(f"/api/evidence/{world.evidence_id}?export=true"))
    forbidden(auditor.client.get(f"/api/evidence/{world.evidence_id}"))


def test_the_auditor_cannot_touch_the_incident_workflow(world, actor):
    auditor = actor("auditor_read_only", username="actor.auditor4")

    forbidden(auditor.client.post(f"/api/incidents/{world.incident.id}/resolve", json={"outcome": "handled", "resolution": "security escort"}))
    forbidden(auditor.client.post(f"/api/incidents/{world.incident.id}/assign", json={"assignee_id": auditor.user.id}))
    forbidden(auditor.client.post(f"/api/incidents/{world.incident.id}/escalate", json={"to_user_id": auditor.user.id}))
    forbidden(auditor.client.post("/api/incidents", json={"title": "Manual incident", "category": "loitering"}))
    forbidden(auditor.client.post(f"/api/events/{world.event.id}/review", json={"decision": "acknowledge"}))


def test_the_auditor_cannot_administer_users_or_policies(world, actor):
    auditor = actor("auditor_read_only", username="actor.auditor5")

    forbidden(auditor.client.get("/api/admin/users"))
    forbidden(
        auditor.client.post(
            "/api/admin/policies",
            json={"code": "POL-X", "name": "X", "detector_codes": ["loitering"]},
        )
    )


# --------------------------------------------------------------------------- #
# Technical operator
# --------------------------------------------------------------------------- #


def test_the_technical_operator_runs_the_camera_workflow(world, actor, fake_probe, supervisor):
    fake_probe(ProbeResult.CONNECTED)
    technician = actor("technical_operator", username="actor.tech")

    registered = technician.client.post("/api/cameras", json=registration_payload("AFIT-TECH-001"))
    assert registered.status_code == 201, registered.text
    camera_id = registered.json()["camera"]["id"]

    assert technician.client.post(f"/api/cameras/{camera_id}/test").status_code == 200
    activated = technician.client.post(f"/api/cameras/{camera_id}/activate")
    assert activated.status_code == 200, activated.text
    assert activated.json()["status"] == "testing"
    assert supervisor.stats(camera_id) is not None
    assert technician.client.post(f"/api/cameras/{camera_id}/disable").status_code == 200
    assert technician.client.get(f"/api/cameras/{camera_id}/health").status_code == 200


def test_the_technical_operator_has_no_incident_authority(world, actor):
    technician = actor("technical_operator", username="actor.tech2")

    forbidden(technician.client.post(f"/api/incidents/{world.incident.id}/resolve", json={"outcome": "done", "resolution": "resolved"}))
    forbidden(technician.client.post(f"/api/incidents/{world.incident.id}/assign", json={"assignee_id": technician.user.id}))
    forbidden(technician.client.post(f"/api/incidents/{world.incident.id}/escalate", json={"to_user_id": technician.user.id}))
    forbidden(technician.client.get("/api/incidents"))
    forbidden(technician.client.get("/api/events"))
    assert "incident.resolve" not in ROLE_DEFINITIONS["technical_operator"]["permissions"]


# --------------------------------------------------------------------------- #
# Security operator
# --------------------------------------------------------------------------- #


def test_the_security_operator_watches_live_but_cannot_configure(world, actor, fake_probe):
    fake_probe(ProbeResult.CONNECTED)
    operator = actor("security_operator", username="actor.op")

    opened = operator.client.post("/api/live/sessions", json={"camera_id": str(world.camera_a.id)})
    assert opened.status_code == 201, opened.text

    forbidden(operator.client.post("/api/cameras", json=registration_payload("AFIT-OP-001")))
    forbidden(operator.client.post(f"/api/cameras/{world.camera_a.id}/test"))
    forbidden(operator.client.patch(f"/api/cameras/{world.camera_a.id}", json={"display_name": "Renamed"}))
    forbidden(operator.client.post(f"/api/cameras/{world.camera_a.id}/disable"))


def test_the_security_operator_reviews_events_but_cannot_resolve(world, actor):
    operator = actor("security_operator", username="actor.op2")

    reviewed = operator.client.post(f"/api/events/{world.event.id}/review", json={"decision": "acknowledge"})
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["event"]["status"] == "acknowledged"
    assert operator.client.post("/api/incidents", json={"title": "Gate opened", "category": "restricted_zone"}).status_code == 201
    forbidden(operator.client.post(f"/api/incidents/{world.incident.id}/resolve", json={"outcome": "done", "resolution": "closed out"}))


# --------------------------------------------------------------------------- #
# Security supervisor
# --------------------------------------------------------------------------- #


def test_the_supervisor_assigns_and_escalates(world, actor, factory, db):
    supervisor = actor("security_supervisor", username="actor.sup")
    assignee = factory.user(username="assignee.one", roles=("security_operator",))
    factory.session.commit()
    db.commit()

    assigned = supervisor.client.post(
        f"/api/incidents/{world.incident.id}/assign", json={"assignee_id": assignee.id}
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["incident"]["status"] == "assigned"
    assert assigned.json()["incident"]["assigned_to"] == assignee.id

    escalated = supervisor.client.post(
        f"/api/incidents/{world.incident.id}/escalate",
        json={"to_user_id": assignee.id, "note": "needs a supervisor decision"},
    )
    assert escalated.status_code == 200, escalated.text
    assert escalated.json()["incident"]["status"] == "investigating"
    assert escalated.json()["incident"]["severity"] == "high"

    resolved = supervisor.client.post(
        f"/api/incidents/{world.incident.id}/resolve",
        json={"outcome": "guarded", "resolution": "site security escorted the person out"},
    )
    assert resolved.status_code == 200, resolved.text

    # configuring cameras is not part of the supervisor's remit (section 14)
    forbidden(supervisor.client.post(f"/api/cameras/{world.camera_a.id}/test"))


# --------------------------------------------------------------------------- #
# System administrator
# --------------------------------------------------------------------------- #


def test_the_administrator_manages_access_without_owning_the_video_wall(world, actor, db):
    administrator = actor("system_administrator", username="actor.root")

    assert administrator.client.get("/api/admin/users").status_code == 200
    assert administrator.client.get("/api/admin/roles").status_code == 200
    assert administrator.client.get("/api/admin/audit").status_code == 200
    # administrative rights and video-viewing rights are separate permissions
    forbidden(administrator.client.post("/api/live/sessions", json={"camera_id": str(world.camera_a.id)}))


# --------------------------------------------------------------------------- #
# Group scoping
# --------------------------------------------------------------------------- #


def test_a_group_scoped_grant_reaches_only_that_groups_camera(world, actor):
    gate_operator = actor(
        "security_operator", username="actor.gateonly", group_id=world.group_a.id
    )

    assert gate_operator.client.get(f"/api/cameras/{world.camera_a.id}").status_code == 200
    forbidden(gate_operator.client.get(f"/api/cameras/{world.camera_b.id}"))
    forbidden(gate_operator.client.post("/api/live/sessions", json={"camera_id": str(world.camera_b.id)}))
    assert gate_operator.client.post("/api/live/sessions", json={"camera_id": str(world.camera_a.id)}).status_code == 201

    listed = gate_operator.client.get("/api/cameras")
    assert listed.status_code == 200
    codes = {camera["code"] for camera in listed.json()}
    assert codes == {"CAM-A01"}
    # an ungrouped camera is not covered by a group grant either
    assert world.ungrouped.code not in codes


def test_a_group_scoped_reviewer_cannot_touch_another_groups_event(world, actor):
    armoury = actor("security_operator", username="actor.armoury", group_id=world.group_b.id)

    forbidden(armoury.client.post(f"/api/events/{world.event.id}/review", json={"decision": "dismiss"}))
    forbidden(armoury.client.get(f"/api/incidents/{world.incident.id}"))


def test_the_incident_list_and_its_status_counts_respect_camera_scope(world, actor, factory):
    """The register the console filters, and the chips above it, must be the same archive.

    `counts` drives the status chips on the incident screen. If they were global they would tell
    a gate operator that four incidents are open while the table underneath offers two.
    """
    other_group = factory.incident(world.camera_b, title="Armoury door left open")
    cameraless = factory.incident(
        title="Visitor logged with no camera record",
        status=wt_models.IncidentStatus.RESOLVED.value,
    )
    factory.session.commit()

    gate = actor("security_operator", username="actor.gate.counts", group_id=world.group_a.id)
    response = gate.client.get("/api/incidents")
    assert response.status_code == 200
    payload = response.json()

    references = {row["reference"] for row in payload["incidents"]}
    assert references == {world.incident.reference, cameraless.reference}
    assert other_group.reference not in references
    assert payload["counts"] == {"open": 1, "resolved": 1}

    armoury = actor("security_operator", username="actor.armoury.counts", group_id=world.group_b.id)
    their = armoury.client.get("/api/incidents").json()
    # An incident tied to no camera belongs to no group, so a group grant cannot exclude it -
    # the same rule `_require` applies when one record is opened.
    assert {row["reference"] for row in their["incidents"]} == {other_group.reference, cameraless.reference}
    assert their["counts"] == {"open": 1, "resolved": 1}


def test_incident_pagination_walks_the_visible_archive(world, actor, factory):
    for index in range(4):
        factory.incident(world.camera_a, title=f"Repeated sighting at the gate {index}")
    factory.session.commit()

    supervisor = actor("security_supervisor", username="actor.paging")
    params = {"limit": 2}
    first = supervisor.client.get("/api/incidents", params={**params, "offset": 0}).json()
    second = supervisor.client.get("/api/incidents", params={**params, "offset": 2}).json()
    last = supervisor.client.get("/api/incidents", params={**params, "offset": 4}).json()

    assert [len(page["incidents"]) for page in (first, second, last)] == [2, 2, 1]
    ids = [{row["id"] for row in page["incidents"]} for page in (first, second, last)]
    assert ids[0].isdisjoint(ids[1]) and ids[1].isdisjoint(ids[2])
    # The chip totals describe the whole filter, not the page being looked at.
    assert {sum(page["counts"].values()) for page in (first, second, last)} == {5}
    assert all(page["counts"] == first["counts"] for page in (second, last))


def test_a_negative_offset_and_an_oversized_page_are_refused(world, actor):
    supervisor = actor("security_supervisor", username="actor.bounds")

    assert supervisor.client.get("/api/incidents", params={"offset": -1}).status_code == 422
    assert supervisor.client.get("/api/incidents", params={"limit": 501}).status_code == 422


def test_an_unscoped_grant_is_institution_wide(world, actor):
    everyone = actor("security_operator", username="actor.unscoped")

    assert everyone.client.get(f"/api/cameras/{world.camera_a.id}").status_code == 200
    assert everyone.client.get(f"/api/cameras/{world.camera_b.id}").status_code == 200


# --------------------------------------------------------------------------- #
# resolve_principal(): the union of several grants
# --------------------------------------------------------------------------- #


def test_resolve_principal_unions_the_permissions_of_several_roles(factory, world):
    from watchtower.security.rbac import resolve_principal

    user = factory.user(username="multi.role", roles=())
    factory.grant(user, "technical_operator")
    factory.grant(user, "security_supervisor", camera_group_id=world.group_a.id)
    factory.session.commit()

    principal = resolve_principal(factory.session, user)

    assert {"camera.register", "incident.assign", "health.view"} <= principal.permissions()
    assert principal.allows("incident.resolve")
    # camera.configure came from the unscoped grant only
    assert principal.camera_scope("camera.configure") is None
    # incident.assign was granted for group A alone
    assert principal.camera_scope("incident.assign") == {world.group_a.id}
    assert principal.is_administrative is False


def test_resolve_principal_unions_several_groups_for_one_permission(factory, world):
    from watchtower.security.rbac import can_view_camera, resolve_principal

    user = factory.user(username="two.groups", roles=())
    factory.grant(user, "security_operator", camera_group_id=world.group_a.id)
    factory.grant(user, "security_operator", camera_group_id=world.group_b.id)
    factory.session.commit()

    principal = resolve_principal(factory.session, user)

    assert principal.camera_scope("camera.view_live") == {world.group_a.id, world.group_b.id}
    assert can_view_camera(principal, "camera.view_live", world.camera_a)
    assert can_view_camera(principal, "camera.view_live", world.camera_b)
    assert not can_view_camera(principal, "camera.view_live", world.ungrouped)


def test_a_role_grant_made_through_the_api_takes_effect_immediately(world, actor, client, factory, db):
    administrator = actor("system_administrator", username="actor.grantor")
    newcomer = factory.user(username="newcomer", roles=(), password="tower-test-password")
    factory.session.commit()
    db.commit()

    granted = administrator.client.post(
        f"/api/admin/users/{newcomer.id}/roles", json={"role_code": "technical_operator"}
    )
    assert granted.status_code == 200, granted.text

    effective = administrator.client.post(f"/api/admin/users/{newcomer.id}/effective-permissions")
    assert effective.status_code == 200, effective.text
    assert "camera.register" in effective.json()["permissions"]

    body = administrator.client.get("/api/admin/audit", params={"action": "admin.role.grant"})
    assert body.json()["entries"], "a role grant must be audited"


def test_anonymous_callers_get_401_not_a_permission_answer(client):
    assert client.get("/api/cameras").status_code == 401
    assert client.post("/api/cameras", json=registration_payload("AFIT-ANON-001")).status_code == 401


def test_a_disabled_role_grant_does_not_leak_permissions(factory, world):
    """Removing the grant removes the permission - there is no implicit super-user path."""
    from watchtower.security.rbac import resolve_principal

    user = factory.user(username="revoked", roles=("technical_operator",))
    factory.session.commit()
    before = resolve_principal(factory.session, user)
    assert before.allows("camera.register")

    for grant_row in factory.session.query(wt_models.UserRole).filter_by(user_id=user.id).all():
        factory.session.delete(grant_row)
    factory.session.commit()

    assert resolve_principal(factory.session, user).grants == []
