"""Incident reads and response actions over the mobile HTTP routes (contract section 6).

`test_incident_workflow.py` exercises the console's state machine directly. These tests are about
the shape the phone receives, which is what task §E of the proposal is written against:

  - the queue must label a candidate event, not only the detail page, so an unread AI detection is
    never read as a settled fact by a duty officer scanning the list;
  - an actor is a user id *plus* a resolved display name, because `assigned_to: 7` tells the
    person holding the phone nothing they can act on;
  - the evidence badge follows the same permission as the evidence itself;
  - the conflict rules the console enforces are the ones the app is told about, in the codes the
    app actually branches on.

The harness session and the request session are separate connections, so every row a test wants
the service to see is committed first, and every state change the service made is read back
through the service rather than from the local session.
"""

from __future__ import annotations

import datetime as dt

from watchtower.models import (
    EvidenceAsset,
    IncidentAction,
    IncidentStatus,
    Severity,
)


def _open_incident(factory, *, group_id=None, severity=Severity.HIGH.value,
                   status=IncidentStatus.OPEN.value, title="Person at the gate"):
    camera = factory.camera(group_id=group_id)
    incident = factory.incident(camera, title=title, severity=severity, status=status)
    return incident, camera


def _candidate(factory, camera, *, confidence=0.83):
    """An incident whose origin is a detection event, i.e. an AI candidate."""
    event = factory.event(camera, confidence=confidence)
    incident = factory.incident(camera)
    incident.origin_event_id = event.id
    factory.session.flush()
    return incident, event


class TestQueueShape:
    def test_a_candidate_is_labelled_in_the_queue_and_not_only_once_opened(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, event = _candidate(factory, factory.camera())
        factory.session.commit()

        items = session.actor.get("/api/v1/incidents").json()["items"]
        row = next(item for item in items if item["id"] == incident.id)
        assert row["detection_source"] == "ai_candidate"
        assert row["confidence"] == event.confidence
        # The phone reads the event's own score, not whatever the ingest payload claimed.
        detail = session.actor.get(f"/api/v1/incidents/{incident.id}").json()
        assert detail["confidence"] == row["confidence"]

    def test_an_incident_nobody_raised_a_model_over_is_reported_as_manual(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        row = next(
            item
            for item in session.actor.get("/api/v1/incidents").json()["items"]
            if item["id"] == incident.id
        )
        assert row["detection_source"] == "manual"
        assert row["confidence"] is None

    def test_a_candidate_whose_event_row_was_pruned_still_reads_as_a_plain_incident(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, event = _candidate(factory, factory.camera())
        incident.origin_event_id = event.id + 999_999
        factory.session.commit()

        row = next(
            item
            for item in session.actor.get("/api/v1/incidents").json()["items"]
            if item["id"] == incident.id
        )
        assert row["detection_source"] == "manual"
        assert row["confidence"] is None

    def test_the_queue_names_the_people_behind_the_two_ids(self, signed_in, factory):
        """`assigned_to` and `escalated_to` are foreign keys; a phone must show who they are."""
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        colleague = factory.user(username="k.abubakar", display_name="Kamal Abubakar",
                                 roles=("security_operator",))
        incident.assigned_to = colleague.id
        incident.escalated_to = colleague.id
        factory.session.commit()

        row = next(
            item
            for item in session.actor.get("/api/v1/incidents").json()["items"]
            if item["id"] == incident.id
        )
        assert row["assigned_to"] == colleague.id
        assert row["assigned_to_name"] == "Kamal Abubakar"
        assert row["escalated_to_name"] == "Kamal Abubakar"

    def test_an_incident_with_no_assignee_names_nobody_rather_than_guessing(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        row = next(
            item
            for item in session.actor.get("/api/v1/incidents").json()["items"]
            if item["id"] == incident.id
        )
        assert row["assigned_to"] is None
        assert row["assigned_to_name"] is None
        assert row["escalated_to_name"] is None

    def test_an_account_without_the_evidence_permission_gets_an_empty_badge(
        self, signed_in, factory
    ):
        """The queue must not advertise media the same account cannot open on the detail page."""
        session = signed_in("auditor_read_only")
        incident, camera = _open_incident(factory)
        factory.session.add(
            EvidenceAsset(
                incident_id=incident.id,
                camera_id=camera.id,
                kind="snapshot",
                filename="gate.jpg",
                storage_key="inc-relay/gate.jpg",
                content_type="image/jpeg",
                byte_size=12,
                sha256="0" * 64,
                captured_at=dt.datetime.now(dt.UTC),
            )
        )
        factory.session.commit()

        row = next(
            item
            for item in session.actor.get("/api/v1/incidents").json()["items"]
            if item["id"] == incident.id
        )
        assert row["evidence"] == []
        assert session.actor.get(f"/api/v1/incidents/{incident.id}").json()["evidence"] == []

    def test_an_account_with_the_evidence_permission_sees_what_is_there(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, camera = _open_incident(factory)
        factory.session.add(
            EvidenceAsset(
                incident_id=incident.id,
                camera_id=camera.id,
                kind="snapshot",
                filename="gate.jpg",
                storage_key="inc-relay/gate.jpg",
                content_type="image/jpeg",
                byte_size=12,
                sha256="0" * 64,
                captured_at=dt.datetime.now(dt.UTC),
            )
        )
        factory.session.add(
            EvidenceAsset(
                incident_id=incident.id,
                camera_id=camera.id,
                kind="clip",
                filename="gate.mp4",
                storage_key="inc-relay/gate.mp4",
                content_type="video/mp4",
                byte_size=9_000,
                sha256="1" * 64,
                captured_at=dt.datetime.now(dt.UTC),
                deleted_at=dt.datetime.now(dt.UTC),
            )
        )
        factory.session.commit()

        row = next(
            item
            for item in session.actor.get("/api/v1/incidents").json()["items"]
            if item["id"] == incident.id
        )
        # A badge is an id, a kind and whether the bytes still exist — never a link.
        assert {asset["state"] for asset in row["evidence"]} == {"available", "deleted"}
        assert "url" not in row["evidence"][0]
        assert "storage_key" not in row["evidence"][0]


class TestQueueFilters:
    def test_an_unknown_status_is_refused_by_name_not_silently_ignored(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        _open_incident(factory)
        factory.session.commit()

        response = session.actor.get("/api/v1/incidents", params={"status": "pending"})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "status_invalid"

    def test_the_six_server_states_are_all_filterable(self, signed_in, factory):
        session = signed_in("security_operator")
        for status in IncidentStatus:
            _open_incident(factory, title=f"Incident in {status.value}", status=status.value)
        factory.session.commit()

        for status in IncidentStatus:
            body = session.actor.get(
                "/api/v1/incidents", params={"status": status.value}
            ).json()["items"]
            assert len(body) == 1, status
            assert body[0]["status"] == status.value

    def test_the_date_bounds_are_called_since_and_until(self, signed_in, factory):
        """Notifications use `from`/`to`; incidents use `since`/`until`. Only the latter filters."""
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        incident.occurred_at = dt.datetime(2026, 3, 4, 9, 0, tzinfo=dt.UTC)
        factory.session.commit()

        window = {"since": "2026-03-04T00:00:00+00:00", "until": "2026-03-05T00:00:00+00:00"}
        assert [i["id"] for i in session.actor.get(
            "/api/v1/incidents", params=window
        ).json()["items"]] == [incident.id]

        # The notifications spelling is unknown to this route, so it filters nothing.
        wrong = {"from": "2026-03-04T00:00:00+00:00", "to": "2026-03-05T00:00:00+00:00"}
        assert len(session.actor.get("/api/v1/incidents", params=wrong).json()["items"]) == 1


class TestScopeOnReads:
    def test_an_incident_on_another_camera_group_answers_404_not_403(
        self, signed_in, factory
    ):
        mine = signed_in("security_operator", group_id=None)
        other_group = factory.group(code="GRP-OTHER")
        foreign, _camera = _open_incident(factory, group_id=other_group.id)
        scoped = signed_in("security_operator", username="gate.only", group_id=other_group.id)
        factory.session.commit()

        # `mine` has no group, so the grant is institution-wide and it can see the row.
        assert mine.actor.get(f"/api/v1/incidents/{foreign.id}").status_code == 200
        # A scoped account sees it; an account scoped to a *different* group does not.
        assert scoped.actor.get(f"/api/v1/incidents/{foreign.id}").status_code == 200
        third_group = factory.group(code="GRP-THIRD")
        outsider = signed_in("security_operator", username="other.yard", group_id=third_group.id)
        factory.session.commit()
        assert outsider.actor.get(f"/api/v1/incidents/{foreign.id}").status_code == 404
        assert outsider.actor.get("/api/v1/incidents").json()["items"] == []


class TestAcknowledgement:
    def test_acknowledging_moves_the_incident_and_records_the_caller_as_owner(
        self, signed_in, factory
    ):
        session = signed_in("security_operator", username="d.ahiya")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/acknowledge", json={"note": "Walking over now."}
        ).json()
        assert body["already_acknowledged"] is False
        assert body["status"] == IncidentStatus.INVESTIGATING.value
        assert body["acknowledged_by"] == session.user.id
        assert body["assigned_to"] == session.user.id
        assert body["assigned_to_name"] == session.user.display_name
        assert body["acknowledgements"][0]["source"] == "mobile"
        assert body["acknowledgements"][0]["note"] == "Walking over now."

    def test_a_second_acknowledge_says_already_rather_than_pretending_to_work(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        session.actor.post(f"/api/v1/incidents/{incident.id}/acknowledge", json={})
        second = session.actor.post(
            f"/api/v1/incidents/{incident.id}/acknowledge", json={}
        )
        assert second.json()["already_acknowledged"] is True
        # One history entry, not two: the duplicate tap is a signal, not an event.
        actions = session.actor.get(f"/api/v1/incidents/{incident.id}/activity").json()["items"]
        assert [a["action"] for a in actions].count("acknowledged") == 1

    def test_a_closed_incident_refuses_acknowledgement_with_the_code_the_app_branches_on(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        ids = []
        for status in (
            IncidentStatus.RESOLVED,
            IncidentStatus.CLOSED,
            IncidentStatus.FALSE_POSITIVE,
        ):
            incident, _camera = _open_incident(factory, status=status.value)
            ids.append(incident.id)
        factory.session.commit()

        for incident_id in ids:
            response = session.actor.post(
                f"/api/v1/incidents/{incident_id}/acknowledge", json={}
            )
            assert response.status_code == 409, status
            assert response.json()["error"]["code"] == "incident_not_actionable"


class TestEscalateAssignResolveReopen:
    def test_an_operator_holds_no_escalation_grant_and_is_told_so(
        self, signed_in, factory
    ):
        """`ROLE_DEFINITIONS.security_operator` carries view/create/acknowledge only.

        The app hides the button off `/auth/me`; this is the answer it gets anyway when the grant
        was revoked while the screen was open, which is a 403 and not a silent no-op.
        """
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/escalate",
            json={"reason": "Two people over the line, no one answering the gate."},
        )
        assert response.status_code == 403

    def test_an_escalation_with_nobody_in_the_target_role_is_a_conflict_not_a_silence(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/escalate",
            json={"reason": "Two people over the line, no one answering the gate.",
                  "to_role": "technical_operator"},
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "escalation_target_unavailable"

    def test_an_escalation_names_the_person_it_reached_and_says_who_was_paged(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        supervisor = factory.user(username="m.yakubu", display_name="Musa Yakubu",
                                  roles=("security_supervisor",))
        factory.session.commit()

        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/escalate",
            json={"reason": "Needs a supervisor, the gate is unattended."},
        ).json()
        assert body["escalated_to"] == supervisor.id
        assert body["escalated_to_name"] == "Musa Yakubu"
        # `escalate` carries the reason as its note; there is no separate note field.
        actions = session.actor.get(f"/api/v1/incidents/{incident.id}/activity").json()["items"]
        assert actions[0]["action"] == "escalated"
        assert actions[0]["note"] == "Needs a supervisor, the gate is unattended."
        assert actions[0]["actor_name"] == session.user.display_name
        assert "notifications" in body
        assert set(body["notifications"]) == {
            "notifications_created",
            "notifications_suppressed",
            "duplicate_recipients",
            "devices_targeted",
            "suppression_reasons",
        }

    def test_escalating_to_a_named_person_that_does_not_exist_is_a_404(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/escalate",
            json={"reason": "Handing this to the duty officer.", "to_user_id": 999_999},
        )
        assert response.status_code == 404

    def test_a_resolve_marked_false_positive_lands_on_the_servers_fourth_terminal_state(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"outcome": "false_positive", "resolution": "A contractor, escorted.",
                  "false_positive": True},
        ).json()
        assert body["status"] == IncidentStatus.FALSE_POSITIVE.value
        assert body["outcome"] == "false_positive"
        assert body["resolved_at"] is not None

    def test_a_second_resolve_rewrites_the_outcome_rather_than_refusing(
        self, signed_in, factory
    ):
        """`IncidentService.resolve()` has no terminal-state guard, and the phone must know.

        The app therefore cannot treat a resolve as claim-once: a colleague who already resolved
        it answers 200 with the newer wording, and a stale queue silently restamps the record and
        re-pages the shift. `already_resolved` is never sent for this route.
        """
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        session.actor.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"outcome": "handled", "resolution": "Gate cleared."},
        )
        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"outcome": "escalated-off", "resolution": "Gate cleared by the yard team."},
        )
        assert body.status_code == 200
        detail = body.json()
        assert detail["status"] == IncidentStatus.RESOLVED.value
        assert detail["outcome"] == "escalated-off"
        assert detail["resolution"] == "Gate cleared by the yard team."
        actions = session.actor.get(f"/api/v1/incidents/{incident.id}/activity").json()["items"]
        assert [a["action"] for a in actions].count("resolved") == 2

    def test_reopening_an_open_incident_says_not_resolved(self, signed_in, factory):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/reopen", json={"reason": "It is not finished."}
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "not_resolved"

    def test_a_reopened_incident_is_under_investigation_again_and_history_keeps_both_ends(
        self, signed_in, factory
    ):
        """`reopen()` lands on `investigating`, not `open`: the phone must not redraw it as new."""
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        session.actor.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"outcome": "handled", "resolution": "Gate cleared."},
        )
        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/reopen",
            json={"reason": "The same person is back at the line."},
        ).json()
        assert body["status"] == IncidentStatus.INVESTIGATING.value
        assert body["resolved_at"] is None
        assert body["outcome"] is None
        actions = [a["action"] for a in session.actor.get(
            f"/api/v1/incidents/{incident.id}/activity"
        ).json()["items"]]
        assert "reopened" in actions
        assert "resolved" in actions

    def test_a_false_positive_cannot_be_reopened(
        self, signed_in, factory
    ):
        """The service guard accepts only `resolved` and `closed`, so this decision is final."""
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        session.actor.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"outcome": "false_positive", "resolution": "A contractor, escorted.",
                  "false_positive": True},
        )
        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/reopen", json={"reason": "It was not a drill."}
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "not_resolved"

    def test_an_operator_without_the_resolve_grant_cannot_close_an_incident(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/resolve",
            json={"outcome": "handled", "resolution": "Gate cleared."},
        )
        assert response.status_code == 403

    def test_assigning_is_a_supervisor_action_and_reaches_the_assignee_by_name(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        operator = factory.user(username="p.eka", display_name="Peter Eka",
                                roles=("security_operator",))
        factory.session.commit()

        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/assign", json={"user_id": operator.id}
        ).json()
        assert body["assigned_to"] == operator.id
        assert body["assigned_to_name"] == "Peter Eka"


class TestNotesAndActivity:
    def test_an_empty_note_is_refused_before_it_reaches_the_history(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        response = session.actor.post(
            f"/api/v1/incidents/{incident.id}/notes", json={"note": "   "}
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "note_required"

    def test_investigating_is_a_note_that_moves_the_state_without_claiming_ownership(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        body = session.actor.post(
            f"/api/v1/incidents/{incident.id}/investigating", json={"note": "Reviewing footage."}
        ).json()
        assert body["status"] == IncidentStatus.INVESTIGATING.value
        assert body["acknowledged_by"] is None
        actions = session.actor.get(f"/api/v1/incidents/{incident.id}/activity").json()["items"]
        assert actions[0]["action"] == "investigation_note"

    def test_the_history_is_newest_first_and_paginates_below_the_last_id(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        for index in range(5):
            incident.actions.append(
                IncidentAction(action="note", note=f"note {index}", actor_id=session.user.id)
            )
        factory.session.commit()

        page = session.actor.get(
            f"/api/v1/incidents/{incident.id}/activity", params={"limit": 2}
        ).json()
        assert [a["note"] for a in page["items"]] == ["note 4", "note 3"]
        assert page["next_cursor"] is not None
        nxt = session.actor.get(
            f"/api/v1/incidents/{incident.id}/activity",
            params={"limit": 2, "cursor": page["next_cursor"]},
        ).json()
        assert [a["note"] for a in nxt["items"]] == ["note 2", "note 1"]

    def test_an_action_by_the_service_has_no_actor_name_and_the_app_can_say_so(
        self, signed_in, factory
    ):
        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        incident.actions.append(IncidentAction(action="created", note="ingested", actor_id=None))
        factory.session.commit()

        items = session.actor.get(f"/api/v1/incidents/{incident.id}/activity").json()["items"]
        created = next(item for item in items if item["action"] == "created")
        assert created["actor_id"] is None
        assert created["actor_name"] is None


class TestPreferencesCheck:
    def test_the_diagnostics_answer_for_the_callers_own_preferences(
        self, signed_in, factory
    ):
        from watchtower.mobile.models import PersonnelPreference

        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory, severity=Severity.CRITICAL.value)
        factory.session.add(
            PersonnelPreference(user_id=session.user.id, min_severity=Severity.HIGH.value)
        )
        factory.session.commit()

        body = session.actor.get(
            f"/api/v1/incidents/{incident.id}/preferences-check"
        ).json()
        assert body == {
            "incident_id": incident.id,
            "severity": "critical",
            "acknowledgements": 0,
            "min_severity": "high",
            "quiet_hours": False,
        }

    def test_a_saved_but_disabled_window_is_not_reported_as_a_silence(
        self, signed_in, factory
    ):
        """`{enabled: false, start: 22:00, end: 06:00}` is the normal shape, not a quiet account.

        The profile screen PUTs the whole window even when the switch is off, so a diagnostic that
        tested the blob for truthiness told every account it was being silenced.
        """
        from watchtower.mobile.models import PersonnelPreference

        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.add(
            PersonnelPreference(
                user_id=session.user.id,
                quiet_hours={"enabled": False, "start": "22:00", "end": "06:00"},
            )
        )
        factory.session.commit()

        body = session.actor.get(
            f"/api/v1/incidents/{incident.id}/preferences-check"
        ).json()
        assert body["quiet_hours"] is False

    def test_a_window_that_covers_the_present_moment_is_reported_as_a_silence(
        self, signed_in, factory
    ):
        from watchtower.mobile.models import PersonnelPreference

        session = signed_in("security_operator")
        incident, _camera = _open_incident(factory)
        factory.session.add(
            PersonnelPreference(
                user_id=session.user.id,
                quiet_hours={"enabled": True, "start": "00:00", "end": "23:59"},
            )
        )
        factory.session.commit()

        body = session.actor.get(
            f"/api/v1/incidents/{incident.id}/preferences-check"
        ).json()
        assert body["quiet_hours"] is True

    def test_an_account_with_no_preference_row_says_so_rather_than_defaulting(
        self, signed_in, factory
    ):
        session = signed_in("auditor_read_only")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        body = session.actor.get(
            f"/api/v1/incidents/{incident.id}/preferences-check"
        ).json()
        assert body["min_severity"] is None
        assert body["quiet_hours"] is False


class TestActionRateLimit:
    def test_actions_are_throttled_per_person_with_the_code_the_app_explains(
        self, signed_in, make_cloud_app, cloud_settings, factory
    ):
        """The write budget is per account per minute, so the ceiling is lowered for this test."""
        session = signed_in("security_supervisor")
        incident, _camera = _open_incident(factory)
        factory.session.commit()

        client = make_cloud_app(cloud_settings, action_attempts_per_minute=3)
        for _ in range(3):
            response = client.post(
                f"/api/v1/incidents/{incident.id}/notes",
                json={"note": "still watching"},
                headers=session.actor.headers,
            )
            assert response.status_code == 200
        fourth = client.post(
            f"/api/v1/incidents/{incident.id}/notes",
            json={"note": "one tap too many"},
            headers=session.actor.headers,
        )
        assert fourth.status_code == 429
        assert fourth.json()["error"]["code"] == "too_many_actions"
        # Reading is not writing: a throttled officer can still watch the queue come in.
        assert client.get(
            "/api/v1/incidents", headers=session.actor.headers
        ).status_code == 200
