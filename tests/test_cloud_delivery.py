"""Device registry, recipient targeting and push delivery (contract sections 3, 10 and 11).

Three separate promises are tested here, because the design keeps them separate:

  * the registry decides *which handset may be paged* and keeps the registration token sealed;
  * targeting decides *who is a recipient* for one alert, in the contract's filter order, and
    writes down why anybody was silenced;
  * delivery turns rows into provider attempts and records what the provider actually said.

The FCM client is replaced with a scripted stand-in (`FakePush`) for the delivery tests. Nothing in
this file contacts Google, and nothing in it hides the absence of a real one: `TestNoFirebase`
runs against the production `DisabledSender` and asserts that a host without a Firebase project
reports the failure instead of inventing a delivery.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections import deque
from pathlib import Path

import pytest
from sqlalchemy import select

from watchtower.cloud import devices as device_store
from watchtower.cloud.delivery import (
    MAX_SEND_ATTEMPTS,
    dedupe_key,
    dispatch_pushes,
    enqueue_alert,
)
from watchtower.cloud.errors import CloudError
from watchtower.cloud.push import PushOutcome, build_payload
from watchtower.cloud.targeting import AlertIntent, KIND_HEALTH, resolve_recipients
from watchtower.mobile.models import (
    AttemptState,
    IncidentAcknowledgement,
    MobileDevice,
    NotificationAttempt,
    PersonnelPreference,
    PushState,
)
from watchtower.models import (
    IncidentStatus,
    Notification,
    NotificationState,
    Severity,
    User,
)
from watchtower.security.secrets import fingerprint

from conftest import INSTALLATION_ID

SECOND_INSTALLATION = "22222222-3333-4444-9555-666666666666"
THIRD_INSTALLATION = "33333333-4444-5555-8666-777777777777"
LOGIN_TOKEN = "fcm-test-token-value"
TOKEN_A = "fcm-registration-token-aaaa"
TOKEN_B = "fcm-registration-token-bbbb"
MIDNIGHT = dt.datetime(2026, 11, 2, 0, 30, tzinfo=dt.UTC)


def _reload(session):
    """Discard the harness session's snapshot so rows written by another session are visible."""
    session.commit()
    session.expire_all()


def _due(*, seconds: int = 0) -> dt.datetime:
    """A moment on the escalation clock, past the deadline the settings name."""
    return dt.datetime.now(dt.UTC) + dt.timedelta(seconds=seconds)


class FakePush:
    """The push client, driven by a script instead of by Google.

    No outcomes means always accepted. One outcome repeats for every send; several answer one send
    each, the last of them repeating, so a test that cares about a third attempt says so by listing
    three. One callable answers per registration token, which is how a test asserts "this handset
    died and that one did not" without depending on the order a query returns rows. An `Exception`
    in the script stands for the transport dying rather than answering badly.
    """

    configured = True
    provider_name = "fcm"

    def __init__(self, *outcomes):
        self._outcomes = deque(outcomes or (PushOutcome.accepted("projects/test/messages/1"),))
        self._per_device = outcomes[0] if len(outcomes) == 1 and callable(outcomes[0]) else None
        self.calls: list[dict] = []

    def send(self, token, *, title, body, data, sound="default"):
        self.calls.append(
            {
                "token": token,
                "title": title,
                "body": body,
                "data": dict(data),
                "sound": sound,
            }
        )
        if self._per_device is not None:
            outcome = self._per_device(token)
        else:
            outcome = self._outcomes[0] if len(self._outcomes) == 1 else self._outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    @property
    def tokens(self) -> list[str]:
        return [call["token"] for call in self.calls]


@pytest.fixture
def container(cloud_app):
    return cloud_app.app.state.container


@pytest.fixture
def push_service(make_cloud_app, cloud_settings):
    """A running service whose deliveries are answered by a sender the test scripts.

    A container keeps one push client for its life, so a test that needs a particular answer -
    a throttle, a dead token, a socket that closed mid-send - builds its service around that
    sender instead of swapping the client under a service already taking requests. Every service
    here shares the harness database, so rows written through one are read by the next.
    """

    def _make(*outcomes):
        push = FakePush(*outcomes)
        client = make_cloud_app(cloud_settings, push_sender=push)
        return client.app.state.container, push

    return _make


def _accepted(message_id="projects/test/messages/9"):
    return PushOutcome.accepted(message_id)


def _failure(*args, **kwargs):
    return PushOutcome.failure(*args, **kwargs)


def _handset(container, factory, user, installation_id, *, push_token=None):
    """A device row written through the real registry, so the token really is sealed."""
    device, _changed = device_store.register(
        factory.session,
        container,
        user_id=user.id,
        installation_id=installation_id,
        push_token=push_token if push_token is not None else f"{TOKEN_A}-{user.id}",
    )
    factory.session.commit()
    return device


def _camera(factory, group, *, name="Gate north"):
    return factory.camera(group_id=group.id, display_name=name)


def _operator(factory, group, username="op.gate"):
    return factory.user(
        username=username, roles=("security_operator",), camera_group_id=group.id
    )


def _supervisor(factory, group, username="sup.gate"):
    return factory.user(
        username=username, roles=("security_supervisor",), camera_group_id=group.id
    )


def _administrator(factory, group, username="admin.gate"):
    return factory.user(
        username=username, roles=("system_administrator",), camera_group_id=group.id
    )


def _intent(incident=None, camera=None, **overrides):
    values = {
        "kind": "incident.created",
        "severity": Severity.HIGH.value,
        "title": "Person at the north gate",
        "body": "Loitering by the barrier for eleven minutes.",
        "incident_id": incident.id if incident else None,
        "camera_id": camera.id if camera else None,
    }
    values.update(overrides)
    return AlertIntent(**values)


def _devices_for(session, user_id):
    return session.scalars(select(MobileDevice).where(MobileDevice.user_id == user_id)).all()


def _rows(session, intent):
    return session.scalars(
        select(Notification).where(Notification.dedupe_key == dedupe_key(intent))
    ).all()


def _names(session, rows):
    return {session.get(User, row.recipient_id).username for row in rows}


def _paged_names(session, intent):
    """The usernames an alert reached: rows left for the delivery worker, not silenced ones."""
    return _names(
        session,
        [row for row in _rows(session, intent) if row.state == NotificationState.PENDING.value],
    )


def _preference(factory, user, **columns):
    values = {
        "user_id": user.id,
        "min_severity": Severity.LOW.value,
        "kinds": {},
        "quiet_hours": {"enabled": False, "start": "22:00", "end": "06:00"},
        "sound": "default",
    }
    values.update(columns)
    preference = PersonnelPreference(**values)
    factory.session.add(preference)
    factory.session.commit()
    return preference


def _app_channel_ids() -> set[str]:
    """The channel ids the handset creates at launch, read out of the app's own source.

    That list belongs to the app - it is where Android's `createChannel()` runs - and this service
    only names one of them. Reading the file instead of repeating the four strings here is what
    stops the two sides drifting apart, which is how every alert came to carry a channel id no
    phone had ever registered.
    """
    source = Path(__file__).resolve().parents[1] / "personnel-app" / "src" / "lib" / "severity.ts"
    if not source.exists():
        pytest.skip(f"the personnel app is not beside this suite: {source}")
    after = source.read_text(encoding="utf-8").split("ALL_CHANNELS", 1)[1]
    return set(re.findall(r"id:\s*'([^']+)'", after.split("];", 1)[0]))


class TestDeviceRegistryOverHttp:
    def test_a_second_handset_is_registered_without_ever_showing_a_token(self, signed_in, factory):
        session = signed_in("security_supervisor")
        registered = session.actor.post(
            "/api/v1/devices",
            json={
                "installation_id": SECOND_INSTALLATION,
                "platform": "android",
                "push_token": TOKEN_B,
                "model": "Second Handset",
            },
        )
        assert registered.status_code == 200
        assert registered.json()["push_state"] == "active"
        assert registered.json()["token_changed"] is True

        listed = session.actor.get("/api/v1/devices").json()["items"]
        assert {item["installation_id"] for item in listed} == {
            INSTALLATION_ID,
            SECOND_INSTALLATION,
        }
        # The app has no reason to read back what it already holds, and a screenshot of a device
        # list must not carry a bearer capability.
        assert all("push_token" not in item for item in listed)
        for secret in (TOKEN_B, LOGIN_TOKEN):
            assert secret not in registered.text
            assert secret not in json.dumps(listed)
        _reload(factory.session)
        assert len(_devices_for(factory.session, session.user.id)) == 2

    def test_the_same_handset_registering_twice_is_not_an_event(self, signed_in, factory):
        session = signed_in("security_supervisor", push_token=TOKEN_A)
        again = session.actor.post(
            "/api/v1/devices",
            json={
                "installation_id": INSTALLATION_ID,
                "platform": "android",
                "push_token": TOKEN_A,
            },
        )
        assert again.status_code == 200
        assert again.json()["token_changed"] is False
        _reload(factory.session)
        rows = _devices_for(factory.session, session.user.id)
        assert len(rows) == 1
        assert rows[0].push_state == PushState.ACTIVE.value

    def test_a_rotated_registration_token_replaces_the_sealed_one(
        self, signed_in, factory, container
    ):
        session = signed_in("security_supervisor", push_token=TOKEN_A)
        rotated = session.actor.post(
            "/api/v1/devices",
            json={
                "installation_id": INSTALLATION_ID,
                "platform": "android",
                "push_token": TOKEN_B,
            },
        )
        assert rotated.json()["token_changed"] is True
        _reload(factory.session)
        device = _devices_for(factory.session, session.user.id)[0]
        assert device.push_token_ciphertext != TOKEN_B.encode()
        assert TOKEN_B.encode() not in device.push_token_ciphertext
        assert device.push_token_fingerprint == fingerprint(TOKEN_B)
        assert device_store.reveal_token(container, device) == TOKEN_B
        assert device.token_updated_at is not None

    def test_a_device_with_no_token_is_listed_as_not_pageable(self, signed_in):
        session = signed_in("security_supervisor", push_token=None)
        listed = session.actor.get("/api/v1/devices").json()["items"]
        assert [item["push_capable"] for item in listed] == [False]
        assert listed[0]["push_state"] == PushState.INACTIVE.value

    def test_a_platform_the_service_does_not_know_is_refused_and_nothing_is_written(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        response = session.actor.post(
            "/api/v1/devices",
            json={
                "installation_id": THIRD_INSTALLATION,
                "platform": "windows",
                "push_token": TOKEN_B,
            },
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "platform_unsupported"
        _reload(factory.session)
        assert len(_devices_for(factory.session, session.user.id)) == 1

    def test_the_registry_does_not_accept_an_installation_it_cannot_name(self, container, factory):
        # Both HTTP bodies demand 8-64 characters, so these two guards belong to the registry
        # itself and are exercised the way any other caller would reach them.
        for bad in ("", "   ", "x" * 65):
            with pytest.raises(CloudError) as refused:
                device_store.register(
                    factory.session, container, user_id=1, installation_id=bad
                )
            assert refused.value.code in (
                "installation_id_required",
                "installation_id_invalid",
            ), bad
            assert refused.value.status_code == 422

    def test_forgetting_a_handset_drops_the_secret_and_ends_its_sessions(
        self, signed_in, factory, container
    ):
        session = signed_in("security_supervisor", push_token=TOKEN_A)
        _reload(factory.session)
        before = _devices_for(factory.session, session.user.id)[0]
        ciphertext = bytes(before.push_token_ciphertext)

        forgotten = session.actor.delete(f"/api/v1/devices/{INSTALLATION_ID}")
        assert forgotten.status_code == 200
        assert forgotten.json()["deactivated"] is True
        assert forgotten.json()["sessions_revoked"] >= 1

        _reload(factory.session)
        device = _devices_for(factory.session, session.user.id)[0]
        assert device.push_state == PushState.REVOKED.value
        assert device.push_token_ciphertext is None
        assert device.push_token_fingerprint is None
        assert device.deactivated_at is not None
        assert device_store.reveal_token(container, device) is None
        # The row survives, because what happened to this handset is part of the account's history
        # - and the sealed bytes that were dropped are the ones an audit can still point at.
        assert len(ciphertext) > 0

    def test_a_revoked_installation_is_not_brought_back_by_reinstalling(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor", push_token=TOKEN_A)
        assert session.actor.delete(f"/api/v1/devices/{INSTALLATION_ID}").status_code == 200

        reinstalled = session.actor.post(
            "/api/v1/devices",
            json={
                "installation_id": INSTALLATION_ID,
                "platform": "android",
                "push_token": TOKEN_B,
            },
        )
        assert reinstalled.status_code == 200
        assert reinstalled.json()["push_state"] == PushState.REVOKED.value
        assert reinstalled.json()["token_changed"] is False
        _reload(factory.session)
        device = _devices_for(factory.session, session.user.id)[0]
        assert device.push_token_ciphertext is None
        assert device_store.targetable(factory.session, [session.user.id]) == []

    def test_rotating_onto_an_unknown_installation_is_not_a_new_device(
        self, signed_in, factory
    ):
        session = signed_in("security_supervisor")
        missing = session.actor.post(
            f"/api/v1/devices/{SECOND_INSTALLATION}/push-token",
            json={"installation_id": SECOND_INSTALLATION, "push_token": TOKEN_B},
        )
        assert missing.status_code == 404
        _reload(factory.session)
        assert len(_devices_for(factory.session, session.user.id)) == 1

        without_token = session.actor.post(
            f"/api/v1/devices/{INSTALLATION_ID}/push-token",
            json={"installation_id": INSTALLATION_ID},
        )
        assert without_token.status_code == 422
        assert without_token.json()["error"]["code"] == "push_token_required"

    def test_a_handset_that_only_now_learned_its_token_becomes_pageable(
        self, signed_in, factory, container
    ):
        session = signed_in("security_supervisor", push_token=None)
        rotated = session.actor.post(
            f"/api/v1/devices/{INSTALLATION_ID}/push-token",
            json={"installation_id": INSTALLATION_ID, "push_token": TOKEN_B},
        )
        assert rotated.status_code == 200
        assert rotated.json()["push_state"] == "active"
        assert rotated.json()["token_changed"] is True
        _reload(factory.session)
        device = _devices_for(factory.session, session.user.id)[0]
        assert device_store.reveal_token(container, device) == TOKEN_B


class TestTargetingFilters:
    def test_the_duty_roster_is_chosen_by_severity(self, container, factory):
        group = factory.group(code="GRP-ROSTER")
        for index, user in enumerate(
            (_operator(factory, group), _supervisor(factory, group), _administrator(factory, group))
        ):
            _handset(container, factory, user, f"installation-{index}")

        cases = {
            Severity.LOW.value: {"op.gate"},
            Severity.MEDIUM.value: {"op.gate", "sup.gate"},
            Severity.HIGH.value: {"op.gate", "sup.gate"},
            # `system_administrator` is on the critical roster but holds no `incident.acknowledge`,
            # so an alert that demands that action cannot be answered by them and is not sent to
            # them. The escalation sweep is how the estate's owner hears about it, and that notice
            # does not demand an in-app action.
            Severity.CRITICAL.value: {"op.gate", "sup.gate"},
        }
        for severity, expected in cases.items():
            # One camera per case, because the dedupe key is the alert's identity: two severities
            # on one camera would be a replay of the first rather than a second decision.
            intent = _intent(camera=_camera(factory, group, name=f"Gate {severity}"),
                             severity=severity)
            enqueue_alert(factory.session, container.settings, intent)
            factory.session.commit()
            assert _paged_names(factory.session, intent) == expected, severity

    def test_a_person_outside_the_camera_group_is_not_even_recorded_as_suppressed(
        self, container, factory
    ):
        gate = factory.group(code="GRP-GATE")
        camera = _camera(factory, gate)
        inside = _operator(factory, gate)
        outside = _operator(factory, factory.group(code="GRP-YARD"), "op.yard")
        for user in (inside, outside):
            _handset(container, factory, user, f"handset-{user.id}")

        intent = _intent(camera=camera, severity=Severity.MEDIUM.value)
        targets = resolve_recipients(factory.session, container.settings, intent)
        assert {target.user.username for target in targets} == {"op.gate"}

        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        rows = _rows(factory.session, intent)
        assert {row.recipient_id for row in rows} == {inside.id}
        # "We chose not to page you" and "you are not responsible for this camera" are different
        # facts, and only the first one belongs in the record.
        assert all(row.state == NotificationState.PENDING.value for row in rows)

    def test_a_person_without_the_read_permission_is_not_a_recipient(self, container, factory):
        group = factory.group(code="GRP-NOTES")
        technician = factory.user(
            username="tech.gate", roles=("technical_operator",), camera_group_id=group.id
        )
        _handset(container, factory, technician, "handset-tech")
        intent = _intent(camera=_camera(factory, group))
        assert resolve_recipients(factory.session, container.settings, intent) == []
        report = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        assert (report.created, report.suppressed) == (0, 0)

    def test_a_health_alert_is_read_under_the_health_permission(self, container, factory):
        group = factory.group(code="GRP-HEALTH")
        technician = factory.user(
            username="tech.gate", roles=("technical_operator",), camera_group_id=group.id
        )
        operator = _operator(factory, group)
        for user in (technician, operator):
            _handset(container, factory, user, f"handset-{user.id}")

        intent = _intent(
            camera=_camera(factory, group),
            kind="camera.health",
            severity=Severity.MEDIUM.value,
            requires_action=False,
        )
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        # The technical operator holds `health.view` and no `incident.view`; the security operator
        # holds neither. Filtered by the incident permission, a hardware alert would page nobody.
        assert _paged_names(factory.session, intent) == {"tech.gate"}

    def test_an_inactive_account_is_not_paged(self, container, factory):
        group = factory.group(code="GRP-GONE")
        operator = _operator(factory, group)
        gone = factory.user(
            username="op.gone",
            roles=("security_operator",),
            camera_group_id=group.id,
            is_active=False,
        )
        for user in (operator, gone):
            _handset(container, factory, user, f"handset-{user.id}")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        assert _paged_names(factory.session, intent) == {"op.gate"}

    def test_the_person_who_took_the_incident_is_not_paged_with_their_own_action(
        self, container, factory
    ):
        group = factory.group(code="GRP-TWO-OPS")
        first = _operator(factory, group, "op.one")
        second = _operator(factory, group, "op.two")
        for user in (first, second):
            _handset(container, factory, user, f"handset-{user.id}")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent, exclude_user_ids={first.id})
        factory.session.commit()
        assert _paged_names(factory.session, intent) == {"op.two"}

    def test_a_minimum_severity_silences_and_records_why(self, container, factory):
        group = factory.group(code="GRP-FLOOR")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(factory, operator, min_severity=Severity.CRITICAL.value)

        intent = _intent(camera=_camera(factory, group), severity=Severity.HIGH.value)
        report = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        assert report.suppressed == 1
        assert report.reasons == {"below_min_severity:critical": 1}
        row = _rows(factory.session, intent)[0]
        assert row.state == NotificationState.SUPPRESSED.value
        assert row.failure_reason == "below_min_severity:critical"
        # A silenced alert is still a fact about the account, so the row exists - it simply is not
        # handed to the delivery worker.
        assert dispatch_pushes(factory.session, container).as_dict()["devices_targeted"] == 0

    def test_a_disabled_alert_kind_silences_and_records_why(self, container, factory):
        group = factory.group(code="GRP-KIND")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(factory, operator, kinds={"incident.created": False})
        intent = _intent(camera=_camera(factory, group))
        report = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        assert report.reasons == {"kind_disabled:incident.created": 1}

    def test_quiet_hours_silence_and_a_mandatory_alert_overrides_them(self, container, factory):
        group = factory.group(code="GRP-QUIET")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(
            factory, operator, quiet_hours={"enabled": True, "start": "22:00", "end": "06:00"}
        )

        quiet = _intent(camera=_camera(factory, group, name="Gate quiet"),
                        severity=Severity.HIGH.value)
        report = enqueue_alert(factory.session, container.settings, quiet, now=MIDNIGHT)
        factory.session.commit()
        assert report.reasons == {"quiet_hours": 1}

        # `forced_alerts` is configuration, not a preference: the person cannot silence the alert
        # the duty rota depends on, whichever handset is charging beside them.
        mandatory = _intent(
            camera=_camera(factory, group, name="Gate forced"),
            severity=Severity.CRITICAL.value,
        )
        report = enqueue_alert(factory.session, container.settings, mandatory, now=MIDNIGHT)
        factory.session.commit()
        assert report.suppressed == 0
        assert _paged_names(factory.session, mandatory) == {"op.gate"}

    def test_a_window_that_crosses_midnight_is_still_a_window(self, container, factory):
        group = factory.group(code="GRP-MIDNIGHT")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(
            factory, operator, quiet_hours={"enabled": True, "start": "23:00", "end": "05:00"}
        )
        inside = _intent(camera=_camera(factory, group, name="Gate late"))
        report = enqueue_alert(
            factory.session, container.settings, inside,
            now=dt.datetime(2026, 11, 2, 23, 30, tzinfo=dt.UTC),
        )
        factory.session.commit()
        assert report.reasons == {"quiet_hours": 1}

        awake = _intent(camera=_camera(factory, group, name="Gate early"))
        report = enqueue_alert(
            factory.session, container.settings, awake,
            now=dt.datetime(2026, 11, 2, 6, 0, tzinfo=dt.UTC),
        )
        factory.session.commit()
        assert (report.suppressed, _paged_names(factory.session, awake)) == (0, {"op.gate"})

    def test_a_malformed_quiet_hours_window_is_not_a_silence(self, container, factory):
        group = factory.group(code="GRP-BADW")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        preference = _preference(factory, operator)
        late = dt.datetime(2026, 11, 2, 23, 30, tzinfo=dt.UTC)

        broken = (
            {"enabled": True, "start": "25:00", "end": "06:00"},
            {"enabled": True, "start": "half past ten", "end": "06:00"},
            {"enabled": True, "start": "22:00"},
            {"enabled": True},
        )
        for index, window in enumerate(broken):
            intent = _intent(
                camera=_camera(factory, group, name=f"Gate {index}"),
                severity=Severity.MEDIUM.value,
            )
            preference.quiet_hours = window
            factory.session.commit()
            report = enqueue_alert(factory.session, container.settings, intent, now=late)
            factory.session.commit()
            assert report.suppressed == 0, window
            assert _paged_names(factory.session, intent) == {"op.gate"}, window


class TestEnqueueDedupe:
    def test_a_replayed_alert_creates_one_row_per_recipient(self, container, factory):
        group = factory.group(code="GRP-REPLAY")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        first = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        second = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        assert (first.created, first.duplicates) == (1, 0)
        assert (second.created, second.duplicates) == (0, 1)
        assert len(_rows(factory.session, intent)) == 1

    def test_a_silenced_recipient_is_not_written_twice(self, container, factory):
        group = factory.group(code="GRP-SILENCED")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(factory, operator, min_severity=Severity.CRITICAL.value)
        intent = _intent(camera=_camera(factory, group), severity=Severity.LOW.value)
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        second = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        assert (second.created, second.suppressed, second.duplicates) == (0, 0, 1)
        assert len(_rows(factory.session, intent)) == 1

    def test_each_escalation_stage_is_its_own_alert(self, container, factory):
        group = factory.group(code="GRP-STAGES")
        supervisor = _supervisor(factory, group)
        _handset(container, factory, supervisor, "handset-sup")
        camera = _camera(factory, group)
        incident = factory.incident(camera=camera, severity=Severity.CRITICAL.value)
        first = _intent(incident=incident, camera=camera, severity=Severity.CRITICAL.value)
        second = _intent(
            incident=incident,
            camera=camera,
            kind="incident.escalated",
            severity=Severity.CRITICAL.value,
            stage="escalated-1",
        )
        enqueue_alert(factory.session, container.settings, first)
        second_report = enqueue_alert(factory.session, container.settings, second)
        factory.session.commit()
        keys = sorted(
            row.dedupe_key
            for row in factory.session.scalars(
                select(Notification).where(Notification.incident_id == incident.id)
            ).all()
        )
        assert keys == [
            f"incident.created:incident:{incident.id}",
            f"incident.escalated:incident:{incident.id}:escalated-1",
        ]
        assert second_report.created == 1
        # The re-page is its own decision, so a worker that runs the same stage twice lands on
        # that stage's key rather than colliding with the alert it is escalating.
        replay = enqueue_alert(factory.session, container.settings, second)
        factory.session.commit()
        assert (replay.created, replay.duplicates) == (0, 1)
        assert len(_rows(factory.session, second)) == 1

    def test_the_subject_of_a_dedupe_key_prefers_the_incident_then_the_event(self, factory):
        group = factory.group(code="GRP-KEYS")
        camera = _camera(factory, group)
        assert dedupe_key(_intent(camera=camera, kind="camera.health")) == (
            f"camera.health:camera:{camera.id}"
        )
        event_only = AlertIntent(
            kind="event.new",
            severity=Severity.HIGH.value,
            title="Crossing the line",
            body="A person crossed the perimeter line.",
            event_id=17,
            camera_id=camera.id,
        )
        assert dedupe_key(event_only) == "event.new:event:17"

    def test_a_handset_with_no_push_token_still_gets_the_alert_to_show(self, push_service, factory):
        """Contract §10.7: with no push channel, the in-app queue is the delivery.

        A phone that signed in but never obtained an FCM token - which is every phone on a build
        with no Firebase project - must have a row to poll, or the app has nothing to show.
        """
        container, fake_push = push_service()
        group = factory.group(code="GRP-NODEVICE")
        operator = _operator(factory, group)
        device_store.register(
            factory.session,
            container,
            user_id=operator.id,
            installation_id="handset-without-a-token",
            push_token=None,
        )
        factory.session.commit()
        intent = _intent(camera=_camera(factory, group))
        report = enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        # Recorded, and counted as zero push targets: nothing about this alert will be sent.
        assert (report.created, report.suppressed, report.devices_targeted) == (1, 0, 0)
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.PENDING.value

        dispatch = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert (dispatch.in_app_only, dispatch.attempted, dispatch.without_device) == (1, 0, 0)
        assert fake_push.calls == []
        assert note.state == NotificationState.SUPPRESSED.value
        assert note.failure_reason == "in_app_only"
        assert (
            factory.session.scalars(
                select(NotificationAttempt).where(NotificationAttempt.notification_id == note.id)
            ).all()
            == []
        )

    def test_a_person_who_has_never_signed_in_on_a_handset_is_not_recorded(self, container, factory):
        group = factory.group(code="GRP-NOHANDSET")
        operator = _operator(factory, group)
        factory.session.commit()
        report = enqueue_alert(factory.session, container.settings, _intent(camera=_camera(factory, group)))
        factory.session.commit()
        assert (report.created, report.suppressed, report.devices_targeted) == (0, 0, 0)
        assert factory.session.scalars(
            select(Notification).where(Notification.recipient_id == operator.id)
        ).all() == []

    def test_a_revoked_handset_is_not_treated_as_a_screen_to_read_on(self, container, factory):
        group = factory.group(code="GRP-REVOKED")
        operator = _operator(factory, group)
        device = _handset(container, factory, operator, "handset-revoked")
        device.push_state = PushState.REVOKED.value
        factory.session.commit()
        report = enqueue_alert(factory.session, container.settings, _intent(camera=_camera(factory, group)))
        factory.session.commit()
        assert (report.created, report.devices_targeted) == (0, 0)

    def test_the_devices_targeted_count_is_devices_not_recipients(self, container, factory):
        group = factory.group(code="GRP-TWOHANDSETS")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-one")
        _handset(container, factory, operator, "handset-two", push_token=TOKEN_B)
        report = enqueue_alert(factory.session, container.settings, _intent(camera=_camera(factory, group)))
        factory.session.commit()
        assert (report.created, report.devices_targeted) == (1, 2)


class TestPushDispatch:
    def test_an_accepted_send_is_recorded_as_accepted_by_the_provider(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-ACCEPT")
        camera = _camera(factory, group)
        incident = factory.incident(camera=camera, severity=Severity.HIGH.value)
        operator = _operator(factory, group)
        device = _handset(container, factory, operator, "handset-op")
        intent = _intent(incident=incident, camera=camera)
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        report = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert report.as_dict() == {
            "devices_targeted": 1,
            "accepted_by_fcm": 1,
            "failed": 0,
            "scheduled_for_retry": 0,
            "devices_invalidated": 0,
            "recipients_without_device": 0,
            "recorded_in_app_only": 0,
        }
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.DELIVERED.value
        assert note.delivered_at is not None
        assert note.failure_reason is None

        attempt = factory.session.scalars(
            select(NotificationAttempt).where(NotificationAttempt.notification_id == note.id)
        ).all()[0]
        assert attempt.state == AttemptState.ACCEPTED.value
        assert attempt.provider_message_id == "projects/test/messages/1"
        assert attempt.accepted_at is not None and attempt.failed_at is None
        assert attempt.provider == "fcm"
        assert attempt.idempotency_key == f"push:{note.id}:{device.id}:1:{note.dedupe_key}"
        assert fake_push.tokens == [f"{TOKEN_A}-{operator.id}"]

    def test_the_payload_carries_only_the_fields_the_contract_lists(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-PAYLOAD")
        camera = _camera(factory, group)
        incident = factory.incident(camera=camera, severity=Severity.HIGH.value)
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(incident=incident, camera=camera, body="Detailed summary of the finding.")
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        data = fake_push.calls[0]["data"]
        assert set(data) == {
            "notification_id",
            "device_id",
            "kind",
            "severity",
            "title",
            "incident_id",
            "deep_link",
            "camera_name",
        }
        assert data["deep_link"] == f"watchtower://incidents/{incident.id}"
        assert data["camera_name"] == "Gate north"
        # A push traverses Google's servers and shows on a locked screen: no summary text, no
        # evidence link, no asset token anywhere in it.
        assert "Detailed summary" not in json.dumps(data)
        assert "token=" not in json.dumps(data)
        assert "evidence" not in json.dumps(data)

    def test_a_retryable_refusal_stays_queued_and_the_next_pass_uses_the_next_ordinal(
        self, push_service, factory
    ):
        container, _push = push_service(
            _failure("temporarily_unavailable", "Throttled.", retryable=True),
            _failure("temporarily_unavailable", "Still throttled.", retryable=True),
            _accepted("projects/test/messages/42"),
        )
        group = factory.group(code="GRP-RETRY")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        for ordinal in range(1, 4):
            report = dispatch_pushes(factory.session, container)
            factory.session.commit()
            if ordinal < MAX_SEND_ATTEMPTS:
                assert report.retried == 1, ordinal
                assert _rows(factory.session, intent)[0].state == NotificationState.PENDING.value
            else:
                assert report.accepted == 1

        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.DELIVERED.value
        attempts = factory.session.scalars(
            select(NotificationAttempt)
            .where(NotificationAttempt.notification_id == note.id)
            .order_by(NotificationAttempt.id)
        ).all()
        assert [attempt.state for attempt in attempts] == [
            AttemptState.FAILED.value,
            AttemptState.FAILED.value,
            AttemptState.ACCEPTED.value,
        ]
        assert attempts[0].error_code == "temporarily_unavailable"
        assert {attempt.idempotency_key.split(":")[3] for attempt in attempts} == {"1", "2", "3"}

    def test_the_last_allowed_attempt_fails_the_alert_instead_of_retrying_forever(
        self, push_service, factory
    ):
        throttled = _failure("temporarily_unavailable", "Throttled.", retryable=True)
        container, _push = push_service(*[throttled] * MAX_SEND_ATTEMPTS)
        group = factory.group(code="GRP-GIVEUP")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        for _ in range(MAX_SEND_ATTEMPTS - 1):
            assert dispatch_pushes(factory.session, container).retried == 1
            factory.session.commit()
        final = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert (final.retried, final.failed) == (0, 1)
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.FAILED.value
        assert note.failure_reason == "Throttled."

    def test_a_dead_registration_token_invalidates_only_that_device(self, push_service, factory):
        def answer(token):
            if token == TOKEN_A:
                return _failure(
                    "unregistered",
                    "The registration token is no longer valid.",
                    token_is_dead=True,
                )
            return _accepted("projects/test/messages/7")

        container, _push = push_service(answer)
        group = factory.group(code="GRP-DEADTOKEN")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-dead", push_token=TOKEN_A)
        _handset(container, factory, operator, "handset-live", push_token=TOKEN_B)
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        report = dispatch_pushes(factory.session, container)
        factory.session.commit()

        assert (report.accepted, report.devices_invalidated) == (1, 1)
        by_installation = {
            row.installation_id: row for row in _devices_for(factory.session, operator.id)
        }
        dead = by_installation["handset-dead"]
        live = by_installation["handset-live"]
        assert dead.push_state == PushState.INVALID.value
        assert dead.invalid_reason == "unregistered"
        assert dead.push_token_ciphertext is None
        assert live.push_state == PushState.ACTIVE.value
        assert live.push_token_ciphertext is not None
        # One handset going dead does not fail the alert for the person's other phones.
        assert _rows(factory.session, intent)[0].state == NotificationState.DELIVERED.value

    def test_a_stored_token_that_cannot_be_opened_is_reported_not_retried(
        self, push_service, factory
    ):
        container, push = push_service()
        group = factory.group(code="GRP-UNSEAL")
        operator = _operator(factory, group)
        device = _handset(container, factory, operator, "handset-op")
        device.push_token_ciphertext = b"this-is-not-a-sealed-token"
        factory.session.commit()
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        report = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert (report.failed, report.devices_invalidated, push.calls) == (1, 1, [])
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.FAILED.value
        assert note.failure_reason == "token_unavailable"
        attempt = factory.session.scalars(
            select(NotificationAttempt).where(NotificationAttempt.notification_id == note.id)
        ).all()[0]
        assert attempt.error_code == "token_unavailable"
        assert (
            device_store.find(
                factory.session, user_id=operator.id, installation_id="handset-op"
            ).push_state
            == PushState.INVALID.value
        )

    def test_a_recipient_whose_only_token_died_still_sees_the_alert_in_app(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-DEADTOKEN")
        operator = _operator(factory, group)
        device = _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        device_store.mark_invalid(factory.session, device, "unregistered")
        factory.session.commit()
        report = dispatch_pushes(factory.session, container)
        factory.session.commit()
        # A token FCM no longer recognises is not a phone that has gone away: the handset is still
        # in the officer's pocket and still reads its queue, so the alert is left where they can
        # see it rather than reported as a failure.
        assert (report.in_app_only, report.attempted, fake_push.calls) == (1, 0, [])
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.SUPPRESSED.value
        assert note.failure_reason == "in_app_only"

    def test_a_recipient_whose_only_handset_was_forgotten_fails_with_the_reason(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-VANISHED")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        # The person pressed "forget this device": there is no screen left to show the alert on.
        device_store.deactivate(factory.session, user_id=operator.id, installation_id="handset-op")
        factory.session.commit()
        report = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert (report.without_device, report.attempted, fake_push.calls) == (1, 0, [])
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.FAILED.value
        assert note.failure_reason == "no_active_device"

    def test_a_second_pass_does_not_send_what_was_already_accepted(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-TWICE")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        enqueue_alert(factory.session, container.settings, _intent(camera=_camera(factory, group)))
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()
        second = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert second.attempted == 0
        assert len(fake_push.calls) == 1

    def test_nothing_in_the_vocabulary_claims_a_human_saw_the_alert(
        self, push_service, factory
    ):
        """FCM acceptance is the strongest statement delivery is allowed to make.

        Android may defer the wake-up and the person may dismiss the banner unread, so the report
        that leaves this module stops at what the provider answered.
        """
        container, _push = push_service()
        group = factory.group(code="GRP-WORDS")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        report = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert report.as_dict()["accepted_by_fcm"] == 1
        assert "read" not in json.dumps(report.as_dict())
        assert _rows(factory.session, intent)[0].read_at is None


class TestAndroidPresentation:
    """What the handset is actually told to display.

    These are wire-format assertions, and they exist because the format had no coverage at all:
    the payload named one shared channel and one custom click action, neither of which the Android
    app declares. Android discards a notification whose `channel_id` does not exist on the handset
    and cannot resolve a tap whose `click_action` matches no intent filter, so both faults produced
    a send this service reported as accepted and a phone that stayed silent.
    """

    def test_every_severity_is_sent_to_a_channel_the_app_creates(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-CHANNEL")
        camera = _camera(factory, group)
        app_channels = _app_channel_ids()

        for severity in Severity:
            operator = _operator(factory, group, username=f"op.{severity.value}")
            _handset(container, factory, operator, f"handset-{severity.value}")
            intent = _intent(
                camera=camera, severity=severity.value, title=f"Reference {severity.value}"
            )
            enqueue_alert(factory.session, container.settings, intent)
            factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        assert len(fake_push.calls) == len(Severity)
        for call in fake_push.calls:
            payload = build_payload(
                token="t",
                title=call["title"],
                body=call["body"],
                data=call["data"],
            )
            channel = payload["message"]["android"]["notification"]["channel_id"]
            assert channel in app_channels, f"{call['data']['severity']} -> unknown channel {channel}"

    def test_a_camera_health_alert_uses_the_health_channel_not_the_incident_one(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-HEALTH-CH")
        technician = factory.user(
            username="tech.health", roles=("technical_operator",), camera_group_id=group.id
        )
        _handset(container, factory, technician, "handset-health")
        intent = _intent(
            camera=_camera(factory, group),
            kind=KIND_HEALTH,
            severity=Severity.MEDIUM.value,
            title="Camera 4 stopped reporting",
            # A hardware alert asks nobody to act, which is why it is read under `health.view`
            # and reaches the technical operator rather than the security operator.
            requires_action=False,
        )
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        payload = build_payload(
            token="t",
            title=fake_push.calls[0]["title"],
            body=fake_push.calls[0]["body"],
            data=fake_push.calls[0]["data"],
        )
        assert (
            payload["message"]["android"]["notification"]["channel_id"]
            == "watchtower-camera-health"
        )

    def test_the_android_block_carries_the_title_because_android_displays_that_block(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-TITLE")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(
            camera=_camera(factory, group),
            title="Person at the north gate",
            body="Loitering by the barrier for eleven minutes.",
        )
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        notification = build_payload(
            token="t",
            title=fake_push.calls[0]["title"],
            body=fake_push.calls[0]["body"],
            data=fake_push.calls[0]["data"],
        )["message"]["android"]["notification"]
        assert notification["title"] == "Person at the north gate"
        # The body is the operator's own sentence. `data` never held it and the notification block
        # must not either: a lock screen shows this text to anyone standing next to the phone.
        assert "body" not in notification
        assert "Loitering" not in json.dumps(notification)

    def test_a_notification_message_names_no_click_action_so_the_tap_opens_the_app(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-TAP")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group), incident=factory.incident(
            camera=_camera(factory, group, name="Gate south"), severity=Severity.HIGH.value
        ))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        notification = build_payload(
            token="t",
            title=fake_push.calls[0]["title"],
            body=fake_push.calls[0]["body"],
            data=fake_push.calls[0]["data"],
        )["message"]["android"]["notification"]
        # With no action of its own, Android launches the app with the payload attached, which is
        # how the Capacitor plugin learns to fire `pushNotificationActionPerformed` and let the
        # app follow `deep_link` itself. A custom action the manifest never declared resolves to
        # nothing, and the officer tapping a critical alert would get no screen at all.
        assert "click_action" not in notification
        assert fake_push.calls[0]["data"]["deep_link"].startswith("watchtower://incidents/")

    def test_a_silent_preference_reaches_the_payload(self, push_service, factory):
        container, fake_push = push_service()
        group = factory.group(code="GRP-QUIET")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(factory, operator, sound="silent")
        intent = _intent(camera=_camera(factory, group), severity=Severity.MEDIUM.value)
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        assert fake_push.calls[0]["sound"] == "silent"
        notification = build_payload(
            token="t",
            title=fake_push.calls[0]["title"],
            body=fake_push.calls[0]["body"],
            data=fake_push.calls[0]["data"],
            sound=fake_push.calls[0]["sound"],
        )["message"]["android"]["notification"]
        assert notification["sound"] == ""

    def test_a_forced_alert_is_not_quieted_by_the_recipient_who_asks_for_quiet(
        self, push_service, factory
    ):
        container, fake_push = push_service()
        group = factory.group(code="GRP-FORCED")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        _preference(factory, operator, sound="silent")
        intent = _intent(camera=_camera(factory, group), severity=Severity.CRITICAL.value)
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        # `critical` is in `forced_alerts`: the same list that overrides quiet hours must
        # override a silenced ringer, or the setting would be a way to opt out of duty.
        assert fake_push.calls[0]["sound"] == "default"


class TestNoFirebase:
    def test_a_host_without_a_firebase_project_reports_the_failure(self, cloud_app, factory):
        """The production default: no credentials, no pretence.

        Nothing is injected here - `cloud_settings` names no Firebase project, so the container
        builds the real `DisabledSender`.
        """
        container = cloud_app.app.state.container
        assert container.push.configured is False
        assert cloud_app.get("/healthz").json()["push"] == "disabled"

        group = factory.group(code="GRP-NOFCM")
        operator = _operator(factory, group)
        _handset(container, factory, operator, "handset-op")
        intent = _intent(camera=_camera(factory, group))
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()

        report = dispatch_pushes(factory.session, container)
        factory.session.commit()
        assert (report.failed, report.accepted) == (1, 0)
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.FAILED.value
        assert "Firebase" in note.failure_reason
        attempt = factory.session.scalars(
            select(NotificationAttempt).where(NotificationAttempt.notification_id == note.id)
        ).all()[0]
        assert attempt.error_code == "not_configured"

    def test_a_handset_with_no_push_channel_reads_its_alert_over_http(self, signed_in, factory):
        """Contract §10.7 end to end: no Firebase project, no token, alert still reachable.

        Four things have to hold for foreground polling to be worth running at all: the row is
        recorded, the queue lists it, the badge counts it, and opening it clears the badge.
        """
        group = factory.group(code="GRP-INAPP-HTTP")
        handset = signed_in(
            "security_operator", username="op.inapp.http", group_id=group.id, push_token=None
        )
        container = handset.client.app.state.container
        camera = factory.camera(group_id=group.id, display_name="North barrier")
        factory.session.commit()

        intent = _intent(camera=camera)
        enqueue_alert(factory.session, container.settings, intent)
        factory.session.commit()
        dispatch_pushes(factory.session, container)
        factory.session.commit()

        listed = handset.actor.get("/api/v1/notifications").json()
        assert [item["state"] for item in listed["items"]] == ["suppressed"]
        assert listed["total_unread"] == 1

        note_id = listed["items"][0]["id"]
        read = handset.actor.post(f"/api/v1/notifications/{note_id}/read")
        assert read.status_code == 200, read.text
        assert (read.json()["state"], read.json()["read_at"] is not None) == ("read", True)

        after = handset.actor.get("/api/v1/notifications").json()
        assert after["total_unread"] == 0
        assert [item["state"] for item in after["items"]] == ["read"]

    def test_a_container_refuses_a_second_push_sender(self, cloud_app):
        from watchtower.cloud.deps import CloudContainer

        spare = CloudContainer(cloud_app.app.state.settings)
        spare.use_push_sender(FakePush())
        with pytest.raises(RuntimeError):
            spare.use_push_sender(FakePush())
        assert spare.push.configured is True


class TestEscalationSweep:
    def _critical(self, container, factory):
        group = factory.group(code="GRP-ESCALATE")
        supervisor = _supervisor(factory, group)
        operator = _operator(factory, group)
        administrator = _administrator(factory, group)
        for index, user in enumerate((supervisor, operator, administrator)):
            _handset(container, factory, user, f"handset-{index}")
        camera = _camera(factory, group)
        incident = factory.incident(camera=camera, severity=Severity.CRITICAL.value)
        enqueue_alert(
            factory.session,
            container.settings,
            _intent(incident=incident, camera=camera, severity=Severity.CRITICAL.value),
        )
        factory.session.commit()
        return group, camera, supervisor, administrator, incident

    def test_only_a_stale_critical_incident_qualifies(self, container, factory):
        from watchtower.cloud.worker import eligible_for_escalation

        _group, _camera, _sup, _admin, incident = self._critical(container, factory)
        interval = container.settings.escalate_after_seconds

        assert eligible_for_escalation(factory.session, container.settings, now=_due()) == []
        due = _due(seconds=interval + 10)
        assert [pair[0].id for pair in eligible_for_escalation(
            factory.session, container.settings, now=due
        )] == [incident.id]
        assert [stage for _incident, stage in eligible_for_escalation(
            factory.session, container.settings, now=due
        )] == [0]

    def test_a_non_critical_incident_is_never_escalated(self, container, factory):
        from watchtower.cloud.worker import eligible_for_escalation

        group = factory.group(code="GRP-MEDIUM")
        supervisor = _supervisor(factory, group)
        _handset(container, factory, supervisor, "handset-sup")
        camera = _camera(factory, group)
        incident = factory.incident(camera=camera, severity=Severity.MEDIUM.value)
        enqueue_alert(
            factory.session,
            container.settings,
            _intent(incident=incident, camera=camera, severity=Severity.MEDIUM.value),
        )
        factory.session.commit()
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        assert eligible_for_escalation(factory.session, container.settings, now=due) == []

    def test_an_acknowledged_incident_stops_being_re_paged(self, container, factory):
        from watchtower.cloud.worker import eligible_for_escalation

        _group, _camera, supervisor, _admin, incident = self._critical(container, factory)
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        assert eligible_for_escalation(factory.session, container.settings, now=due)

        factory.session.add(
            IncidentAcknowledgement(
                incident_id=incident.id,
                user_id=supervisor.id,
                source="mobile",
                acknowledged_at=due,
            )
        )
        factory.session.commit()
        assert eligible_for_escalation(factory.session, container.settings, now=due) == []

    def test_a_resolved_incident_stops_being_re_paged(self, container, factory):
        from watchtower.cloud.worker import eligible_for_escalation

        _group, _camera, _sup, _admin, incident = self._critical(container, factory)
        incident.status = IncidentStatus.RESOLVED.value
        factory.session.commit()
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        assert eligible_for_escalation(factory.session, container.settings, now=due) == []

    def test_the_two_stages_page_the_supervisors_then_the_administrators(
        self, container, factory
    ):
        from watchtower.cloud.worker import escalate_once

        _group, _camera, supervisor, administrator, incident = self._critical(container, factory)
        interval = container.settings.escalate_after_seconds

        first = escalate_once(factory.session, container.settings, now=_due(seconds=interval + 10))
        factory.session.commit()
        assert [
            (item["stage"], item["roles"], item["notifications_created"]) for item in first
        ] == [("escalated-1", ["security_supervisor"], 1)]

        second = escalate_once(factory.session, container.settings, now=_due(seconds=2 * interval + 10))
        factory.session.commit()
        assert [
            (item["stage"], item["roles"], item["notifications_created"]) for item in second
        ] == [("escalated-2", ["system_administrator"], 1)]
        # An administrator cannot acknowledge an incident, so this stage must not demand an action
        # they cannot take: marked actionable it would filter them out and the escalation would
        # reach nobody while looking like it had run.
        escalated = factory.session.scalars(
            select(Notification)
            .where(Notification.kind == "incident.escalated")
            .order_by(Notification.id)
        ).all()
        assert [row.recipient_id for row in escalated] == [supervisor.id, administrator.id]
        assert [row.dedupe_key for row in escalated] == [
            f"incident.escalated:incident:{incident.id}:escalated-1",
            f"incident.escalated:incident:{incident.id}:escalated-2",
        ]
        assert all(row.severity == Severity.CRITICAL.value for row in escalated)
        assert "assign one" in escalated[1].body

        third = escalate_once(factory.session, container.settings, now=_due(seconds=6 * interval))
        factory.session.commit()
        assert third == []

    def test_running_the_sweep_twice_never_repeats_a_stage(self, container, factory):
        from watchtower.cloud.worker import escalate_once

        _group, _camera, _sup, _admin, incident = self._critical(container, factory)
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        escalate_once(factory.session, container.settings, now=due)
        factory.session.commit()
        escalate_once(factory.session, container.settings, now=due)
        factory.session.commit()
        rows = factory.session.scalars(
            select(Notification).where(Notification.kind == "incident.escalated")
        ).all()
        assert sorted(row.dedupe_key for row in rows) == [
            f"incident.escalated:incident:{incident.id}:escalated-1",
            f"incident.escalated:incident:{incident.id}:escalated-2",
        ]

    def test_one_tick_dispatches_and_then_escalates(self, push_service, factory):
        from watchtower.cloud.worker import run_once

        container, fake_push = push_service()
        _group, _camera, _sup, _admin, incident = self._critical(container, factory)
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        report = run_once(factory.session, container, now=due)
        factory.session.commit()
        assert report.errors == []
        # Two of the three accounts in this estate can answer a critical alert: the operator and
        # the supervisor. The escalation the same tick queues is not sent until the next one,
        # because dispatch runs before it.
        assert report.dispatched["accepted_by_fcm"] == 2
        assert report.escalated == [incident.reference]
        assert len(fake_push.calls) == 2

    def test_a_batch_that_raises_does_not_stop_the_other_job(self, push_service, factory):
        from watchtower.cloud.worker import run_once

        container, _push = push_service(RuntimeError("the socket closed mid-send"))
        _group, camera, _sup, _admin, incident = self._critical(container, factory)
        intent = _intent(incident=incident, camera=camera, severity=Severity.CRITICAL.value)
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        report = run_once(factory.session, container, now=due)
        _reload(factory.session)

        assert [error.split(":")[0] for error in report.errors] == ["dispatch"]
        assert report.escalated == [incident.reference]
        # The dispatch's own writes go back with it: the alert is still queued for the next tick,
        # with no half-recorded attempt behind it.
        note = _rows(factory.session, intent)[0]
        assert note.state == NotificationState.PENDING.value
        assert factory.session.scalars(
            select(NotificationAttempt).where(NotificationAttempt.notification_id == note.id)
        ).all() == []

    def test_a_delivery_only_tick_pages_and_never_runs_the_sweep(self, push_service, factory):
        from watchtower.cloud.worker import DELIVERY, run_once

        container, fake_push = push_service()
        _group, _camera, _sup, _admin, _incident = self._critical(container, factory)
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        report = run_once(factory.session, container, now=due, jobs=DELIVERY)
        factory.session.commit()

        assert report.errors == []
        assert report.dispatched["accepted_by_fcm"] == 2
        assert report.escalated == []
        assert len(fake_push.calls) == 2
        # The deadline had passed, so the same moment with both jobs selected queues a re-page.
        # Selecting one job has to leave the other untouched, not merely unreported.
        assert factory.session.scalars(
            select(Notification).where(Notification.kind == "incident.escalated")
        ).all() == []

    def test_an_escalation_only_tick_queues_the_re_page_without_calling_the_provider(
        self, push_service, factory
    ):
        from watchtower.cloud.worker import ESCALATION, run_once

        container, fake_push = push_service()
        _group, _camera, _sup, _admin, incident = self._critical(container, factory)
        due = _due(seconds=container.settings.escalate_after_seconds + 10)
        report = run_once(factory.session, container, now=due, jobs=ESCALATION)
        factory.session.commit()

        assert report.errors == []
        assert report.escalated == [incident.reference]
        assert fake_push.calls == []
        # Nothing was dispatched, which is the point of splitting the processes: the re-page sits
        # in the queue for the delivery worker to find, exactly as the first alert still does.
        assert report.dispatched == {}
        queued = factory.session.scalars(
            select(Notification).where(Notification.kind == "incident.escalated")
        ).all()
        assert len(queued) == 1
        assert queued[0].state == NotificationState.PENDING.value


class TestWorkerLoopArithmetic:
    def _worker(self, container, factory, jobs=None):
        from watchtower.cloud.worker import CloudWorker

        return CloudWorker(
            container.settings,
            lambda: factory.session,
            container,
            idle_seconds=2.0,
            jobs=jobs,
        )

    def test_the_sleep_grows_after_repeated_failures_and_caps(self, container, factory):
        worker = self._worker(container, factory)
        assert worker._next_sleep(None) == pytest.approx(4.0)
        worker.consecutive_failures = 3
        assert worker._next_sleep(None) == pytest.approx(16.0)
        worker.consecutive_failures = 10
        assert worker._next_sleep(None) == pytest.approx(30.0)

    def test_a_busy_tick_sleeps_less_than_an_idle_one(self, container, factory):
        from watchtower.cloud.worker import TickReport

        worker = self._worker(container, factory)
        assert worker._next_sleep(TickReport(dispatched={"devices_targeted": 3})) == pytest.approx(2.0)
        assert worker._next_sleep(TickReport()) == pytest.approx(4.0)

    def test_a_re_page_counts_as_busy_for_a_worker_that_only_escalates(self, container, factory):
        from watchtower.cloud.worker import TickReport

        worker = self._worker(container, factory, jobs="escalation")
        # A sweep that found something stale is doing work; idling out at the 30-second ceiling
        # because no push went out this tick would delay the next look at the same incident.
        assert worker._next_sleep(TickReport(escalated=["WT-1"])) == pytest.approx(2.0)

    def test_the_loop_only_runs_the_jobs_it_was_started_with(self, container, factory, monkeypatch):
        from watchtower.cloud import worker as worker_module

        asked_for: list = []

        def spy(session, cont, *, now=None, jobs=None):
            del session, cont, now
            asked_for.append(jobs)
            return worker_module.TickReport()

        monkeypatch.setattr(worker_module, "run_once", spy)

        self._worker(container, factory)._tick()
        self._worker(container, factory, jobs="delivery")._tick()
        self._worker(container, factory, jobs="escalation")._tick()
        assert asked_for == [worker_module.ALL_JOBS, frozenset({"delivery"}), frozenset({"escalation"})]
        # `build_worker` is what the served process calls, so it has to forward the choice too.
        assert worker_module.build_worker(container, jobs="delivery").jobs == frozenset({"delivery"})

    def test_a_container_with_no_session_factory_builds_no_worker(self, cloud_app):
        from watchtower.cloud.deps import CloudContainer
        from watchtower.cloud.worker import build_worker

        spare = CloudContainer(cloud_app.app.state.settings)
        assert build_worker(spare) is None
