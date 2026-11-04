"""The live channel (contract section 10.8).

Four promises are checked here, and they are separable on purpose:

  * **scoping** - a handset is told about rows addressed to it and activity on incidents it may
    already read. Nothing else crosses an open stream, because a stream is one long-lived
    authorisation and is the easiest place for a scope rule to be forgotten.
  * **position** - the cursor only moves forward, a fresh connection starts at the end of both
    feeds instead of replaying history, and a resume replays exactly what was missed.
  * **lifetime** - the connection ends when it must and says why: at the cap, or because the
    database stopped answering, or because the client went away.
  * **the wire** - real SSE frames, over a real route, to a bearer token.

The route is exercised against a service whose stream lifetime is a fraction of a second: the
test transport collects a response body only once the application has finished writing it, so a
route that stayed open for its production ten minutes would hang the suite rather than prove
anything. The behaviour that needs a connection to *stay* open is tested against `stream_frames`
directly, where a scripted reader says "nothing yet" and then produces rows.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from sqlalchemy import select

from watchtower.cloud.deps import Caller
from watchtower.cloud.streaming import (
    Cursor,
    StreamEvent,
    StreamRoom,
    drain,
    latest_cursor,
    stream_frames,
)
from watchtower.models import (
    IncidentAction,
    Notification,
    NotificationState,
    Severity,
)

from conftest import INSTALLATION_ID, Personnel, TEST_PASSWORD


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


def _caller(factory, user) -> Caller:
    return Caller(
        principal=factory.principal(user),
        user_id=user.id,
        session_id="stream-test",
        must_change_password=False,
        source_ip=None,
        installation_id=INSTALLATION_ID,
    )


def _reload(session) -> None:
    """Let the app's separate connection see what the harness session just wrote."""
    session.commit()
    session.expire_all()


def _note(factory, recipient_id: int, *, marker: str, **values) -> Notification:
    note = Notification(
        kind=values.pop("kind", "restricted_area_entry"),
        title=values.pop("title", "Potential restricted-area entry"),
        body=values.pop("body", "Detected at the main entrance."),
        severity=values.pop("severity", Severity.HIGH.value),
        channel=values.pop("channel", "mobile_push"),
        state=values.pop("state", NotificationState.PENDING.value),
        dedupe_key=f"stream:{marker}",
        recipient_id=recipient_id,
        camera_id=values.pop("camera_id", None),
        incident_id=values.pop("incident_id", None),
    )
    factory.session.add(note)
    factory.session.flush()
    return note


def _action(factory, incident, *, action: str = "acknowledged", actor=None) -> IncidentAction:
    row = IncidentAction(
        incident_id=incident.id,
        action=action,
        note=f"{action} from the live-stream test",
        actor_id=actor.id if actor is not None else None,
    )
    factory.session.add(row)
    factory.session.flush()
    return row


def _parse_frames(body: str) -> list[tuple[str, dict]]:
    """SSE frames back into `(name, payload)` pairs, in the order they were written."""
    frames = []
    for block in body.split("\n\n"):
        name = data = None
        for line in block.splitlines():
            if line.startswith("event: "):
                name = line[len("event: ") :].strip()
            elif line.startswith("data: "):
                data = json.loads(line[len("data: ") :])
        if name is not None:
            frames.append((name, data))
    return frames


def _names(body: str) -> list[str]:
    return [name for name, _ in _parse_frames(body)]


class _SilentSession:
    """A reader that answers "nothing yet" for its first passes.

    The alternative is a thread writing into SQLite while the stream polls it, which turns a
    determinate test into a locking race. The rows are still real: once the scripted silence is
    spent the factory hands out a genuine session.
    """

    def __init__(self, inner) -> None:
        self._inner = inner
        self.silent_passes = 0
        self.passes = 0

    def __call__(self):
        self.passes += 1
        return _NothingSession() if self.passes <= self.silent_passes else self._inner()


class _NothingResult:
    def all(self):
        return []


class _NothingSession:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def scalars(self, _statement):
        return _NothingResult()

    def execute(self, _statement):
        return _NothingResult()


class _BrokenFactory:
    """Every read raises, the way a pool does when the database host disappears."""

    def __call__(self):
        raise RuntimeError("connection to server at 10.0.0.1 failed: refused (0x0)")


def _collect(generator) -> str:
    async def _run():
        return "".join([frame async for frame in generator])

    return asyncio.run(_run())


# --------------------------------------------------------------------------- #
# the cursor and the room
# --------------------------------------------------------------------------- #


class TestCursor:
    def test_a_cursor_round_trips_through_its_wire_form(self):
        assert Cursor.parse(Cursor(7, 12).encode()) == Cursor(7, 12)

    @pytest.mark.parametrize(
        "raw", [None, "", "   ", "7", "7:", "a:1", "1:2:3", "-1:0", "1:-1", "1" * 13 + ":0"]
    )
    def test_a_cursor_the_service_cannot_read_is_refused_not_guessed(self, raw):
        # Anything but `None` here would mean "from the beginning of the table", which is a
        # history replay dressed up as a resume.
        assert Cursor.parse(raw) is None


class TestStreamRoom:
    def test_the_room_refuses_once_it_is_full_and_frees_a_slot_again(self):
        room = StreamRoom(2)
        assert room.acquire() and room.acquire()
        assert not room.acquire()
        assert room.refusals == 1
        room.release()
        assert room.acquire()

    def test_releasing_an_empty_room_cannot_go_negative(self):
        room = StreamRoom(1)
        room.release()
        assert room.open == 0


# --------------------------------------------------------------------------- #
# what a drain reads
# --------------------------------------------------------------------------- #


class TestDrainScoping:
    def test_a_new_alert_addressed_to_the_caller_is_streamed(self, factory, cloud_settings):
        officer = factory.user(username="stream.operator", roles=("security_operator",))
        note = _note(factory, officer.id, marker="own")
        _reload(factory.session)

        events = drain(
            factory.session, _caller(factory, officer), cloud_settings, Cursor(0, 0)
        ).events
        assert [event.name for event in events] == ["notification"]
        assert events[0].data["id"] == note.id
        assert events[0].data["severity"] == Severity.HIGH.value
        assert events[0].data["state"] == NotificationState.PENDING.value

    def test_an_alert_on_an_incident_carries_the_reference_and_the_deep_link(
        self, factory, cloud_settings
    ):
        officer = factory.user(username="stream.linked", roles=("security_operator",))
        camera = factory.camera(code="CAM-STREAM-LINK")
        incident = factory.incident(camera)
        _note(factory, officer.id, marker="linked", incident_id=incident.id, camera_id=camera.id)
        _reload(factory.session)

        data = drain(
            factory.session, _caller(factory, officer), cloud_settings, Cursor(0, 0)
        ).events[0].data
        assert data["incident_reference"] == incident.reference
        assert data["deep_link"].endswith(f"incidents/{incident.id}")
        assert data["camera_name"] == camera.display_name

    def test_an_alert_addressed_to_another_officer_is_not_streamed(
        self, factory, cloud_settings
    ):
        me = factory.user(username="stream.me", roles=("security_operator",))
        other = factory.user(username="stream.other", roles=("security_operator",))
        _note(factory, other.id, marker="not-mine", title="Someone else's alert")
        _reload(factory.session)
        assert (
            drain(factory.session, _caller(factory, me), cloud_settings, Cursor(0, 0)).events
            == []
        )

    def test_activity_on_an_incident_inside_the_camera_grant_is_streamed(
        self, factory, cloud_settings
    ):
        group = factory.group(code="GRP-STREAM-A")
        officer = factory.user(
            username="stream.scoped", roles=("security_operator",), camera_group_id=group.id
        )
        camera = factory.camera(code="CAM-STREAM-A", group_id=group.id)
        incident = factory.incident(camera)
        action = _action(factory, incident, actor=officer)
        _reload(factory.session)

        events = drain(
            factory.session, _caller(factory, officer), cloud_settings, Cursor(0, 0)
        ).events
        assert [row.name for row in events] == ["incident_activity"]
        assert events[0].data["id"] == action.id
        assert events[0].data["incident_reference"] == incident.reference
        assert events[0].data["actor_name"] == officer.display_name

    def test_activity_on_an_incident_outside_the_camera_grant_is_not_streamed(
        self, factory, cloud_settings
    ):
        mine = factory.group(code="GRP-STREAM-B")
        theirs = factory.group(code="GRP-STREAM-C")
        officer = factory.user(
            username="stream.scoped.two", roles=("security_operator",), camera_group_id=mine.id
        )
        _action(factory, factory.incident(factory.camera(code="CAM-STREAM-B", group_id=mine.id)))
        _action(
            factory,
            factory.incident(factory.camera(code="CAM-STREAM-C", group_id=theirs.id)),
            action="escalated",
        )
        _reload(factory.session)

        events = drain(
            factory.session, _caller(factory, officer), cloud_settings, Cursor(0, 0)
        ).events
        assert [row.data["action"] for row in events] == ["acknowledged"]

    def test_an_institution_wide_grant_sees_activity_on_every_camera(
        self, factory, cloud_settings
    ):
        first = factory.group(code="GRP-STREAM-D")
        second = factory.group(code="GRP-STREAM-E")
        admin = factory.user(username="stream.admin", roles=("system_administrator",))
        _action(
            factory, factory.incident(factory.camera(code="CAM-STREAM-D", group_id=first.id))
        )
        _action(
            factory, factory.incident(factory.camera(code="CAM-STREAM-E", group_id=second.id))
        )
        _reload(factory.session)

        events = drain(
            factory.session, _caller(factory, admin), cloud_settings, Cursor(0, 0)
        ).events
        assert len(events) == 2

    def test_an_incident_with_no_camera_stays_visible_to_any_holder_of_the_permission(
        self, factory, cloud_settings
    ):
        group = factory.group(code="GRP-STREAM-F")
        officer = factory.user(
            username="stream.nocam", roles=("security_operator",), camera_group_id=group.id
        )
        _action(factory, factory.incident(None), actor=officer)
        _reload(factory.session)

        events = drain(
            factory.session, _caller(factory, officer), cloud_settings, Cursor(0, 0)
        ).events
        assert [row.name for row in events] == ["incident_activity"]


class TestDrainPosition:
    def test_a_second_drain_from_the_returned_cursor_repeats_nothing(
        self, factory, cloud_settings
    ):
        officer = factory.user(username="stream.once", roles=("security_operator",))
        _note(factory, officer.id, marker="first")
        _reload(factory.session)

        caller = _caller(factory, officer)
        first = drain(factory.session, caller, cloud_settings, Cursor(0, 0))
        assert len(first.events) == 1
        assert drain(factory.session, caller, cloud_settings, first.cursor).events == []

    def test_the_callers_own_cursor_is_not_moved_by_a_drain(self, factory, cloud_settings):
        officer = factory.user(username="stream.immutable", roles=("security_operator",))
        _note(factory, officer.id, marker="one")
        _reload(factory.session)

        position = Cursor(0, 0)
        drain(factory.session, _caller(factory, officer), cloud_settings, position)
        assert position == Cursor(0, 0)

    def test_resuming_from_an_older_position_sends_only_what_was_missed(
        self, factory, cloud_settings
    ):
        officer = factory.user(username="stream.resume", roles=("security_operator",))
        old = _note(factory, officer.id, marker="old")
        _reload(factory.session)

        caller = _caller(factory, officer)
        start = drain(factory.session, caller, cloud_settings, Cursor(0, 0))
        assert [event.data["id"] for event in start.events] == [old.id]

        newer = _note(factory, officer.id, marker="new")
        _reload(factory.session)
        resumed = drain(factory.session, caller, cloud_settings, start.cursor)
        assert [event.data["id"] for event in resumed.events] == [newer.id]

    def test_a_fresh_connection_starts_at_the_end_of_both_feeds(self, factory, cloud_settings):
        officer = factory.user(username="stream.fresh", roles=("security_operator",))
        camera = factory.camera(code="CAM-STREAM-FRESH")
        _note(factory, officer.id, marker="before")
        _action(factory, factory.incident(camera))
        _reload(factory.session)

        position = latest_cursor(factory.session, _caller(factory, officer))
        assert position.notifications == int(
            factory.session.scalar(
                select(Notification.id).order_by(Notification.id.desc()).limit(1)
            )
        )
        assert position.actions == int(
            factory.session.scalar(
                select(IncidentAction.id).order_by(IncidentAction.id.desc()).limit(1)
            )
        )
        assert (
            drain(factory.session, _caller(factory, officer), cloud_settings, position).events
            == []
        )

    def test_one_pass_is_capped_and_the_next_pass_picks_up_the_rest(
        self, factory, cloud_settings
    ):
        officer = factory.user(username="stream.batch", roles=("security_operator",))
        for index in range(6):
            _note(factory, officer.id, marker=f"batch-{index}")
        _reload(factory.session)

        caller = _caller(factory, officer)
        first = drain(factory.session, caller, cloud_settings, Cursor(0, 0), limit=4)
        rest = drain(factory.session, caller, cloud_settings, first.cursor, limit=4)
        ids = [event.data["id"] for event in first.events + rest.events]
        assert len(first.events) == 4
        assert ids == sorted(ids)
        assert len(ids) == 6


# --------------------------------------------------------------------------- #
# the loop
# --------------------------------------------------------------------------- #


class TestStreamFrames:
    def test_an_alert_that_arrives_after_the_connection_opened_is_framed(
        self, factory, session_factory, cloud_settings
    ):
        officer = factory.user(username="stream.live", roles=("security_operator",))
        note = _note(factory, officer.id, marker="lands-later")
        _reload(factory.session)

        scripted = _SilentSession(session_factory)
        scripted.silent_passes = 2
        # Those two silent passes are the "before": the alert exists in the table but the
        # connection has not looked yet, which is the same thing the officer sees when the
        # monitoring host raises an incident a minute after they opened the app.
        body = _collect(
            stream_frames(
                scripted,
                _caller(factory, officer),
                cloud_settings,
                Cursor(0, 0),
                poll_seconds=0.002,
                heartbeat_seconds=1000.0,
                max_lifetime_seconds=2.0,
            )
        )
        frames = _parse_frames(body)
        assert frames[0][0] == "ready"
        assert [name for name, _ in frames].count("notification") == 1
        assert frames[-1][0] == "closing"
        assert next(data for name, data in frames if name == "notification")["id"] == note.id
        assert scripted.passes > 2

    def test_a_connection_that_opened_at_the_end_of_the_feed_replays_no_history(
        self, factory, session_factory, cloud_settings
    ):
        officer = factory.user(username="stream.nohistory", roles=("security_operator",))
        _note(factory, officer.id, marker="already-there")
        _reload(factory.session)

        position = latest_cursor(factory.session, _caller(factory, officer))
        body = _collect(
            stream_frames(
                session_factory,
                _caller(factory, officer),
                cloud_settings,
                position,
                poll_seconds=0.002,
                heartbeat_seconds=1000.0,
                max_lifetime_seconds=0.02,
            )
        )
        assert _names(body) == ["ready", "closing"]

    def test_heartbeats_are_written_while_nothing_else_is_happening(
        self, factory, session_factory, cloud_settings
    ):
        officer = factory.user(username="stream.heartbeat", roles=("security_operator",))
        body = _collect(
            stream_frames(
                session_factory,
                _caller(factory, officer),
                cloud_settings,
                Cursor(0, 0),
                poll_seconds=0.005,
                heartbeat_seconds=0.02,
                max_lifetime_seconds=0.5,
            )
        )
        assert _names(body).count("heartbeat") >= 2

    def test_a_database_that_stops_answering_ends_the_stream_and_says_so(
        self, factory, cloud_settings
    ):
        officer = factory.user(username="stream.broken", roles=("security_operator",))
        frames = _parse_frames(
            _collect(
                stream_frames(
                    _BrokenFactory(),
                    _caller(factory, officer),
                    cloud_settings,
                    Cursor(0, 0),
                    poll_seconds=0.002,
                    max_lifetime_seconds=1.0,
                )
            )
        )
        assert frames[0][0] == "ready"
        assert frames[-1][0] == "closing"
        assert frames[-1][1]["reason"] == "database_unavailable"
        # The driver's own text names the host; it must not reach the handset.
        assert "10.0.0.1" not in json.dumps(frames)

    def test_a_client_that_went_away_stops_the_reads(
        self, factory, session_factory, cloud_settings
    ):
        officer = factory.user(username="stream.gone", roles=("security_operator",))
        scripted = _SilentSession(session_factory)
        body = _collect(
            stream_frames(
                scripted,
                _caller(factory, officer),
                cloud_settings,
                Cursor(0, 0),
                poll_seconds=0.002,
                max_lifetime_seconds=5.0,
                is_disconnected=lambda: scripted.passes >= 2,
            )
        )
        assert _names(body) == ["ready"]
        assert scripted.passes == 2

    def test_every_frame_carries_a_cursor_that_only_moves_forward(
        self, factory, session_factory, cloud_settings
    ):
        officer = factory.user(username="stream.cursors", roles=("security_operator",))
        note = _note(factory, officer.id, marker="cursor-frame")
        action = _action(factory, factory.incident(None), actor=officer)
        _reload(factory.session)

        body = _collect(
            stream_frames(
                session_factory,
                _caller(factory, officer),
                cloud_settings,
                Cursor(0, 0),
                poll_seconds=0.002,
                heartbeat_seconds=1000.0,
                max_lifetime_seconds=0.2,
            )
        )
        cursors = [
            Cursor.parse(line.splitlines()[0].removeprefix("id: "))
            for line in body.split("\n\n")
            if line.startswith("id: ")
        ]
        assert cursors[0] == Cursor(0, 0)
        assert cursors[-1].notifications >= note.id
        assert cursors[-1].actions >= action.id

    def test_a_frame_is_an_id_line_a_name_line_and_one_json_line(self):
        frame = StreamEvent(name="notification", data={"id": 4}, id="4:0").frame()
        assert frame == 'id: 4:0\nevent: notification\ndata: {"id": 4}\n\n'


# --------------------------------------------------------------------------- #
# configuration guards
# --------------------------------------------------------------------------- #


def _cloud_env(**overrides) -> dict[str, str]:
    values = {
        "CLOUD_DATABASE_URL": "postgresql://watchtower:pw@127.0.0.1:5432/watchtower",
        "CLOUD_JWT_SECRET": "z" * 48,
    }
    values.update({key: str(value) for key, value in overrides.items()})
    return {key: value for key, value in values.items() if value}


class TestStreamConfiguration:
    def test_the_documented_defaults_are_a_working_cadence(self):
        from watchtower.cloud.config import load_cloud_settings

        settings = load_cloud_settings(_cloud_env())
        assert settings.stream_enabled is True
        assert settings.stream_poll_seconds == 2.0
        assert settings.stream_heartbeat_seconds == 15.0
        assert settings.stream_max_connections == 24
        # The cap that makes the whole design safe to hold open: shorter than a token's life.
        assert settings.stream_max_lifetime_seconds < settings.access_token_ttl_seconds

    def test_the_channel_can_be_switched_off_for_a_host_whose_proxy_buffers(self):
        from watchtower.cloud.config import load_cloud_settings

        assert load_cloud_settings(_cloud_env(CLOUD_STREAM_ENABLED="0")).stream_enabled is False

    def test_a_stream_allowed_to_outlive_its_access_token_is_refused_at_boot(self):
        from watchtower.cloud.config import CloudConfigError, load_cloud_settings

        with pytest.raises(CloudConfigError, match="must be shorter than"):
            load_cloud_settings(
                _cloud_env(CLOUD_ACCESS_TOKEN_TTL_SECONDS="900", CLOUD_STREAM_MAX_LIFETIME_SECONDS="900")
            )

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("CLOUD_STREAM_POLL_SECONDS", "0"),
            ("CLOUD_STREAM_POLL_SECONDS", "-1"),
            ("CLOUD_STREAM_HEARTBEAT_SECONDS", "0"),
            ("CLOUD_STREAM_MAX_LIFETIME_SECONDS", "30"),
            ("CLOUD_STREAM_MAX_CONNECTIONS", "0"),
            ("CLOUD_STREAM_MAX_CONNECTIONS", "5000"),
        ],
    )
    def test_a_cadence_that_cannot_work_fails_the_process_instead_of_a_phone(
        self, name, value
    ):
        from watchtower.cloud.config import CloudConfigError, load_cloud_settings

        with pytest.raises(CloudConfigError):
            load_cloud_settings(_cloud_env(**{name: value}))


# --------------------------------------------------------------------------- #
# the route
# --------------------------------------------------------------------------- #


@pytest.fixture
def stream_app(make_cloud_app, cloud_settings):
    """A cloud service whose stream ends in a fraction of a second.

    The test transport collects a body only after the application finishes writing it, so these
    numbers are what keeps the suite off the production ten-minute lifetime.
    """

    def _make(**overrides):
        values = {
            "stream_max_lifetime_seconds": 0.2,
            "stream_poll_seconds": 0.02,
            "stream_heartbeat_seconds": 1000.0,
        }
        values.update(overrides)
        return make_cloud_app(cloud_settings, **values)

    return _make


def _handset(client, factory, *, username: str, roles: tuple[str, ...] = ("security_operator",)):
    user = factory.user(username=username, roles=roles)
    factory.session.commit()
    actor = Personnel(client)
    response = actor.login(user.username, TEST_PASSWORD)
    assert response.status_code == 200, response.text
    return user, actor


class TestStreamRoute:
    def test_a_signed_in_handset_opens_the_stream_and_gets_valid_frames(self, stream_app, factory):
        client = stream_app()
        user, actor = _handset(client, factory, username="stream.route.open")
        note = _note(factory, user.id, marker="route")
        _reload(factory.session)

        response = client.get("/api/v1/events/stream?since=0:0", headers=actor.headers)
        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/event-stream")
        assert response.headers["cache-control"] == "no-store, no-transform"
        # Without this, a buffering proxy holds the body back and the officer watches an app that
        # looks connected and has received nothing.
        assert response.headers["x-accel-buffering"] == "no"

        frames = _parse_frames(response.text)
        assert frames[0][0] == "ready"
        assert frames[0][1]["poll_seconds"] == 0.02
        assert frames[1][0] == "notification"
        assert frames[1][1]["id"] == note.id
        assert frames[-1][0] == "closing"
        assert frames[-1][1]["reason"] == "lifetime"
        assert frames[-1][1]["cursor"]

    def test_a_connection_slot_is_freed_when_the_stream_ends(self, stream_app, factory):
        client = stream_app()
        _, actor = _handset(client, factory, username="stream.route.freeslot")
        room = client.app.state.container.streams
        assert room.open == 0
        client.get("/api/v1/events/stream", headers=actor.headers)
        assert room.open == 0

    def test_the_stream_needs_a_bearer_token(self, stream_app):
        client = stream_app()
        response = client.get("/api/v1/events/stream")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_required"

    def test_a_refusal_never_opens_a_connection_slot(self, stream_app):
        client = stream_app()
        room = client.app.state.container.streams
        client.get("/api/v1/events/stream")
        assert (room.open, room.refusals) == (0, 0)

    def test_the_stream_refuses_an_account_that_may_not_view_incidents(
        self, stream_app, factory
    ):
        client = stream_app()
        # A roleless account can sign in - the app needs that to show a profile - but the alert
        # surface, live or polled, is gated on the same permission the REST routes use.
        _, actor = _handset(client, factory, username="stream.route.powerless", roles=())
        response = client.get("/api/v1/events/stream", headers=actor.headers)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"

    def test_a_full_room_refuses_with_a_retry_after_instead_of_a_queue(
        self, stream_app, factory
    ):
        client = stream_app()
        _, actor = _handset(client, factory, username="stream.route.full")
        client.app.state.container.streams.limit = 0
        response = client.get("/api/v1/events/stream", headers=actor.headers)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "stream_unavailable"
        assert response.headers["retry-after"] == "30"

    def test_a_service_with_the_channel_switched_off_says_so(self, stream_app, factory):
        client = stream_app(stream_enabled=False)
        _, actor = _handset(client, factory, username="stream.route.off")
        response = client.get("/api/v1/events/stream", headers=actor.headers)
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "stream_disabled"

    def test_a_resume_cursor_is_echoed_back_in_the_ready_frame(self, stream_app, factory):
        client = stream_app()
        _, actor = _handset(client, factory, username="stream.route.resume")
        response = client.get("/api/v1/events/stream?since=3:5", headers=actor.headers)
        assert _parse_frames(response.text)[0][1]["cursor"] == "3:5"

    def test_the_last_event_id_header_resumes_without_a_query_parameter(
        self, stream_app, factory
    ):
        client = stream_app()
        _, actor = _handset(client, factory, username="stream.route.lastid")
        response = client.get(
            "/api/v1/events/stream", headers={**actor.headers, "last-event-id": "8:4"}
        )
        assert _parse_frames(response.text)[0][1]["cursor"] == "8:4"

    def test_an_unreadable_cursor_starts_at_the_end_of_the_feeds_not_at_the_beginning(
        self, stream_app, factory
    ):
        client = stream_app()
        user, actor = _handset(client, factory, username="stream.route.junk")
        _note(factory, user.id, marker="route-before-open")
        _reload(factory.session)

        response = client.get("/api/v1/events/stream?since=whatever", headers=actor.headers)
        frames = _parse_frames(response.text)
        assert [name for name, _ in frames] == ["ready", "closing"]
        assert Cursor.parse(frames[0][1]["cursor"]).notifications >= 1

    def test_a_stream_carries_only_rows_addressed_to_the_caller(self, stream_app, factory):
        client = stream_app()
        mine, actor = _handset(client, factory, username="stream.route.mine")
        other, _ = _handset(client, factory, username="stream.route.theirs")
        note = _note(factory, mine.id, marker="route-mine")
        _note(factory, other.id, marker="route-theirs", title="Another officer's alert")
        _reload(factory.session)

        response = client.get("/api/v1/events/stream?since=0:0", headers=actor.headers)
        payloads = [data for name, data in _parse_frames(response.text) if name == "notification"]
        assert [row["id"] for row in payloads] == [note.id]
        assert all(row["title"] != "Another officer's alert" for row in payloads)

    def test_a_stream_reports_activity_on_an_incident_the_caller_may_see(
        self, stream_app, factory
    ):
        client = stream_app()
        group = factory.group(code="GRP-STREAM-ROUTE")
        user, actor = _handset(client, factory, username="stream.route.activity")
        factory.grant(user, "security_operator", camera_group_id=group.id)
        camera = factory.camera(code="CAM-STREAM-ROUTE", group_id=group.id)
        incident = factory.incident(camera)
        _action(factory, incident, action="escalated", actor=user)
        _reload(factory.session)

        response = client.get("/api/v1/events/stream?since=0:0", headers=actor.headers)
        activity = [
            data for name, data in _parse_frames(response.text) if name == "incident_activity"
        ]
        assert [row["action"] for row in activity] == ["escalated"]
        assert activity[0]["incident_reference"] == incident.reference
        assert activity[0]["incident_status"] == incident.status
