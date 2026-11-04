"""Stream supervisor: the registry of managed sessions and its ceilings (section 7).

There is no camera and no video in the test environment, so a real worker process is never
started: `mp.get_context("spawn")` is replaced by a fake multiprocessing context whose
`Process` objects are recorded instead. The registry behaviour under test - one session per
camera id, bounded concurrency, bounded connection tests - is what section 7 promises.
"""

from __future__ import annotations

import queue as queue_module
import typing
from dataclasses import replace

import pytest

from watchtower.ingest import supervisor as S
from watchtower.ingest.supervisor import StreamCapacityError, StreamSupervisor
from watchtower.rtsp.parser import ConnectionSpec


class FakeProcess:
    """Stands in for `mp.Process` so no OS process is created."""

    all: typing.ClassVar[list[FakeProcess]] = []

    def __init__(self, target=None, args=(), name=None, daemon=None):
        self.target = target
        self.args = args
        self.name = name
        self.daemon = daemon
        self.pid = 50_000 + len(FakeProcess.all)
        self._alive = False
        self.terminated = False
        self.killed = False
        self.join_calls = 0
        FakeProcess.all.append(self)

    def start(self):
        self._alive = True

    def is_alive(self):
        return self._alive

    def join(self, timeout=None):
        self.join_calls += 1
        if self.terminated or self.killed:
            self._alive = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


class FakeQueue:
    def __init__(self, maxsize=0):
        self.messages = []
        self.closed = False

    def put_nowait(self, item):
        self.messages.append(item)

    def get_nowait(self):
        raise queue_module.Empty

    def cancel_join_thread(self):
        pass

    def close(self):
        self.closed = True


class FakeEvent:
    def __init__(self):
        self._set = False

    def set(self):
        self._set = True

    def is_set(self):
        return self._set


class FakeContext:
    def __init__(self):
        self.events: list[FakeEvent] = []
        self.queues: list[FakeQueue] = []

    def Queue(self, maxsize=0):  # noqa: N802 - matches the mp API
        queue = FakeQueue(maxsize)
        self.queues.append(queue)
        return queue

    def Event(self):  # noqa: N802
        event = FakeEvent()
        self.events.append(event)
        return event

    def Process(self, target=None, args=(), name=None, daemon=None):  # noqa: N802
        return FakeProcess(target=target, args=args, name=name, daemon=daemon)


@pytest.fixture
def mp_context(monkeypatch):
    FakeProcess.all = []
    context = FakeContext()

    def get_context(kind: str = "spawn") -> FakeContext:
        return context

    monkeypatch.setattr(S.mp, "get_context", get_context)
    return context


def spec(host: str = "10.20.0.7") -> ConnectionSpec:
    return ConnectionSpec(
        host=host, port=554, path="/cam/realmonitor", username="admin", password="secret-pw"
    )


@pytest.fixture
def supervisor_for(settings, mp_context):
    built: list[StreamSupervisor] = []

    def _make(**overrides) -> StreamSupervisor:
        instance = StreamSupervisor(replace(settings, **overrides))
        built.append(instance)
        return instance

    yield _make
    for instance in built:
        instance.shutdown()


# --------------------------------------------------------------------------- #
# One session per camera
# --------------------------------------------------------------------------- #


def test_duplicate_activations_do_not_start_a_second_worker(supervisor_for, mp_context):
    """Section 7: "duplicate activation requests do not create duplicate workers"."""
    supervisor = supervisor_for()
    camera_id = "11111111-1111-1111-1111-111111111111"

    first = supervisor.ensure(camera_id, spec())
    second = supervisor.ensure(camera_id, spec())
    third = supervisor.ensure(camera_id, spec())

    assert second is first
    assert third is first
    assert len(mp_context.queues) == 1
    assert len(FakeProcess.all) == 1
    assert list(supervisor.snapshot_all()) == [camera_id]


def test_a_dead_worker_is_replaced_rather_than_reused(supervisor_for, mp_context):
    supervisor = supervisor_for()
    camera_id = "22222222-2222-2222-2222-222222222222"

    supervisor.ensure(camera_id, spec())
    FakeProcess.all[0]._alive = False  # the worker died
    replaced = supervisor.ensure(camera_id, spec())

    assert replaced is not None
    assert len(FakeProcess.all) == 2
    # a worker that already exited is reaped, not signalled again
    assert FakeProcess.all[0].join_calls >= 1
    assert not FakeProcess.all[0].terminated
    assert supervisor.stats(camera_id).state == "starting"


def test_two_cameras_get_two_sessions(supervisor_for, mp_context):
    supervisor = supervisor_for()

    supervisor.ensure("aaaa", spec("10.20.0.7"))
    supervisor.ensure("bbbb", spec("10.20.0.8"))

    assert len(FakeProcess.all) == 2
    assert sorted(supervisor.snapshot_all()) == ["aaaa", "bbbb"]


def test_stop_is_controlled_and_reports_whether_anything_was_running(supervisor_for, mp_context):
    supervisor = supervisor_for()
    supervisor.ensure("cccc", spec())

    assert supervisor.stop("cccc", reason="disabled") is True
    assert supervisor.stop("cccc", reason="disabled") is False
    assert supervisor.snapshot_all() == {}


# --------------------------------------------------------------------------- #
# Ceilings
# --------------------------------------------------------------------------- #


def test_the_stream_ceiling_is_enforced(supervisor_for, mp_context):
    supervisor = supervisor_for(max_concurrent_streams=2)

    supervisor.ensure("one", spec())
    supervisor.ensure("two", spec())
    with pytest.raises(StreamCapacityError) as caught:
        supervisor.ensure("three", spec("10.20.0.99"))

    assert "2" in str(caught.value)
    assert len(FakeProcess.all) == 2
    assert "three" not in supervisor.snapshot_all()


def test_a_disabled_stream_frees_a_slot_for_the_next_camera(supervisor_for, mp_context):
    supervisor = supervisor_for(max_concurrent_streams=1)
    supervisor.ensure("one", spec())

    supervisor.stop("one", reason="disabled")
    assert supervisor.ensure("two", spec("10.20.0.8")) is not None


def test_the_connection_test_ceiling_is_enforced(supervisor_for):
    supervisor = supervisor_for(max_concurrent_connection_tests=1)

    with supervisor.acquire_test_slot():
        with pytest.raises(S.TestCapacityError):
            supervisor.acquire_test_slot()


def test_a_failing_probe_releases_its_test_slot(supervisor_for):
    """A probe that raises must not consume the budget forever (section 7 ceiling)."""
    supervisor = supervisor_for(max_concurrent_connection_tests=1)

    with pytest.raises(RuntimeError, match="decoder blew up"):
        with supervisor.acquire_test_slot():
            raise RuntimeError("decoder blew up")

    assert supervisor._tests_in_flight == 0
    with supervisor.acquire_test_slot():
        pass
    assert supervisor._tests_in_flight == 0


def test_two_tests_run_concurrently_up_to_the_limit(supervisor_for):
    supervisor = supervisor_for(max_concurrent_connection_tests=2)

    with supervisor.acquire_test_slot(), supervisor.acquire_test_slot():
        with pytest.raises(S.TestCapacityError):
            supervisor.acquire_test_slot()


# --------------------------------------------------------------------------- #
# Delivery bookkeeping
# --------------------------------------------------------------------------- #


def test_several_viewers_share_one_source_stream(supervisor_for, mp_context):
    """Section 9: viewer count is per managed session, not per RTSP connection."""
    supervisor = supervisor_for()
    supervisor.ensure("dddd", spec())

    supervisor.attach_viewer("dddd")
    supervisor.attach_viewer("dddd")
    supervisor.attach_viewer("dddd")

    assert supervisor.stats("dddd").viewers == 3
    assert len(FakeProcess.all) == 1

    supervisor.detach_viewer("dddd")
    assert supervisor.stats("dddd").viewers == 2


def test_the_viewer_count_never_goes_negative(supervisor_for, mp_context):
    supervisor = supervisor_for()
    supervisor.ensure("eeee", spec())

    for _ in range(4):
        supervisor.detach_viewer("eeee")

    assert supervisor.stats("eeee").viewers == 0


def test_shutdown_terminates_every_managed_session(supervisor_for, mp_context):
    supervisor = supervisor_for()
    supervisor.ensure("ffff", spec())
    supervisor.ensure("gggg", spec("10.20.0.9"))

    supervisor.shutdown()

    assert supervisor.snapshot_all() == {}
    assert all(process.terminated or process.killed for process in FakeProcess.all)


def test_the_worker_config_carries_the_redacted_url_only(supervisor_for, mp_context):
    """A worker's config could end up in a traceback; the credential must not be in it."""
    supervisor = supervisor_for()
    supervisor.ensure("hhhh", spec())

    config = FakeProcess.all[0].args[0]
    assert config.spec.password == "secret-pw"  # needed in-process to dial the camera
    assert "secret-pw" not in config.spec.redacted_url()
    assert config.spec.redacted_url().startswith("rtsp://")
