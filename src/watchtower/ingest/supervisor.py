"""Stream supervisor: the registry of managed camera sessions (proposal section 7).

Responsibilities, straight from the proposal:
  * one managed session per unique camera ID, with duplicate activation requests collapsed
  * per-worker connection state, start time, last-frame timestamp, frame and decode
    statistics, retry counter, controlled shutdown and health reporting
  * restart policy with bounded backoff when a worker process dies
  * configurable ceilings on simultaneous streams and connection tests
  * shared delivery of one source stream to several viewers
"""

from __future__ import annotations

import contextlib
import logging
import multiprocessing as mp
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import Settings
from ..rtsp.parser import ConnectionSpec
from ..security.secrets import redact
from . import worker as W

LOGGER = logging.getLogger("watchtower.ingest.supervisor")

StreamCallback = Callable[[str, W.StreamStats], None]


class StreamCapacityError(RuntimeError):
    pass


class TestCapacityError(RuntimeError):
    pass


@dataclass
class ManagedStream:
    camera_id: str
    spec: ConnectionSpec
    process: mp.Process
    stop_event: mp.Event
    queue: mp.Queue
    stats: W.StreamStats
    latest_frame: tuple[float, bytes, float] | None = None
    viewers: int = 0
    terminal_logged: bool = False
    lock: threading.Lock = field(default_factory=threading.Lock)


class StreamSupervisor:
    def __init__(
        self,
        settings: Settings,
        *,
        on_stream_event: StreamCallback | None = None,
    ) -> None:
        self._settings = settings
        self._streams: dict[str, ManagedStream] = {}
        self._lock = threading.RLock()
        self._on_stream_event = on_stream_event
        self._tests_in_flight = 0
        self._stop = threading.Event()
        self._pump = threading.Thread(
            target=self._drain_queues, name="stream-pump", daemon=True
        )
        self._pump.start()

    # ------------------------------------------------------------------ #
    # Activation
    # ------------------------------------------------------------------ #

    def ensure(
        self, camera_id: str, spec: ConnectionSpec, *, restart: bool = False
    ) -> ManagedStream:
        """Idempotently guarantee a running managed session for this camera.

        Section 7: "duplicate activation requests do not create unnecessary duplicate
        workers for the same camera."
        """
        with self._lock:
            existing = self._streams.get(camera_id)
            if existing is not None:
                if existing.process.is_alive() and not restart:
                    return existing
                self._terminate(existing, reason="replaced")
            running = sum(1 for s in self._streams.values() if s.process.is_alive())
            if running >= self._settings.max_concurrent_streams:
                raise StreamCapacityError(
                    f"the configured ceiling of {self._settings.max_concurrent_streams} "
                    "simultaneous streams has been reached; disable a camera or raise "
                    "WATCHTOWER_MAX_CONCURRENT_STREAMS."
                )

            context = mp.get_context("spawn")
            stream_queue = context.Queue(maxsize=4)
            stop_event = context.Event()
            config = W.WorkerConfig(
                camera_id=camera_id,
                spec=spec,
                jpeg_quality=self._settings.live_jpeg_quality,
                backoff_seconds=self._settings.stream_retry_backoff_seconds,
                max_restarts=self._settings.max_stream_restarts,
                stall_after_seconds=self._settings.offline_after_seconds,
            )
            process = context.Process(
                target=W.run_worker,
                args=(config, stream_queue, stop_event),
                name=f"camera-{camera_id[:8]}",
                daemon=True,
            )
            process.start()
            managed = ManagedStream(
                camera_id=camera_id,
                spec=spec,
                process=process,
                stop_event=stop_event,
                queue=stream_queue,
                stats=W.StreamStats(
                    camera_id=camera_id,
                    state="starting",
                    pid=process.pid,
                    started_at=time.time(),
                ),
            )
            self._streams[camera_id] = managed
            return managed

    def stop(self, camera_id: str, *, reason: str = "disabled") -> bool:
        with self._lock:
            managed = self._streams.pop(camera_id, None)
            if managed is None:
                return False
            self._terminate(managed, reason=reason)
            return True

    def _terminate(self, managed: ManagedStream, *, reason: str) -> None:
        """Controlled shutdown: signal, wait, then escalate (section 7)."""
        with contextlib.suppress(OSError, RuntimeError):
            managed.stop_event.set()
        managed.process.join(timeout=6)
        if managed.process.is_alive():
            managed.process.terminate()
            managed.process.join(timeout=3)
        if managed.process.is_alive():
            managed.process.kill()
            managed.process.join(timeout=2)
        managed.stats.state = "stopped"
        managed.stats.last_error = reason
        try:
            managed.queue.cancel_join_thread()
            managed.queue.close()
        except (OSError, ValueError):
            pass
        self._notify(managed)

    def shutdown(self) -> None:
        with self._lock:
            for managed in list(self._streams.values()):
                self._terminate(managed, reason="server_shutdown")
            self._streams.clear()
        self._stop.set()

    # ------------------------------------------------------------------ #
    # Delivery
    # ------------------------------------------------------------------ #

    def latest_frame(self, camera_id: str) -> tuple[float, bytes, float] | None:
        with self._lock:
            managed = self._streams.get(camera_id)
            return managed.latest_frame if managed else None

    def stats(self, camera_id: str) -> W.StreamStats | None:
        with self._lock:
            managed = self._streams.get(camera_id)
            return managed.stats if managed else None

    def snapshot_all(self) -> dict[str, W.StreamStats]:
        with self._lock:
            return {camera_id: managed.stats for camera_id, managed in self._streams.items()}

    def attach_viewer(self, camera_id: str) -> None:
        with self._lock:
            managed = self._streams.get(camera_id)
            if managed is not None:
                managed.viewers += 1
                managed.stats.viewers = managed.viewers

    def detach_viewer(self, camera_id: str) -> None:
        with self._lock:
            managed = self._streams.get(camera_id)
            if managed is not None:
                managed.viewers = max(0, managed.viewers - 1)
                managed.stats.viewers = managed.viewers

    # ------------------------------------------------------------------ #
    # Connection-test budget (section 7: limits on connection tests too)
    # ------------------------------------------------------------------ #

    class _TestSlot:
        def __init__(self, supervisor: StreamSupervisor) -> None:
            self._supervisor = supervisor

        def __enter__(self) -> StreamSupervisor._TestSlot:
            return self

        def __exit__(self, *exc_info: object) -> None:
            with self._supervisor._lock:
                self._supervisor._tests_in_flight -= 1

    def acquire_test_slot(self) -> _TestSlot:
        with self._lock:
            if self._tests_in_flight >= self._settings.max_concurrent_connection_tests:
                raise TestCapacityError(
                    "another connection test is already running on this host; try again "
                    "shortly."
                )
            self._tests_in_flight += 1
        return self._TestSlot(self)

    # ------------------------------------------------------------------ #
    # Queue pump
    # ------------------------------------------------------------------ #

    def _drain_queues(self) -> None:
        while not self._stop.is_set():
            drained = 0
            with self._lock:
                streams = list(self._streams.items())
            for camera_id, managed in streams:
                while drained < 64:
                    try:
                        message = managed.queue.get_nowait()
                    except (queue.Empty, OSError, ValueError):
                        break
                    drained += 1
                    kind, payload = message
                    if kind == W.FRAME:
                        managed.latest_frame = payload
                        managed.stats.last_frame_at = payload[0]
                    elif kind in (W.STATS, W.STATE):
                        merged = W.StreamStats(**payload)
                        merged.viewers = managed.viewers
                        with managed.lock:
                            managed.stats = merged
                        if merged.state in ("failed", "stopped"):
                            self._handle_terminal(camera_id, managed)
                    else:
                        continue
            if not streams:
                time.sleep(0.05)
            else:
                time.sleep(0.02)

    def _handle_terminal(self, camera_id: str, managed: ManagedStream) -> None:
        """A worker exited its retry budget; record it and let the health layer alert."""
        if managed.terminal_logged:
            return
        managed.terminal_logged = True
        with self._lock:
            self._streams.pop(camera_id, None)
        self._notify(managed)

    def _notify(self, managed: ManagedStream) -> None:
        if self._on_stream_event is not None:
            try:
                self._on_stream_event(managed.camera_id, managed.stats)
            except Exception as exc:  # noqa: BLE001 - a health hook must not kill ingestion
                # Logged because a failing hook otherwise means missed alerts with no trace.
                LOGGER.warning(
                    "stream event hook failed for %s: %s",
                    managed.camera_id[:8],
                    redact(str(exc)),
                )
