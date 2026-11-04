"""One supervised stream session per camera (proposal sections 7 and 9).

A worker is a separate process, not a thread: a decoder fault or a hung FFmpeg read inside
one camera's session cannot take down the API or the other cameras. The worker owns exactly
one RTSP connection and publishes its newest encoded frame into a bounded queue, which the
supervisor fans out to every authorized browser viewer - so several viewers of the same
camera share one source stream instead of opening duplicate RTSP connections (section 9).
"""

from __future__ import annotations

import contextlib
import multiprocessing as mp
import queue
import time
from dataclasses import asdict, dataclass
from typing import Any

from ..rtsp.parser import ConnectionSpec

FRAME = "frame"
STATS = "stats"
STATE = "state"
LOG = "log"


@dataclass(slots=True)
class WorkerConfig:
    camera_id: str
    spec: ConnectionSpec
    jpeg_quality: int = 78
    target_fps: float = 10.0
    analysis_fps: float = 4.0
    backoff_seconds: tuple[int, ...] = (2, 5, 15, 30, 60)
    max_restarts: int = 10
    stall_after_seconds: float = 15.0


@dataclass(slots=True)
class StreamStats:
    camera_id: str = ""
    state: str = "starting"
    pid: int | None = None
    started_at: float = 0.0
    last_frame_at: float = 0.0
    frames_received: int = 0
    frames_dropped: int = 0
    decode_failures: int = 0
    retry_count: int = 0
    measured_fps: float = 0.0
    width: int = 0
    height: int = 0
    viewers: int = 0
    last_error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _send(out: mp.Queue, kind: str, payload: Any) -> None:
    # Control messages are small and coalesced by the supervisor; frames are dropped
    # rather than queued so a slow browser can never back the decoder up.
    with contextlib.suppress(queue.Full):
        out.put_nowait((kind, payload))


def run_worker(config: WorkerConfig, out: mp.Queue, stop_event: mp.Event) -> None:
    """Process entry point. Must stay a module-level function to be spawn-able."""
    import os

    import cv2

    os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp")
    open_timeout_ms = 10_000
    read_timeout_ms = int(config.stall_after_seconds * 1000)
    capture_params = [
        cv2.CAP_PROP_OPEN_TIMEOUT_MSEC,
        open_timeout_ms,
        cv2.CAP_PROP_READ_TIMEOUT_MSEC,
        read_timeout_ms,
    ]

    stats = StreamStats(
        camera_id=config.camera_id,
        state="starting",
        started_at=time.time(),
        pid=os.getpid(),
    )
    frame_interval = 1.0 / max(config.target_fps, 0.5)
    restart = 0

    while not stop_event.is_set():
        stats.state = "connecting"
        _send(out, STATE, stats.as_dict())

        capture = cv2.VideoCapture(config.spec.to_url(), cv2.CAP_FFMPEG, capture_params)
        if not capture.isOpened():
            stats.decode_failures += 1
            stats.last_error = "stream could not be opened"
            stats.state = "reconnecting"
            _send(out, STATE, stats.as_dict())
            capture.release()
            restart += 1
            stats.retry_count = restart
            if restart > config.max_restarts:
                stats.state = "failed"
                _send(out, STATE, stats.as_dict())
                return
            _sleep_until(stop_event, time.monotonic() + _backoff(config, restart))
            continue

        stats.state = "online"
        stats.width = int(capture.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        stats.height = int(capture.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        _send(out, STATE, stats.as_dict())

        last_frame_emit = 0.0
        last_stats_emit = 0.0
        window_start = time.monotonic()
        window_frames = 0

        try:
            while not stop_event.is_set():
                ok, frame = capture.read()
                now = time.monotonic()
                if not ok or frame is None:
                    stats.decode_failures += 1
                    stats.last_error = "frame delivery stalled"
                    break
                if (now - stats.last_frame_at) > config.stall_after_seconds and stats.last_frame_at:
                    # The read returned but the stream is frozen - treat it as a failure so
                    # the supervisor records a Degraded/Offline transition.
                    stats.last_error = "no frame progress"
                    break

                stats.frames_received += 1
                window_frames += 1
                stats.last_frame_at = now

                if now - last_frame_emit >= frame_interval:
                    last_frame_emit = now
                    _publish_frame(out, frame, config, stats)

                if now - last_stats_emit >= 1.0:
                    last_stats_emit = now
                    elapsed = now - window_start
                    stats.measured_fps = round(window_frames / elapsed, 2) if elapsed > 0 else 0.0
                    window_start = now
                    window_frames = 0
                    _send(out, STATS, stats.as_dict())
        except Exception as exc:  # noqa: BLE001 - pragma: no cover
            # A decoder fault is reported through stats, never raised out of the worker.
            stats.last_error = f"{exc.__class__.__name__}: decoder fault"
        finally:
            capture.release()

        if stop_event.is_set():
            break

        restart += 1
        stats.retry_count = restart
        stats.state = "reconnecting"
        _send(out, STATE, stats.as_dict())
        if restart > config.max_restarts:
            stats.state = "failed"
            _send(out, STATE, stats.as_dict())
            return
        # Section 7: bounded retries with backoff, not continuous retrying.
        _sleep_until(stop_event, time.monotonic() + _backoff(config, restart))

    stats.state = "stopped"
    _send(out, STATE, stats.as_dict())


def _publish_frame(
    out: mp.Queue, frame: Any, config: WorkerConfig, stats: StreamStats
) -> None:
    import cv2

    encoded = cv2.imencode(
        ".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), config.jpeg_quality]
    )
    ok, buffer = encoded
    if not ok:
        stats.frames_dropped += 1
        return
    payload = buffer.tobytes()
    try:
        out.put_nowait((FRAME, (time.time(), payload, stats.measured_fps)))
    except queue.Full:
        # Drop the stale frame instead of queueing: viewers must never see a backlog.
        try:
            while True:
                pending = out.get_nowait()
                if pending[0] == FRAME:
                    break
        except (queue.Empty, OSError):
            pass
        stats.frames_dropped += 1
        # The queue emptied between the drain and here; dropping is the intended outcome.
        with contextlib.suppress(queue.Full):
            out.put_nowait((FRAME, (time.time(), payload, stats.measured_fps)))


def _backoff(config: WorkerConfig, attempt: int) -> float:
    index = min(max(attempt - 1, 0), len(config.backoff_seconds) - 1)
    return float(config.backoff_seconds[index])


def _sleep_until(stop_event: mp.Event, deadline: float) -> None:
    while time.monotonic() < deadline and not stop_event.is_set():
        time.sleep(min(0.25, max(0.0, deadline - time.monotonic())))
