"""Connection testing for camera registration (proposal section 6.5).

A registration test must distinguish *why* a camera failed, because the operator's fix is
different for each case. The checks run in order:

  1. reachability      -> host_unreachable / timed_out
  2. RTSP handshake    -> authentication_failed / stream_path_invalid_or_unsupported
  3. frame decode      -> video_decode_failed
  4. sustain interval  -> connection_successful only if frames keep arriving
  5. clean close       -> resources released

Step 2 speaks RTSP directly rather than relying on a decoder's single boolean, which is how
the distinct results in section 6.5 are produced. A camera is never reported as reachable
because a form was submitted.
"""

from __future__ import annotations

import base64
import socket
import time
from dataclasses import dataclass
from collections.abc import Callable

from ..models import ProbeResult
from ..security.secrets import redact
from .parser import ConnectionSpec

RTSP_VERSION = "RTSP/1.0"


@dataclass(slots=True)
class ProbeOutcome:
    result: ProbeResult
    message: str
    frames_decoded: int = 0
    measured_fps: float = 0.0
    width: int = 0
    height: int = 0
    elapsed_seconds: float = 0.0
    stage: str = ""

    @property
    def success(self) -> bool:
        return self.result is ProbeResult.CONNECTED


class ConnectionCancelled(RuntimeError):
    pass


CancelCheck = Callable[[], bool]


def _cancelled(check: CancelCheck | None) -> None:
    if check is not None and check():
        raise ConnectionCancelled("test cancelled by operator")


def check_reachability(spec: ConnectionSpec, timeout: float) -> tuple[bool, str]:
    """Confirm the destination is reachable from the authorized host (section 6.5)."""
    host = spec.host_without_brackets
    try:
        with socket.create_connection((host, spec.port), timeout=timeout):
            return True, ""
    except TimeoutError:
        return False, "timed_out"
    except socket.gaierror:
        return False, f"{host} does not resolve from this host."
    except OSError as exc:
        return False, f"{host}:{spec.port} is not reachable ({exc.strerror or exc})."


def rtsp_describe(spec: ConnectionSpec, timeout: float) -> tuple[int, str]:
    """Perform OPTIONS + DESCRIBE and return (status_code, response_text).

    Returns (0, detail) when the transport itself failed.
    """
    try:
        with socket.create_connection((spec.host_without_brackets, spec.port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            cseq = 1
            request = (
                f"OPTIONS rtsp://{spec.host}:{spec.port}{spec.path} {RTSP_VERSION}\r\n"
                f"CSeq: {cseq}\r\n\r\n"
            )
            sock.sendall(request.encode())
            _read_response(sock, timeout)

            cseq += 1
            headers = [f"CSeq: {cseq}"]
            if spec.username is not None:
                token = base64.b64encode(
                    f"{spec.username}:{spec.password or ''}".encode()
                ).decode()
                headers.append(f"Authorization: Basic {token}")
            describe = (
                f"DESCRIBE rtsp://{spec.host}:{spec.port}{spec.path} {RTSP_VERSION}\r\n"
                + "\r\n".join(headers)
                + "\r\nAccept: application/sdp\r\n\r\n"
            )
            sock.sendall(describe.encode())
            status, body = _read_response(sock, timeout)
            return status, body
    except TimeoutError:
        return 0, "timed_out"
    except OSError as exc:
        return 0, str(exc)


def _read_response(sock: socket.socket, timeout: float) -> tuple[int, str]:
    chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
        except TimeoutError:
            break
        if not chunk:
            break
        chunks.append(chunk)
        if b"\r\n\r\n" in b"".join(chunks):
            break
    raw = b"".join(chunks).decode(errors="replace")
    first_line = raw.split("\r\n", 1)[0]
    parts = first_line.split(" ")
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1]), raw
    return 0, raw


def decode_frames(
    spec: ConnectionSpec,
    *,
    frame_count: int,
    sustain_seconds: float,
    timeout: float,
    cancel: CancelCheck | None,
) -> tuple[ProbeResult | None, dict]:
    """Confirm actual video frames decode, and keep decoding over the test interval."""
    import os

    import cv2

    # Ask OpenCV's FFmpeg backend to use interleaved TCP transport; UDP frequently stalls
    # behind the campus Wi-Fi routers the initial camera was tested against.
    os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS", "rtsp_transport;tcp")

    opened = cv2.VideoCapture(
        spec.to_url(),
        cv2.CAP_FFMPEG,
        [
            cv2.CAP_PROP_OPEN_TIMEOUT_MSEC,
            int(timeout * 1000),
            cv2.CAP_PROP_READ_TIMEOUT_MSEC,
            int(timeout * 1000),
        ],
    )
    if not opened.isOpened():
        return ProbeResult.DECODE_FAILED, {"detail": "the video stream could not be opened"}

    try:
        decoded = 0
        started = time.monotonic()
        first_shapes: tuple[int, int] = (0, 0)
        while decoded < frame_count and (time.monotonic() - started) < timeout:
            _cancelled(cancel)
            ok, frame = opened.read()
            if not ok or frame is None:
                break
            decoded += 1
            if first_shapes == (0, 0):
                first_shapes = (int(frame.shape[1]), int(frame.shape[0]))

        if decoded == 0:
            return ProbeResult.DECODE_FAILED, {"detail": "no decodable video frames arrived"}

        # Section 6.5: "whether the stream remains usable during the configured test
        # interval" - a single lucky frame is not a working camera.
        sustained_until = time.monotonic() + sustain_seconds
        while time.monotonic() < sustained_until:
            _cancelled(cancel)
            ok, _ = opened.read()
            if not ok:
                return (
                    ProbeResult.DECODE_FAILED,
                    {"detail": f"delivery stopped after {decoded} frames"},
                )
            decoded += 1

        elapsed = time.monotonic() - started
        return None, {
            "frames_decoded": decoded,
            "measured_fps": round(decoded / elapsed, 2) if elapsed else 0.0,
            "width": first_shapes[0],
            "height": first_shapes[1],
        }
    finally:
        opened.release()


def run_probe(
    spec: ConnectionSpec,
    *,
    timeout: float = 12.0,
    frame_count: int = 12,
    sustain_seconds: float = 3.0,
    cancel: CancelCheck | None = None,
) -> ProbeOutcome:
    """Execute the full connection test and map it onto a section 6.5 result."""
    started = time.monotonic()
    try:
        reachable, detail = check_reachability(spec, timeout)
        if not reachable:
            result = (
                ProbeResult.TIMED_OUT
                if detail == "timed_out"
                else ProbeResult.HOST_UNREACHABLE
            )
            return _outcome(result, detail or "Host unreachable", started, "reachability")

        _cancelled(cancel)
        status, body = rtsp_describe(spec, timeout)
        if status == 0:
            if "timed_out" in body:
                return _outcome(
                    ProbeResult.TIMED_OUT, "The camera stopped responding mid-handshake.",
                    started, "handshake",
                )
            return _outcome(
                ProbeResult.HOST_UNREACHABLE,
                redact(f"RTSP handshake failed: {body}"),
                started,
                "handshake",
            )
        if status in (401, 403):
            return _outcome(
                ProbeResult.AUTH_FAILED,
                "Authentication failed - the supplied username or password was rejected.",
                started,
                "handshake",
            )
        if status in (404, 501):
            return _outcome(
                ProbeResult.PATH_INVALID,
                f"Stream path {spec.path!r} is invalid or unsupported by this camera.",
                started,
                "handshake",
            )
        if status >= 500:
            return _outcome(
                ProbeResult.HOST_UNREACHABLE,
                f"The camera returned server error {status}; it may still be starting up.",
                started,
                "handshake",
            )

        _cancelled(cancel)
        failure, info = decode_frames(
            spec,
            frame_count=frame_count,
            sustain_seconds=sustain_seconds,
            timeout=timeout,
            cancel=cancel,
        )
        if failure is not None:
            return _outcome(
                failure,
                redact(info.get("detail", "video decode failed")),
                started,
                "decode",
            )

        return ProbeOutcome(
            result=ProbeResult.CONNECTED,
            message=(
                f"Connection successful - {info['frames_decoded']} frames decoded at "
                f"{info['width']}x{info['height']}, about {info['measured_fps']} fps."
            ),
            frames_decoded=info["frames_decoded"],
            measured_fps=info["measured_fps"],
            width=info["width"],
            height=info["height"],
            elapsed_seconds=round(time.monotonic() - started, 2),
            stage="complete",
        )
    except ConnectionCancelled:
        return _outcome(ProbeResult.CANCELLED, "Test cancelled.", started, "cancelled")
    except Exception as exc:  # noqa: BLE001 - pragma: no cover
        # OpenCV/FFmpeg raise assorted driver faults; the probe reports one outcome per stage.
        return _outcome(
            ProbeResult.DECODE_FAILED,
            redact(f"Unexpected failure during the test: {exc.__class__.__name__}"),
            started,
            "error",
        )


def _outcome(
    result: ProbeResult, message: str, started: float, stage: str
) -> ProbeOutcome:
    return ProbeOutcome(
        result=result,
        message=redact(message),
        elapsed_seconds=round(time.monotonic() - started, 2),
        stage=stage,
    )
