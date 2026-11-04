"""Connection-test results (proposal section 6.5): every documented outcome must be
reachable and mapped from the right underlying condition.

There is no camera and no network service in this environment, so the tests drive the
mapping functions directly with monkeypatched reachability/handshake/decode steps. The only
real network calls are to loopback and to an unroutable address, which fail fast.
"""

from __future__ import annotations

import io
import socket

import pytest

from watchtower.models import ProbeResult
from watchtower.rtsp import probe
from watchtower.rtsp.probe import (
    ProbeOutcome,
    check_reachability,
    run_probe,
)
from watchtower.rtsp.parser import build_spec

SPEC = build_spec(
    host="10.20.0.7", port=554, stream_path="/cam/realmonitor", username="admin", password="pw"
)

# Every outcome section 6.5 lists for a connection test.
DOCUMENTED_OUTCOMES = {
    "testing",
    "connection_successful",
    "authentication_failed",
    "host_unreachable",
    "stream_path_invalid_or_unsupported",
    "video_decode_failed",
    "timed_out",
    "test_cancelled",
}


def spec_for(**overrides) -> probe.ConnectionSpec:
    values = {"host": "10.20.0.7", "port": 554, "stream_path": "/cam/realmonitor"}
    values.update(overrides)
    return build_spec(username="admin", password="pw", transport="tcp", **values)


@pytest.fixture(autouse=True)
def _no_real_reachability(monkeypatch):
    """Keep mapping tests off the network unless a test opts back in."""
    monkeypatch.setattr(probe, "check_reachability", lambda spec, timeout: (True, ""))


@pytest.mark.parametrize("status", [401, 403])
def test_a_rejected_handshake_is_authentication_failed(monkeypatch, status):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (status, "denied"))
    outcome = run_probe(SPEC)
    assert outcome.result is ProbeResult.AUTH_FAILED
    assert "Authentication failed" in outcome.message
    assert outcome.stage == "handshake"
    assert outcome.success is False


@pytest.mark.parametrize("status", [404, 501])
def test_an_unknown_stream_path_is_reported_as_path_invalid(monkeypatch, status):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (status, "not found"))
    outcome = run_probe(SPEC)
    assert outcome.result is ProbeResult.PATH_INVALID
    assert "/cam/realmonitor" in outcome.message


def test_a_server_error_from_the_camera_is_not_reported_as_a_working_camera(monkeypatch):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (500, "internal error"))
    outcome = run_probe(SPEC)
    assert outcome.result is ProbeResult.HOST_UNREACHABLE
    assert "500" in outcome.message


def test_a_handshake_that_stops_responding_is_a_timeout(monkeypatch):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (0, "timed_out"))
    outcome = run_probe(SPEC)
    assert outcome.result is ProbeResult.TIMED_OUT
    assert outcome.stage == "handshake"


def test_a_transport_failure_during_the_handshake_is_host_unreachable(monkeypatch):
    monkeypatch.setattr(
        probe, "rtsp_describe", lambda spec, timeout: (0, "[WinError 10061] refused")
    )
    outcome = run_probe(SPEC)
    assert outcome.result is ProbeResult.HOST_UNREACHABLE


def test_a_test_in_progress_is_observable_as_the_testing_result(camera_service, factory, monkeypatch):
    """The wizard polls the camera while the test runs, so `testing` has to be persisted."""
    from watchtower.rtsp import probe as probe_module

    camera = factory.camera(probe_result=None)
    principal = factory.principal(factory.user(roles=("technical_operator",)))
    factory.session.commit()

    observed: dict[str, object] = {}

    def fake_run_probe(spec, **kwargs):
        observed["while_running"] = camera.connection_profile.last_probe_result
        return ProbeOutcome(result=ProbeResult.CONNECTED, message="ok", frames_decoded=20)

    monkeypatch.setattr(probe_module, "run_probe", fake_run_probe)
    camera_service.run_connection_test(camera, principal)
    assert observed["while_running"] == ProbeResult.TESTING.value


def test_the_documented_outcome_set_is_complete():
    assert {member.value for member in ProbeResult} == DOCUMENTED_OUTCOMES


def test_frames_that_cannot_be_decoded_are_reported_as_decode_failed(monkeypatch):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (200, "RTSP/1.0 200 OK"))
    monkeypatch.setattr(
        probe,
        "decode_frames",
        lambda spec, **kwargs: (ProbeResult.DECODE_FAILED, {"detail": "no decodable frames"}),
    )
    outcome = run_probe(SPEC)
    assert outcome.result is ProbeResult.DECODE_FAILED
    assert outcome.stage == "decode"
    assert outcome.frames_decoded == 0


def test_a_confirmed_stream_is_the_only_success(monkeypatch):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (200, "RTSP/1.0 200 OK"))
    monkeypatch.setattr(
        probe,
        "decode_frames",
        lambda spec, **kwargs: (
            None,
            {
                "frames_decoded": 40,
                "measured_fps": 12.5,
                "width": 1920,
                "height": 1080,
            },
        ),
    )
    outcome = run_probe(SPEC, frame_count=12, sustain_seconds=0.0, timeout=2.0)
    assert outcome.result is ProbeResult.CONNECTED
    assert outcome.success is True
    assert (outcome.frames_decoded, outcome.measured_fps) == (40, 12.5)
    assert (outcome.width, outcome.height) == (1920, 1080)
    assert "40 frames" in outcome.message


def test_an_operator_cancel_becomes_the_cancelled_outcome(monkeypatch):
    def always_cancelled():
        return True

    outcome = run_probe(SPEC, cancel=always_cancelled)
    assert outcome.result is ProbeResult.CANCELLED
    assert outcome.stage == "cancelled"
    assert outcome.success is False


def test_an_unexpected_driver_fault_is_contained_and_reported(monkeypatch):
    def explode(spec, timeout):
        raise RuntimeError("decoder exploded")

    monkeypatch.setattr(probe, "rtsp_describe", explode)
    outcome = run_probe(SPEC)
    assert outcome.success is False
    assert "Unexpected failure" in outcome.message


# --------------------------------------------------------------------------- #
# Reachability, without monkeypatching: loopback and an unroutable address only
# --------------------------------------------------------------------------- #


def test_a_closed_loopback_port_is_not_reachable():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    reachable, detail = check_reachability(spec_for(host="127.0.0.1", port=port), 1.0)
    assert reachable is False
    assert detail


def test_an_unroutable_address_is_reported_as_unreachable_or_timed_out(monkeypatch):
    """240.0.0.0/4 is reserved and undialable, so this never reaches a real host."""
    monkeypatch.setattr(probe, "check_reachability", check_reachability)
    outcome = run_probe(spec_for(host="240.0.0.1"), timeout=0.5)
    assert outcome.result in {ProbeResult.HOST_UNREACHABLE, ProbeResult.TIMED_OUT}
    assert outcome.success is False


def test_a_name_that_does_not_resolve_is_host_unreachable(monkeypatch):
    """RFC 2606 keeps .invalid unresolvable, so the mapping is deterministic."""
    monkeypatch.setattr(probe, "check_reachability", check_reachability)
    outcome = run_probe(spec_for(host="watchtower-absent-host.invalid"), timeout=1.0)
    assert outcome.result is ProbeResult.HOST_UNREACHABLE


def test_a_rejected_camera_cannot_be_reported_as_reachable_by_submitting_a_form(
    monkeypatch,
):
    monkeypatch.setattr(
        probe,
        "check_reachability",
        lambda spec, timeout: (False, "10.20.0.7:554 is not reachable"),
    )
    monkeypatch.setattr(
        probe, "rtsp_describe", lambda spec, timeout: pytest.fail("handshake must not run")
    )
    assert run_probe(SPEC).result is ProbeResult.HOST_UNREACHABLE


# --------------------------------------------------------------------------- #
# Redaction at the probe boundary
# --------------------------------------------------------------------------- #


def test_probe_messages_never_carry_the_credential(monkeypatch):
    monkeypatch.setattr(
        probe, "rtsp_describe", lambda spec, timeout: (0, SPEC.to_url() + " refused")
    )
    outcome = run_probe(SPEC)
    assert "pw" not in outcome.message
    assert "rtsp://admin:***@" in outcome.message


def test_decode_failures_are_redacted_before_being_returned(monkeypatch):
    monkeypatch.setattr(probe, "rtsp_describe", lambda spec, timeout: (200, "RTSP/1.0 200 OK"))
    monkeypatch.setattr(
        probe,
        "decode_frames",
        lambda spec, **kwargs: (
            ProbeResult.DECODE_FAILED,
            {"detail": f"cannot open {SPEC.to_url()}"},
        ),
    )
    assert "pw" not in run_probe(SPEC).message


def test_probe_outcome_success_is_only_the_connected_result():
    assert ProbeOutcome(result=ProbeResult.CONNECTED, message="ok").success is True
    for result in ProbeResult:
        if result is ProbeResult.CONNECTED:
            continue
        assert ProbeOutcome(result=result, message="x").success is False


# --------------------------------------------------------------------------- #
# The RTSP status line is what the whole mapping rests on
# --------------------------------------------------------------------------- #


class _FakeSocket:
    def __init__(self, payload: bytes):
        self._stream = io.BytesIO(payload)

    def recv(self, _size: int) -> bytes:
        return self._stream.read(16)


def test_the_rtsp_status_line_is_parsed_into_a_status_code():
    status, _body = probe._read_response(
        _FakeSocket(b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n"), timeout=1.0
    )
    assert status == 401


def test_an_unparseable_response_is_status_zero():
    status, _body = probe._read_response(_FakeSocket(b"garbage\r\n"), timeout=1.0)
    assert status == 0
