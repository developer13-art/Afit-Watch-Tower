"""RTSP connection-string parsing and validation (proposal sections 6.2 and 6.3).

Both registration methods must converge on one validated `ConnectionSpec`, credentials must
round-trip through percent-encoding, and every rejection must name the field the wizard has
to highlight.
"""

from __future__ import annotations

import pytest
from urllib.parse import quote

from watchtower.rtsp.parser import (
    RTSPSpecError,
    build_spec,
    parse_connection_string,
)


def test_both_registration_methods_converge_on_the_same_spec():
    """Method A (pasted address) and Method B (guided fields) describe one camera."""
    from_string = parse_connection_string("rtsp://admin:s3cr3t@10.20.0.7:554/media/video1")
    from_fields = build_spec(
        host="10.20.0.7",
        port=554,
        stream_path="/media/video1",
        username="admin",
        password="s3cr3t",
    )
    assert from_string == from_fields
    assert from_string.to_url() == from_fields.to_url()


def test_both_methods_default_the_rtsp_port_the_same_way():
    from_string = parse_connection_string("rtsp://10.20.0.7/live0")
    from_fields = build_spec(
        host="10.20.0.7", port=None, stream_path="/live0", username=None, password=None
    )
    assert from_string.port == 554
    assert from_fields.port == from_string.port
    assert from_string.host == from_fields.host == "10.20.0.7"


def test_both_methods_converge_when_the_stream_path_carries_query_parameters():
    """Section 6.1: Method A and Method B must produce the same spec.

    Cameras such as the Genexie-style ones select the stream with query parameters, so a
    parser that keeps only `path` dials a different stream from the one VLC verified.
    """
    path = "/cam/realmonitor?channel=1&subtype=0"
    from_string = parse_connection_string(f"rtsp://admin:pw@10.20.0.7:554{path}")
    from_fields = build_spec(
        host="10.20.0.7", port=554, stream_path=path, username="admin", password="pw"
    )
    assert from_string.path == from_fields.path == path
    assert from_string.to_url() == from_fields.to_url()


def test_special_characters_in_credentials_round_trip_through_percent_encoding():
    """A password containing @, : and / must survive parse -> build -> to_url intact."""
    password = "p@ss:w/rd!x"
    username = "a.d_min"
    url = f"rtsp://{username}:{quote(password, safe='')}@10.20.0.7:554/cam/realmonitor"

    parsed = parse_connection_string(url)
    assert parsed.username == username
    assert parsed.password == password

    rebuilt = build_spec(
        host=parsed.host,
        port=parsed.port,
        stream_path=parsed.path,
        username=parsed.username,
        password=parsed.password,
    )
    assert rebuilt.password == password
    assert quote(password, safe="") in rebuilt.to_url()
    assert password not in rebuilt.to_url()  # never embedded raw
    assert parse_connection_string(rebuilt.to_url()).password == password


def test_a_percent_in_a_password_is_not_double_decoded():
    parsed = parse_connection_string("rtsp://admin:100%25sure@10.20.0.7/live")
    assert parsed.password == "100%sure"
    assert parse_connection_string(parsed.to_url()).password == "100%sure"


def test_non_rtsp_scheme_is_rejected_and_names_the_rtsp_url_field():
    for bad in (
        "http://10.20.0.7:554/live",
        "rtmp://10.20.0.7/live",
        "onvif://www.onvif.org/Profile/Streaming",
    ):
        with pytest.raises(RTSPSpecError) as raised:
            parse_connection_string(bad)
        assert raised.value.field == "rtsp_url", bad
        assert "RTSP" in raised.value.message


def test_an_empty_connection_string_is_rejected():
    with pytest.raises(RTSPSpecError) as raised:
        parse_connection_string("   ")
    assert raised.value.field == "rtsp_url"


def test_a_connection_string_without_a_host_is_rejected():
    with pytest.raises(RTSPSpecError) as raised:
        parse_connection_string("rtsp://:554/live")
    assert raised.value.field == "rtsp_url"


def test_a_missing_stream_path_is_rejected_and_names_the_stream_path_field():
    with pytest.raises(RTSPSpecError) as raised:
        parse_connection_string("rtsp://admin:pw@10.20.0.7:554")
    assert raised.value.field == "stream_path"

    with pytest.raises(RTSPSpecError) as root_only:
        parse_connection_string("rtsp://admin:pw@10.20.0.7:554/")
    assert root_only.value.field == "stream_path"

    with pytest.raises(RTSPSpecError) as guided:
        build_spec(host="10.20.0.7", port=554, stream_path="", username=None, password=None)
    assert guided.value.field == "stream_path"


def test_out_of_range_ports_are_rejected():
    for port in (0, 70000, 65536):
        with pytest.raises(RTSPSpecError) as raised:
            build_spec(
                host="10.20.0.7", port=port, stream_path="/live", username=None, password=None
            )
        assert raised.value.field == "port", port

    with pytest.raises(RTSPSpecError) as pasted:
        parse_connection_string("rtsp://10.20.0.7:99999/live")
    assert "port" in pasted.value.message.lower()
    assert pasted.value.field in {"port", "rtsp_url"}


def test_a_non_numeric_port_is_rejected_by_the_guided_form():
    with pytest.raises(RTSPSpecError) as raised:
        build_spec(
            host="10.20.0.7",
            port="not-a-port",
            stream_path="/live",
            username=None,
            password=None,
        )
    assert raised.value.field == "port"


def test_an_unknown_transport_is_rejected():
    with pytest.raises(RTSPSpecError) as raised:
        build_spec(
            host="10.20.0.7",
            port=554,
            stream_path="/live",
            username=None,
            password=None,
            transport="sctp",
        )
    assert raised.value.field == "transport"


def test_a_public_host_is_flagged_for_network_review():
    """Section 16 keeps camera streams inside network isolation, so this is surfaced."""
    public = build_spec(
        host="8.8.8.8", port=554, stream_path="/live", username=None, password=None
    )
    assert public.requires_network_review is True

    for address in ("10.20.0.7", "192.168.1.10", "172.16.5.9", "127.0.0.1", "169.254.1.20"):
        private = build_spec(
            host=address, port=554, stream_path="/live", username=None, password=None
        )
        assert private.requires_network_review is False, address


def test_a_hostname_is_not_claimed_to_be_public():
    """A name may resolve to anything; only the connection test decides."""
    named = build_spec(
        host="cam01.gate.local", port=554, stream_path="/live", username=None, password=None
    )
    assert named.requires_network_review is False


def test_the_guided_form_normalises_the_address_it_is_given():
    spec = build_spec(
        host="RTSP://Camera.Gate.Local/",
        port="554",
        stream_path="live0",
        username="  admin  ",
        password="pw",
    )
    assert spec.host == "camera.gate.local"
    assert spec.path == "/live0"
    assert spec.port == 554
    assert spec.username == "admin"


def test_redacted_url_and_non_secret_dict_never_carry_the_password():
    spec = build_spec(
        host="10.20.0.7",
        port=554,
        stream_path="/live",
        username="admin",
        password="sup3r-secret",
    )
    assert spec.password in spec.to_url()  # the ingestion service does need it
    assert spec.password not in spec.redacted_url()
    assert spec.redacted_url() == "rtsp://admin:***@10.20.0.7:554/live"

    safe = spec.non_secret_dict()
    assert safe == {
        "host": "10.20.0.7",
        "port": 554,
        "stream_path": "/live",
        "username": "admin",
        "transport": "tcp",
        "has_password": True,
    }
    assert "sup3r-secret" not in repr(safe)


def test_the_password_is_kept_out_of_repr():
    """`repr()` of the spec is what lands in a log line by accident."""
    spec = parse_connection_string("rtsp://admin:sup3r-secret@10.20.0.7:554/live")
    assert "sup3r-secret" not in repr(spec)
