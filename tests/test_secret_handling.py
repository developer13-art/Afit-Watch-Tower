"""Secret handling (proposal sections 8.3, 6.5, 16 and 22).

The promise under test is narrow and absolute: a camera password and a credential-bearing
RTSP URL exist only as input. They are sealed into `camera_secrets`, never stored in a
column, never returned in a response body, never written to an audit row in the clear.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy import select

from watchtower import models as wt_models
from watchtower.rtsp.parser import ConnectionSpec, build_spec
from watchtower.security.audit import sanitize
from watchtower.security.secrets import REDACTED_PLACEHOLDER, KeyRing, SecretStore, key_is_secret, redact

PASSWORD = "sup3r-secret-pw"
URL = f"rtsp://admin:{PASSWORD}@10.20.0.7:554/cam/realmonitor"


# --------------------------------------------------------------------------- #
# Sealing at rest
# --------------------------------------------------------------------------- #


def test_a_sealed_secret_never_contains_the_plaintext(secret_store):
    sealed = secret_store.seal(PASSWORD)

    assert sealed.ciphertext != PASSWORD.encode()
    assert PASSWORD.encode() not in sealed.ciphertext
    assert PASSWORD not in repr(sealed)
    # only the length is kept for diagnostics
    assert sealed.plaintext_length == len(PASSWORD)


def test_a_sealed_secret_round_trips_through_the_key_ring(db, secret_store, settings):
    row = secret_store.persist(db, secret_store.seal(PASSWORD))
    db.commit()

    assert secret_store.reveal(row) == PASSWORD
    assert row.ciphertext is not None
    assert PASSWORD not in str(row.ciphertext)


def test_the_ciphertext_column_holds_no_password_bytes(db, factory):
    factory.camera(password=PASSWORD)
    factory.session.commit()

    stored = factory.session.scalars(select(wt_models.CameraSecret)).all()
    assert stored
    for row in stored:
        assert PASSWORD.encode() not in row.ciphertext
        assert row.reference.startswith("sec_")
    # and no camera/profile column holds a password or reassembles the URL
    profile = factory.session.scalars(select(wt_models.CameraConnectionProfile)).one()
    assert not hasattr(profile, "password")
    mapped = {column.name for column in wt_models.CameraConnectionProfile.__table__.columns}
    assert "password" not in mapped
    assert "rtsp_url" not in mapped
    for column in ("host", "stream_path", "username", "secret_reference"):
        assert PASSWORD not in str(getattr(profile, column))
    camera_columns = {column.name for column in wt_models.Camera.__table__.columns}
    assert "password" not in camera_columns
    assert "rtsp_url" not in camera_columns


def test_a_second_key_ring_cannot_reveal_the_secret(tmp_path, db):
    """The ring file is the secret; a stolen database row is not decryptable on its own."""
    row = db.scalars(select(wt_models.CameraSecret)).first()
    if row is None:
        store = SecretStore(KeyRing(tmp_path / "ring.json", create_if_missing=True))
        row = store.persist(db, store.seal(PASSWORD))
        db.commit()

    other = SecretStore(KeyRing(tmp_path / "other-ring.json", create_if_missing=True))
    with pytest.raises(Exception) as caught:  # SecretStoreError, deliberately not a plaintext
        other.reveal(row)
    assert PASSWORD not in str(caught.value)


# --------------------------------------------------------------------------- #
# Redaction at the log / error / audit boundary
# --------------------------------------------------------------------------- #


def test_redact_masks_the_password_inside_a_url_bearing_error_message():
    message = f"FFmpeg failed to open {URL} (error -8)"

    masked = redact(message)

    assert PASSWORD not in masked
    assert "admin:***@" in masked
    # the host and path stay, because they are what an operator needs to fix the camera
    assert "10.20.0.7" in masked
    assert "/cam/realmonitor" in masked


def test_redact_masks_a_password_field_inside_a_json_body():
    body = json.dumps({"host": "10.20.0.7", "password": PASSWORD, "transport": "tcp"})

    masked = redact(body)

    assert PASSWORD not in masked
    assert json.loads(masked)["password"] == "***"
    assert json.loads(masked)["host"] == "10.20.0.7"


def test_redact_masks_a_password_passed_as_a_query_parameter():
    masked = redact(f"POST /hook?password={PASSWORD}&kind=alert")
    assert PASSWORD not in masked
    assert "password=***" in masked


def test_audit_sanitisation_recurses_into_nested_details():
    details = {
        "error": f"connect failed for {URL}",
        "attempted": [URL],
        "payload": {"rtsp_url": URL, "port": 554},
    }

    cleaned = sanitize(details)

    assert PASSWORD not in json.dumps(cleaned)
    assert cleaned["payload"]["port"] == 554


def test_a_key_naming_a_credential_masks_its_value_even_without_a_pattern():
    """A raw password handed over as `{"rtsp_password": "…"}` matches no URL or JSON pattern.

    The key is the only thing that says what the value is, so the key has to be the signal.
    """
    cleaned = sanitize({"rtsp_password": PASSWORD, "connection": {"api_key": PASSWORD}})

    assert cleaned["rtsp_password"] == REDACTED_PLACEHOLDER
    assert cleaned["connection"]["api_key"] == REDACTED_PLACEHOLDER
    assert PASSWORD not in json.dumps(cleaned)


@pytest.mark.parametrize(
    "name",
    ["has_secret", "secret_reference", "password_fingerprint", "token_kind", "password_hint_count"],
)
def test_a_descriptor_that_only_mentions_a_secret_is_not_masked(name):
    """Masking these would destroy the context an investigator needs, without hiding anything."""
    assert key_is_secret(name) is False


def test_key_naming_is_case_and_separator_insensitive():
    assert key_is_secret("RTSP-Password") is True
    assert key_is_secret("  Authorization ") is True
    assert key_is_secret("access_token") is True


def test_redact_masks_a_password_that_contains_an_at_sign():
    awkward = "rtsp://admin:p@ssw0rd@10.20.0.7/live"
    masked = redact(awkward)
    assert "ssw0rd" not in masked
    assert "p@ssw0rd" not in masked


def test_a_failed_probe_with_a_credential_url_is_redacted_in_the_audit_row(
    admin, fake_probe, read_audit
):
    """The failure message genuinely carries the URL a driver produced; the audit row must not."""
    fake_probe(
        wt_models.ProbeResult.AUTH_FAILED,
        message=f"RTSP DESCRIBE for {URL} returned 401",
    )
    created = admin.client.post(
        "/api/cameras",
        json={
            "method": "rtsp_string",
            "display_name": "Gate Redaction",
            "code": "AFIT-REDACT-001",
            "campus_location": "Main gate",
            "rtsp_url": URL,
            "verified_in_vlc": True,
        },
    )
    assert created.status_code == 201, created.text

    rows = [row for row in read_audit() if row.action == "camera.connection_test"]
    assert rows
    dumped = json.dumps(rows[-1].details)
    assert PASSWORD not in dumped
    assert f":{PASSWORD}@" not in dumped
    assert "admin:***@" in dumped


# --------------------------------------------------------------------------- #
# Nothing credential-bearing leaves through the API
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "url",
    [
        "/api/cameras",
        "/api/cameras/{id}",
        "/api/cameras/summary/overview",
        "/api/events",
        "/api/incidents",
        "/api/notifications",
        "/api/auth/me",
    ],
)
def test_no_endpoint_body_carries_a_password_or_a_scheme_bearing_url(
    admin, fake_probe, url
):
    fake_probe(wt_models.ProbeResult.CONNECTED)
    created = admin.client.post(
        "/api/cameras",
        json={
            "method": "rtsp_string",
            "display_name": "Gate Leakage",
            "code": "AFIT-LEAK-001",
            "campus_location": "Main gate",
            "rtsp_url": URL,
            "verified_in_vlc": True,
        },
    )
    assert created.status_code == 201, created.text
    camera_id = created.json()["camera"]["id"]

    response = admin.client.get(url.replace("{id}", camera_id))
    assert response.status_code == 200, response.text
    body = response.text
    assert PASSWORD not in body
    assert "rtsp://" not in body
    assert f"{PASSWORD}" not in body


def test_register_exposes_only_non_secret_connection_fields(admin, fake_probe):
    fake_probe(wt_models.ProbeResult.CONNECTED)
    response = admin.client.post(
        "/api/cameras",
        json={
            "method": "structured",
            "display_name": "Gate Shape",
            "code": "AFIT-SHAPE-001",
            "campus_location": "Main gate",
            "host": "10.20.0.7",
            "port": "554",
            "stream_path": "live",
            "username": "admin",
            "password": PASSWORD,
            "transport": "tcp",
            "verified_in_vlc": True,
        },
    )
    assert response.status_code == 201, response.text
    camera = response.json()["camera"]

    assert camera["host"] == "10.20.0.7"
    assert camera["port"] == 554
    assert camera["stream_path"] == "/live"
    assert camera["username"] == "admin"
    assert camera["has_secret"] is True
    # the shape of the exposed record is exactly the non-secret projection
    assert "password" not in camera
    assert "secret" not in {key for key in camera if key != "has_secret"}
    assert "rtsp_url" not in camera
    assert PASSWORD not in response.text


def test_a_patch_that_rotates_the_password_reports_only_the_fingerprint(
    admin, fake_probe, read_audit
):
    fake_probe(wt_models.ProbeResult.CONNECTED)
    created = admin.client.post(
        "/api/cameras",
        json={
            "method": "rtsp_string",
            "display_name": "Gate Rotate",
            "code": "AFIT-ROT-001",
            "campus_location": "Main gate",
            "rtsp_url": URL,
            "verified_in_vlc": True,
        },
    )
    camera_id = created.json()["camera"]["id"]
    fake_probe(wt_models.ProbeResult.CONNECTED)

    rotated = admin.client.patch(
        f"/api/cameras/{camera_id}",
        json={"rtsp_url": "rtsp://admin:rotated-secret-pw@10.20.0.7:554/cam/realmonitor"},
    )
    assert rotated.status_code == 200, rotated.text
    assert "rotated-secret-pw" not in rotated.text
    assert PASSWORD not in rotated.text

    rows = [row for row in read_audit() if row.action == "camera.secret.rotate"]
    assert rows, "a credential rotation must be audited"
    assert len(rows[-1].details["fingerprint"]) == 12
    assert "rotated-secret-pw" not in json.dumps(rows[-1].details)


def test_the_probe_never_receives_a_url_that_the_api_returned(admin, fake_probe):
    """`spec_for()` reassembles the credential in-process; that object is the only carrier."""
    fake_probe(wt_models.ProbeResult.CONNECTED)
    created = admin.client.post(
        "/api/cameras",
        json={
            "method": "rtsp_string",
            "display_name": "Gate In-Process",
            "code": "AFIT-INPROC-001",
            "campus_location": "Main gate",
            "rtsp_url": URL,
            "verified_in_vlc": True,
        },
    )
    assert created.status_code == 201, created.text

    spec = fake_probe.calls[-1]
    assert isinstance(spec, ConnectionSpec)
    assert spec.password == PASSWORD
    # but the redacted projection is what any log line would get
    assert "rtsp://" in spec.redacted_url()
    assert PASSWORD not in spec.redacted_url()
    assert PASSWORD not in json.dumps(spec.non_secret_dict())


def test_a_revealed_secret_is_used_for_the_stream_but_not_echoed(admin, fake_probe):
    """A second test run re-reveals the stored password; the response stays clean."""
    fake_probe(wt_models.ProbeResult.CONNECTED)
    created = admin.client.post(
        "/api/cameras",
        json={
            "method": "rtsp_string",
            "display_name": "Gate Retest",
            "code": "AFIT-RETEST-001",
            "campus_location": "Main gate",
            "rtsp_url": URL,
            "verified_in_vlc": True,
        },
    )
    camera_id = created.json()["camera"]["id"]

    again = admin.client.post(f"/api/cameras/{camera_id}/test")
    assert again.status_code == 200, again.text
    assert PASSWORD not in again.text
    assert "rtsp://" not in again.text
    assert fake_probe.calls[-1].to_url() == build_spec(
        host="10.20.0.7",
        port=554,
        stream_path="/cam/realmonitor",
        username="admin",
        password=PASSWORD,
        transport="tcp",
    ).to_url()
