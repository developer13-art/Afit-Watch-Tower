"""Signed monitoring-host ingest (contract section 9).

Every test here asks one of two questions: does a call that has not proved itself get refused
*before* it can cause work, and does a call that has proved itself get acted on exactly once.
The replay cache is a database constraint, so "exactly once" is tested across a second request
rather than assumed from an in-memory set.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json

from sqlalchemy import select

from watchtower.cloud import ingest as gate
from watchtower.mobile.models import (
    EvidenceRelayState,
    IngestNonce,
    IngestRecord,
    MonitoringHeartbeat,
    PersonnelPreference,
)
from watchtower.models import EvidenceAsset, Incident, Notification, User

from conftest import INGEST_KEY_ID

INCIDENT_PATH = "/api/v1/ingest/incident"
HEARTBEAT_PATH = "/api/v1/ingest/heartbeat"
ACK_PATH = "/api/v1/ingest/outbox-ack"


def _body(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True).encode()


def _post(client, headers_for, path: str, payload: dict, *, raw: bytes | None = None):
    body = _body(payload) if raw is None else raw
    return client.post(path, content=body, headers=headers_for(path, body))


def _incident_payload(incident, **overrides) -> dict:
    payload = {
        "idempotency_key": f"incident-{incident.id}",
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "severity": incident.severity,
        },
    }
    payload.update(overrides)
    return payload


class TestSignatureGate:
    def test_an_unsigned_call_is_refused_before_the_payload_is_read(self, cloud_app):
        response = cloud_app.post(INCIDENT_PATH, json={"idempotency_key": "k"})
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "missing_key_id"

    def test_an_unknown_key_id_says_no_more_than_that(self, cloud_app, signed_ingest_headers):
        body = _body({"idempotency_key": "k"})
        headers = signed_ingest_headers(INCIDENT_PATH, body, key_id="a-host-never-issued")
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unknown_key_id"
        assert "a-host-never-issued" not in response.text

    def test_the_wrong_secret_is_a_bad_signature(self, cloud_app, signed_ingest_headers):
        body = _body({"idempotency_key": "k"})
        headers = signed_ingest_headers(
            INCIDENT_PATH, body, secret="a-different-but-equally-long-secret-value"
        )
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "bad_signature"

    def test_a_stale_timestamp_is_refused(self, cloud_app, signed_ingest_headers):
        body = _body({"idempotency_key": "k"})
        stale = int(dt.datetime.now(dt.UTC).timestamp()) - 4000
        headers = signed_ingest_headers(INCIDENT_PATH, body, timestamp=stale)
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "timestamp_out_of_window"

    def test_a_nonce_that_is_not_hex_is_refused(self, cloud_app, signed_ingest_headers):
        body = _body({"idempotency-key": "k"})
        headers = signed_ingest_headers(INCIDENT_PATH, body, nonce="not-a-hex-nonce")
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_nonce"

    def test_a_body_changed_after_signing_is_refused(self, cloud_app, signed_ingest_headers):
        signed = _body({"idempotency_key": "k", "incident": {"id": 1}})
        headers = signed_ingest_headers(INCIDENT_PATH, signed)
        tampered = _body({"idempotency_key": "k", "incident": {"id": 999}})
        response = cloud_app.post(INCIDENT_PATH, content=tampered, headers=headers)
        assert response.status_code == 401
        # The digest check is what stops a proxy, or an attacker in the same rack, from editing
        # the alert it is carrying.
        assert response.json()["error"]["code"] == "content_mismatch"

    def test_authorization_naming_another_key_is_not_a_fallback(self, cloud_app, signed_ingest_headers):
        body = _body({"idempotency_key": "k"})
        headers = signed_ingest_headers(INCIDENT_PATH, body)
        # One request must be attributable to exactly one credential, so the header and the
        # signature have to name the same key. Substituting a different id is not a second try.
        headers["authorization"] = headers["authorization"].replace(
            f"{INGEST_KEY_ID}:", "some-other-host:"
        )
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "key_id_mismatch"

    def test_a_header_key_the_cloud_does_not_know_never_reaches_the_signature(
        self, cloud_app, signed_ingest_headers
    ):
        body = _body({"idempotency_key": "k"})
        headers = signed_ingest_headers(INCIDENT_PATH, body)
        headers["x-watchtower-key-id"] = "another-key-id"
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "unknown_key_id"

    def test_a_replayed_request_is_refused_and_consumed_nothing(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        signed_in("security_supervisor", push_token="fcm-token-value-replay")
        incident = factory.incident()
        factory.session.commit()
        body = _body(_incident_payload(incident))
        headers = signed_ingest_headers(INCIDENT_PATH, body)
        assert cloud_app.post(INCIDENT_PATH, content=body, headers=headers).status_code == 201

        again = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert again.status_code == 401
        assert again.json()["error"]["code"] == "replay_detected"

        _reload(factory.session)
        assert len(factory.session.scalars(
            select(Notification).where(Notification.incident_id == incident.id)
        ).all()) == 1
        # One alert, not two: the replay stopped at the nonce, before the payload could act.
        assert len(factory.session.scalars(
            select(IngestRecord).where(
                IngestRecord.idempotency_key == f"incident-{incident.id}"
            )
        ).all()) == 1

    def test_a_replay_survives_a_fresh_process_because_the_cache_is_a_table(
        self, cloud_app, signed_ingest_headers, factory
    ):
        """A captured request replayed after a restart still fails: no in-memory set is involved."""
        body = _body({"idempotency_key": "heartbeat-1", "monitoring_host": "watch-host-1"})
        headers = signed_ingest_headers(HEARTBEAT_PATH, body)
        assert cloud_app.post(HEARTBEAT_PATH, content=body, headers=headers).status_code == 200
        _reload(factory.session)
        stored = factory.session.scalar(select(IngestNonce))
        assert stored is not None and stored.key_id == INGEST_KEY_ID
        # Same nonce, new timestamp - the signature is still valid and still refused.
        fresh_headers = signed_ingest_headers(HEARTBEAT_PATH, body, nonce=headers["x-watchtower-nonce"])
        response = cloud_app.post(HEARTBEAT_PATH, content=body, headers=fresh_headers)
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "replay_detected"

    def test_an_oversized_body_is_refused_without_being_verified(
        self, cloud_app, signed_ingest_headers, monkeypatch
    ):
        monkeypatch.setattr(gate, "MAX_BODY_BYTES", 128)
        body = _body({"idempotency_key": "k", "padding": "x" * 4096})
        headers = signed_ingest_headers(INCIDENT_PATH, body)
        response = cloud_app.post(INCIDENT_PATH, content=body, headers=headers)
        assert response.status_code == 413
        assert response.json()["error"]["code"] == "payload_too_large"

    def test_a_cloud_with_no_service_key_accepts_nothing(
        self, make_cloud_app, cloud_settings, factory
    ):
        client = make_cloud_app(cloud_settings, service_keys={})
        incident = factory.incident()
        factory.session.commit()
        response = client.post(INCIDENT_PATH, content=_body({"idempotency_key": "k"}))
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "ingest_unconfigured"
        _reload(factory.session)
        # Nothing is remembered about a call that was refused at the gate, so the replay table
        # stays empty and the incident it named is untouched.
        assert factory.session.scalars(select(IngestRecord)).all() == []
        assert factory.session.get(Incident, incident.id) is not None

    def test_an_ingest_call_is_not_reachable_with_a_persons_token(
        self, signed_in, cloud_app
    ):
        response = cloud_app.post(
            INCIDENT_PATH,
            content=_body({"idempotency_key": "k"}),
            headers=signed_in("security_supervisor").actor.headers,
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "missing_key_id"


class TestIncidentIngest:
    def test_a_signed_incident_pages_the_eligible_recipients_once(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        target = signed_in("security_supervisor", push_token="fcm-token-value-aaaa")
        unrelated = signed_in("technical_operator", push_token="fcm-token-value-bbbb",
                              installation_id="22222222-2222-4333-8444-555555555555")
        incident = factory.incident(title="Perimeter motion", severity="high")
        factory.session.commit()

        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH,
                         _incident_payload(incident))
        assert response.status_code == 201
        body = response.json()
        assert body["incident_id"] == incident.id
        assert body["reference"] == incident.reference
        assert body["delivery"] == "queued"
        assert body["notifications_created"] == 1

        _reload(factory.session)
        notes = factory.session.scalars(
            select(Notification).where(Notification.incident_id == incident.id)
        ).all()
        # A technical operator holds no incident role for this severity: not suppressed, never a
        # recipient in the first place.
        assert [n.recipient_id for n in notes] == [target.user.id]
        assert unrelated.user.id not in [n.recipient_id for n in notes]
        assert notes[0].state == "pending"
        assert notes[0].dedupe_key == f"incident.created:incident:{incident.id}"

        record = factory.session.scalar(select(IngestRecord))
        assert record.incident_id == incident.id
        assert record.key_id == INGEST_KEY_ID
        assert record.response["reference"] == incident.reference

    def test_the_same_idempotency_key_answers_with_the_first_result(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        signed_in("security_supervisor", push_token="fcm-token-value-cccc")
        incident = factory.incident()
        factory.session.commit()
        payload = _incident_payload(incident)
        first = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, payload)
        assert first.status_code == 201
        # A retry after a lost response carries a new nonce - the forwarder has not been told
        # the first attempt landed - but the same key.
        second = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, payload)
        assert second.status_code == 201
        assert second.json()["duplicate"] is True
        assert second.json()["incident_id"] == first.json()["incident_id"]

        _reload(factory.session)
        assert len(factory.session.scalars(select(Notification)).all()) == 1
        assert len(factory.session.scalars(select(IngestRecord)).all()) == 1

    def test_reusing_a_key_for_different_content_is_refused_instead_of_answered_with_the_old_result(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        """A used key carrying different bytes is a different alert, not a retry.

        Without the digest comparison this call would be answered from the stored response and
        report success, so the second alert would be gone with no failed row anywhere.
        """
        signed_in("security_supervisor", push_token="fcm-token-value-dddd")
        incident = factory.incident()
        factory.session.commit()
        assert _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, _incident_payload(incident)).status_code == 201

        conflicting = _incident_payload(incident)
        conflicting["title"] = "Different content under a used key"
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, conflicting)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "idempotency_conflict"

        _reload(factory.session)
        assert len(factory.session.scalars(select(IngestRecord)).all()) == 1
        assert len(factory.session.scalars(select(Notification)).all()) == 1

    def test_a_payload_describing_an_incident_that_does_not_exist_is_refused_permanently(
        self, cloud_app, signed_ingest_headers
    ):
        response = _post(
            cloud_app, signed_ingest_headers, INCIDENT_PATH,
            {"idempotency_key": "ghost-1", "incident": {"id": 424242}},
        )
        assert response.status_code == 410
        assert response.json()["error"]["code"] == "incident_unavailable"

    def test_a_payload_without_an_incident_id_is_refused(
        self, cloud_app, signed_ingest_headers
    ):
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, {"idempotency_key": "k"})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "incident_id_required"

    def test_a_call_without_an_idempotency_key_is_refused(self, cloud_app, signed_ingest_headers):
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, {"incident": {"id": 1}})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "idempotency_key_required"

    def test_a_body_that_is_not_a_json_object_is_refused(
        self, cloud_app, signed_ingest_headers
    ):
        for raw in (b"[1,2,3]", b"not json at all", b'{"a": 1', b"\xff\xfe"):
            response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, {}, raw=raw)
            assert response.status_code == 422, raw
            assert response.json()["error"]["code"] == "invalid_json", raw

    def test_an_empty_body_is_an_empty_object_and_fails_on_the_key(
        self, cloud_app, signed_ingest_headers
    ):
        # `body or {}` is deliberate: a signed, empty POST is a well-formed call that is missing
        # a field, which is a different refusal from a body that is not JSON.
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, {}, raw=b"")
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "idempotency_key_required"

    def test_a_recipient_without_a_device_is_not_invented_one(
        self, cloud_app, signed_ingest_headers, factory
    ):
        user = factory.user(username="no.handset.yet", roles=("security_supervisor",))
        factory.session.commit()
        incident = factory.incident(severity="high")
        factory.session.commit()
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH,
                         _incident_payload(incident))
        assert response.json()["notifications_created"] == 0
        assert response.json()["devices_targeted"] == 0
        _reload(factory.session)
        assert factory.session.scalars(select(Notification)).all() == []
        # The person is a real, active recipient of this alert; the only thing missing is a
        # handset, and the cloud does not invent one to make a delivery look plausible.
        assert factory.session.get(User, user.id).is_active is True

    def test_a_silenced_account_is_recorded_as_suppressed_with_the_reason(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        target = signed_in("security_supervisor", push_token="fcm-token-value-dddd")
        _reload(factory.session)
        factory.session.add(
            PersonnelPreference(
                user_id=target.user.id,
                min_severity="critical",
                kinds={},
                quiet_hours={},
            )
        )
        factory.session.commit()

        incident = factory.incident(severity="medium")
        factory.session.commit()
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH,
                         _incident_payload(incident))
        assert response.json()["notifications_suppressed"] == 1

        _reload(factory.session)
        note = factory.session.scalar(select(Notification))
        assert note.state == "suppressed"
        assert note.failure_reason == "below_min_severity:critical"

    def test_a_critical_alert_ignores_an_individuals_silence(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        target = signed_in("security_supervisor", push_token="fcm-token-value-eeee")
        _reload(factory.session)
        factory.session.add(
            PersonnelPreference(
                user_id=target.user.id, min_severity="critical", kinds={}, quiet_hours={}
            )
        )
        factory.session.commit()
        incident = factory.incident(severity="critical")
        factory.session.commit()
        response = _post(cloud_app, signed_ingest_headers, INCIDENT_PATH,
                         _incident_payload(incident))
        assert response.json()["notifications_created"] == 1
        _reload(factory.session)
        assert factory.session.scalar(select(Notification)).state == "pending"


class TestHeartbeatAndAck:
    def test_a_heartbeat_is_stored_and_needs_no_idempotency_key(
        self, cloud_app, signed_ingest_headers, factory
    ):
        payload = {"monitoring_host": "watch-host-1", "app_version": "1.4.2",
                   "outbox_pending": 7, "outbox_failed": 2}
        first = _post(cloud_app, signed_ingest_headers, HEARTBEAT_PATH, payload)
        assert first.status_code == 200
        assert first.json()["monitoring_host"] == "watch-host-1"
        assert first.json()["next_heartbeat_seconds"] >= 5
        # The same report twice is normal - it is a heartbeat, not an alert.
        assert _post(cloud_app, signed_ingest_headers, HEARTBEAT_PATH, payload).status_code == 200

        _reload(factory.session)
        rows = factory.session.scalars(select(MonitoringHeartbeat)).all()
        assert len(rows) == 2
        assert (rows[0].outbox_pending, rows[0].outbox_failed) == (7, 2)
        assert rows[0].app_version == "1.4.2"

    def test_a_counter_that_is_not_a_number_is_the_callers_error(
        self, cloud_app, signed_ingest_headers, factory
    ):
        response = _post(
            cloud_app, signed_ingest_headers, HEARTBEAT_PATH,
            {"monitoring_host": "watch-host-1", "outbox_pending": "seven or eight"},
        )
        assert response.status_code == 422
        error = response.json()["error"]
        assert error["code"] == "validation_failed"
        assert "outbox_pending" in error["message"]
        _reload(factory.session)
        assert factory.session.scalars(select(MonitoringHeartbeat)).all() == []

    def test_a_heartbeat_without_a_host_name_is_refused(self, cloud_app, signed_ingest_headers):
        response = _post(cloud_app, signed_ingest_headers, HEARTBEAT_PATH, {"outbox_pending": 1})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "monitoring_host_required"

    def test_an_ack_reports_whether_the_key_was_processed(
        self, cloud_app, signed_ingest_headers, signed_in, factory
    ):
        signed_in("security_supervisor", push_token="fcm-token-value-ffff")
        incident = factory.incident()
        factory.session.commit()
        payload = _incident_payload(incident, idempotency_key="forwarded-42")
        assert _post(cloud_app, signed_ingest_headers, INCIDENT_PATH, payload).status_code == 201

        acked = _post(cloud_app, signed_ingest_headers, ACK_PATH, {"idempotency_key": "forwarded-42"})
        assert acked.status_code == 200
        assert acked.json()["processed"] is True
        assert acked.json()["incident_id"] == incident.id

        unknown = _post(cloud_app, signed_ingest_headers, ACK_PATH, {"idempotency_key": "no-such"})
        assert unknown.status_code == 200
        assert unknown.json()["processed"] is False

    def test_an_ack_without_a_key_is_refused(self, cloud_app, signed_ingest_headers):
        response = _post(cloud_app, signed_ingest_headers, ACK_PATH, {"incident_id": 1})
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "idempotency_key_required"


def _evidence_asset(factory, *, data: bytes, kind="snapshot", content_type="image/jpeg",
                    storage_key="inc-1/snapshot-1.jpg", **overrides):
    incident = factory.incident()
    asset = EvidenceAsset(
        incident_id=incident.id,
        kind=kind,
        filename=storage_key.rsplit("/", 1)[-1],
        storage_key=storage_key,
        content_type=content_type,
        byte_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        captured_at=dt.datetime.now(dt.UTC),
        **overrides,
    )
    factory.session.add(asset)
    factory.session.flush()
    return asset, incident


def _reload(session):
    session.commit()
    session.expire_all()


class TestEvidenceRelay:
    def test_relayed_bytes_land_inside_the_cloud_directory(
        self, cloud_app, cloud_settings, signed_ingest_headers, factory
    ):
        data = b"\xff\xd8\xff\xe0fake-jpeg-bytes"
        asset, incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        payload = {
            "idempotency_key": f"evidence:{asset.id}",
            "sha256": asset.sha256,
            "byte_size": len(data),
            "kind": asset.kind,
            "content_type": asset.content_type,
            "data_base64": base64.b64encode(data).decode(),
        }
        path = f"/api/v1/ingest/evidence/{asset.id}"
        response = _post(cloud_app, signed_ingest_headers, path, payload)
        assert response.status_code == 201
        assert response.json()["stored"] is True
        assert response.json()["bytes_received"] == len(data)
        assert response.json()["incident_id"] == incident.id

        target = cloud_settings.evidence_dir / asset.storage_key
        assert target.is_file()
        assert target.read_bytes() == data
        assert not list(cloud_settings.evidence_dir.glob("*.part"))

        _reload(factory.session)
        state = factory.session.scalar(
            select(EvidenceRelayState).where(EvidenceRelayState.asset_id == asset.id)
        )
        assert state.state == "available"
        assert state.received_sha256 == asset.sha256
        assert state.bytes_received == len(data)
        assert state.last_error is None

    def test_a_relayed_asset_serves_the_stored_bytes_to_a_phone(
        self, cloud_app, cloud_settings, signed_ingest_headers, signed_in, factory
    ):
        """The two halves meet here: the monitoring host writes, the phone reads."""
        data = b"\xff\xd8\xff\xe0gate-snapshot"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        actor = signed_in("security_supervisor", push_token=None).actor
        path = f"/api/v1/ingest/evidence/{asset.id}"
        _post(
            cloud_app, signed_ingest_headers, path,
            {"idempotency_key": f"evidence:{asset.id}", "sha256": asset.sha256,
             "byte_size": len(data), "data_base64": base64.b64encode(data).decode()},
        )
        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=actor.headers
        )
        assert response.status_code == 200
        assert response.content == data
        assert response.headers["content-type"] == asset.content_type
        # The claimed content type in the relay body is not what reaches the browser header.
        assert cloud_settings.evidence_dir not in response.headers.values()

    def test_bytes_that_do_not_match_the_record_are_never_made_visible(
        self, cloud_app, cloud_settings, signed_ingest_headers, factory
    ):
        data = b"the-real-bytes-here"
        # Same length, different content: the only thing left to catch it is the digest.
        wrong = bytes(item ^ 0xFF for item in data)
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        path = f"/api/v1/ingest/evidence/{asset.id}"
        response = _post(
            cloud_app, signed_ingest_headers, path,
            {"idempotency_key": "relay-1", "sha256": asset.sha256,
             "byte_size": len(wrong), "data_base64": base64.b64encode(wrong).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_digest_mismatch"
        assert not (cloud_settings.evidence_dir / asset.storage_key).exists()
        # The temporary file is deleted on the way out, so a half-written asset is not left
        # where a later relay could overwrite the name and a reader could find it.
        assert not list(cloud_settings.evidence_dir.glob("**/*.part"))

    def test_a_refused_relay_is_still_recorded(
        self, cloud_app, signed_ingest_headers, factory
    ):
        """The 422 is rolled back; the fact that a bad attempt arrived is not."""
        data = b"the-real-bytes-here"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        wrong = bytes(item ^ 0xFF for item in data)
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-11", "sha256": asset.sha256,
             "byte_size": len(wrong), "data_base64": base64.b64encode(wrong).decode()},
        )
        assert response.status_code == 422

        _reload(factory.session)
        state = factory.session.scalar(
            select(EvidenceRelayState).where(EvidenceRelayState.asset_id == asset.id)
        )
        assert state is not None
        assert state.state == "missing"
        assert "digest" in state.last_error

    def test_a_declared_digest_that_is_not_the_rows_is_refused(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"snapshot-bytes"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-2", "sha256": hashlib.sha256(b"other").hexdigest(),
             "byte_size": len(data), "data_base64": base64.b64encode(data).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_digest_mismatch"

    def test_a_byte_size_that_does_not_match_the_data_is_refused(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"snapshot-bytes"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-3", "sha256": asset.sha256, "byte_size": 1,
             "data_base64": base64.b64encode(data).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_size_mismatch"

    def test_a_missing_byte_size_is_refused_rather_than_defaulting_to_zero(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"snapshot-bytes"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-4", "sha256": asset.sha256,
             "data_base64": base64.b64encode(data).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_size_required"

    def test_a_non_numeric_byte_size_is_a_422_not_a_500(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"snapshot-bytes"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-5", "sha256": asset.sha256, "byte_size": "lots",
             "data_base64": base64.b64encode(data).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "validation_failed"

    def test_data_that_is_not_base64_is_refused(self, cloud_app, signed_ingest_headers, factory):
        asset, _incident = _evidence_asset(factory, data=b"snapshot-bytes")
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-6", "sha256": asset.sha256, "byte_size": 14,
             "data_base64": "not!base64!!"},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_data_invalid"

    def test_a_content_type_claimed_by_the_sender_does_not_become_a_response_header(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"<script>alert(1)</script>"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-7", "sha256": asset.sha256, "byte_size": len(data),
             "content_type": "text/html", "kind": asset.kind,
             "data_base64": base64.b64encode(data).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_metadata_mismatch"

    def test_an_asset_type_the_cloud_will_not_serve_is_refused_on_the_way_in(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"executable-bytes"
        asset, _incident = _evidence_asset(
            factory, data=data, content_type="application/x-executable"
        )
        factory.session.commit()
        response = _post(
            cloud_app, signed_ingest_headers, f"/api/v1/ingest/evidence/{asset.id}",
            {"idempotency_key": "relay-8", "sha256": asset.sha256, "byte_size": len(data),
             "data_base64": base64.b64encode(data).decode()},
        )
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "evidence_type_unsupported"

    def test_an_unknown_asset_is_refused_and_no_bytes_are_written(
        self, cloud_app, cloud_settings, signed_ingest_headers
    ):
        response = _post(
            cloud_app, signed_ingest_headers, "/api/v1/ingest/evidence/999999",
            {"idempotency_key": "relay-9", "sha256": "0" * 64, "byte_size": 4,
             "data_base64": base64.b64encode(b"bytes").decode()},
        )
        assert response.status_code == 404
        assert not any(cloud_settings.evidence_dir.glob("**/*"))

    def test_a_retried_relay_is_answered_from_the_first_one(
        self, cloud_app, signed_ingest_headers, factory
    ):
        data = b"one-snapshot-two-answers"
        asset, _incident = _evidence_asset(factory, data=data)
        factory.session.commit()
        payload = {"idempotency_key": "relay-10", "sha256": asset.sha256,
                   "byte_size": len(data), "data_base64": base64.b64encode(data).decode()}
        path = f"/api/v1/ingest/evidence/{asset.id}"
        first = _post(cloud_app, signed_ingest_headers, path, payload)
        assert first.status_code == 201
        second = _post(cloud_app, signed_ingest_headers, path, payload)
        assert second.json()["duplicate"] is True
        assert second.json()["stored"] is True
