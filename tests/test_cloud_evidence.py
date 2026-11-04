"""Evidence retrieval on a handset (contract section 7).

A phone reads bytes that the monitoring host wrote and the cloud merely holds. Everything tested
here is a boundary the proposal insists on: the bytes are reachable only through an access
decision, the file path never crosses to the client, an asset whose bytes have not arrived yet
says so, and the short link an `<img>` tag uses cannot be traded for anything else.
"""

from __future__ import annotations

import datetime as dt
import hashlib

from sqlalchemy import select

from watchtower.cloud import storage
from watchtower.cloud.evidence_tokens import mint
from watchtower.models import AuditLog, EvidenceAsset, UserRole

from conftest import TEST_PASSWORD, Personnel

SNAPSHOT = b"\xff\xd8\xff\xe0gate-snapshot-bytes"


def _reload(session):
    session.commit()
    session.expire_all()


def _asset(factory, settings, *, incident=None, group_id=None, content_type="image/jpeg",
           kind="snapshot", storage_key="inc-relay/snap-1.jpg", data=SNAPSHOT,
           write_bytes=True, **columns):
    """An `evidence_assets` row and, unless told otherwise, the relayed bytes behind it."""
    camera = factory.camera(group_id=group_id) if group_id is not None else None
    incident = incident or factory.incident(camera=camera)
    asset = EvidenceAsset(
        incident_id=incident.id,
        camera_id=camera.id if camera else None,
        kind=kind,
        filename=storage_key.rsplit("/", 1)[-1],
        storage_key=storage_key,
        content_type=content_type,
        byte_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        captured_at=dt.datetime.now(dt.UTC),
        **columns,
    )
    factory.session.add(asset)
    factory.session.flush()
    if write_bytes:
        storage.store_bytes(settings, storage_key, data, expected_sha256=asset.sha256)
    return asset, incident, camera


def _audit_rows(session, action: str):
    _reload(session)
    return list(session.scalars(select(AuditLog).where(AuditLog.action == action)).all())


class TestBearerRead:
    def test_an_authenticated_supervisor_gets_the_bytes_and_the_integrity_headers(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()

        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=session.actor.headers
        )
        assert response.status_code == 200
        assert response.content == SNAPSHOT
        assert response.headers["content-type"] == "image/jpeg"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["accept-ranges"] == "bytes"
        assert response.headers["content-disposition"] == "inline"
        assert response.headers["content-length"] == str(asset.byte_size)
        # Nothing in the response tells a bystander where the file lives on this host.
        assert str(cloud_settings.evidence_dir) not in str(response.headers)
        assert asset.storage_key not in str(response.headers)

        rows = _audit_rows(factory.session, "evidence.view")
        assert len(rows) == 1
        assert rows[0].details["via"] == "session"
        assert rows[0].details["partial"] is False
        assert rows[0].object_id == str(asset.id)

    def test_metadata_reports_the_state_without_exposing_a_path(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        body = cloud_app.get(
            f"/api/v1/evidence/{asset.id}", headers=session.actor.headers
        ).json()
        assert body["state"] == "available"
        assert body["sha256"] == asset.sha256
        assert body["incident_id"] == incident.id
        assert set(body) == {
            "id", "kind", "content_type", "byte_size", "sha256", "captured_at",
            "expires_at", "state", "incident_id", "camera_id",
        }
        assert cloud_settings.evidence_dir.as_posix() not in str(body)

    def test_a_viewing_device_can_seek_without_downloading_the_clip(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        url = f"/api/v1/evidence/{asset.id}/content"
        headers = session.actor.headers

        response = cloud_app.get(url, headers={**headers, "range": "bytes=0-3"})
        assert response.status_code == 206
        assert response.content == SNAPSHOT[:4]
        assert response.headers["content-range"] == f"bytes 0-3/{len(SNAPSHOT)}"
        assert response.headers["accept-ranges"] == "bytes"

        suffix = cloud_app.get(url, headers={**headers, "range": "bytes=-4"})
        assert suffix.status_code == 206
        assert suffix.content == SNAPSHOT[-4:]

        tail = cloud_app.get(
            url, headers={**headers, "range": f"bytes={len(SNAPSHOT) - 2}-"}
        )
        assert tail.content == SNAPSHOT[-2:]

        # A seek is audited as partial, because "did this person see the recording?" has a
        # different answer for the first four bytes than for the whole file.
        assert [row.details["partial"] for row in _audit_rows(factory.session, "evidence.view")] == [
            True, True, True
        ]

    def test_an_unsupported_range_is_refused_before_anything_is_read(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        url = f"/api/v1/evidence/{asset.id}/content"

        for header, code in (
            ("bytes=1-2,4-5", "range_invalid"),
            ("bytes=", "range_invalid"),
            ("bytes=-0", "range_invalid"),
            (f"bytes={len(SNAPSHOT) + 50}-", "range_unsatisfiable"),
            ("items=0-1", "range_invalid"),
        ):
            response = cloud_app.get(url, headers={**session.actor.headers, "range": header})
            assert response.status_code == 416, header
            assert response.json()["error"]["code"] == code, header

    def test_bytes_that_have_not_relayed_yet_are_reported_as_still_arriving(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(
            factory, cloud_settings, storage_key="inc-relay/not-yet.jpg", write_bytes=False
        )
        factory.session.commit()
        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=session.actor.headers
        )
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "evidence_unavailable"
        body = cloud_app.get(
            f"/api/v1/evidence/{asset.id}", headers=session.actor.headers
        ).json()
        assert body["state"] == "processing"

    def test_corrupted_bytes_are_refused_rather_than_shown_as_evidence(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        (cloud_settings.evidence_dir / asset.storage_key).write_bytes(
            bytes(item ^ 0xFF for item in SNAPSHOT)
        )

        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=session.actor.headers
        )
        assert response.status_code == 503
        error = response.json()["error"]
        assert error["code"] == "evidence_integrity_failed"
        assert "sha256" not in error["message"]
        assert _audit_rows(factory.session, "evidence.view") == []

    def test_a_past_retention_date_is_a_410(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(
            factory, cloud_settings,
            expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(days=1),
        )
        factory.session.commit()
        for path in (f"/api/v1/evidence/{asset.id}", f"/api/v1/evidence/{asset.id}/content"):
            response = cloud_app.get(path, headers=session.actor.headers)
            assert response.status_code == 410, path
            assert response.json()["error"]["code"] == "evidence_expired"

    def test_deleted_evidence_is_not_confirmed_as_having_ever_existed(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(
            factory, cloud_settings, deleted_at=dt.datetime.now(dt.UTC)
        )
        factory.session.commit()
        for path in (f"/api/v1/evidence/{asset.id}", f"/api/v1/evidence/{asset.id}/content"):
            assert cloud_app.get(path, headers=session.actor.headers).status_code == 404

    def test_a_key_outside_the_evidence_directory_is_never_read(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(
            factory, cloud_settings, storage_key="../../outside-the-root.jpg", write_bytes=False
        )
        factory.session.commit()
        content = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=session.actor.headers
        )
        assert content.status_code == 404
        assert content.json()["error"]["code"] == "evidence_key_invalid"
        # The refusal is indistinguishable from "no such asset", and the response says nothing
        # about how the storage directory is laid out.
        assert "outside-the-root" not in str(content.json())
        metadata = cloud_app.get(f"/api/v1/evidence/{asset.id}", headers=session.actor.headers)
        assert metadata.status_code == 200
        # The row exists and this person may know about it; what it cannot claim is that the bytes
        # are still on their way, because a key this service refuses never delivers anything.
        assert metadata.json()["state"] == "unavailable"

    def test_an_unknown_asset_is_answered_with_the_same_404_as_any_other_missing_one(
        self, signed_in, cloud_app, factory
    ):
        session = signed_in("security_supervisor")
        for path in ("/api/v1/evidence/424242", "/api/v1/evidence/424242/content"):
            assert cloud_app.get(path, headers=session.actor.headers).status_code == 404, path

    def test_a_type_the_cloud_will_not_render_is_never_served_with_its_own_header(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(
            factory, cloud_settings,
            content_type="text/html",
            data=b"<script>document.location</script>",
            storage_key="inc-relay/hostile.html",
        )
        factory.session.commit()
        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=session.actor.headers
        )
        assert response.status_code == 415
        assert response.json()["error"]["code"] == "evidence_type_unsupported"

    def test_reading_evidence_needs_a_credential(self, cloud_app):
        response = cloud_app.get("/api/v1/evidence/1/content")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "authentication_required"

    def test_the_evidence_read_budget_is_per_account(
        self, signed_in, make_cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        client = make_cloud_app(cloud_settings, evidence_attempts_per_minute=3)
        url = f"/api/v1/evidence/{asset.id}/content"
        for _ in range(3):
            assert client.get(url, headers=session.actor.headers).status_code == 200
        response = client.get(url, headers=session.actor.headers)
        assert response.status_code == 429
        assert response.json()["error"]["code"] == "too_many_evidence_reads"


class TestScope:
    def test_an_officer_scoped_to_another_group_is_told_the_asset_does_not_exist(
        self, cloud_app, cloud_settings, factory
    ):
        gate_group = factory.group(code="GRP-GATE")
        yard_group = factory.group(code="GRP-YARD")
        asset, _incident, _camera = _asset(factory, cloud_settings, group_id=yard_group.id)
        inside = factory.user(username="gate.officer", roles=("security_supervisor",),
                              camera_group_id=gate_group.id)
        outside = factory.user(username="yard.officer", roles=("security_supervisor",),
                               camera_group_id=yard_group.id)
        factory.session.commit()

        actor = Personnel(cloud_app)
        assert actor.login(inside.username, TEST_PASSWORD).status_code == 200
        for path in (f"/api/v1/evidence/{asset.id}", f"/api/v1/evidence/{asset.id}/content"):
            response = cloud_app.get(path, headers=actor.headers)
            assert response.status_code == 404, path
            # Not 403: confirming that the file exists is itself a disclosure.
            assert response.json()["error"]["code"] == "not_found"

        other = Personnel(cloud_app, installation_id="33333333-2222-4333-8444-555555555555")
        assert other.login(outside.username, TEST_PASSWORD).status_code == 200
        assert cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=other.headers
        ).status_code == 200

    def test_an_account_without_the_evidence_permission_gets_nothing(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("technical_operator")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}", headers=session.actor.headers
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "forbidden"

    def test_a_temporary_password_is_not_a_way_to_read_evidence(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor", must_change_password=True)
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        response = cloud_app.get(
            f"/api/v1/evidence/{asset.id}/content", headers=session.actor.headers
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "password_change_required"


class TestAssetTokens:
    def test_an_img_element_style_read_works_with_a_token_and_no_header(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        token, expires_at = mint(cloud_settings, asset_id=asset.id, user_id=session.user.id)
        response = cloud_app.get(f"/api/v1/evidence/{asset.id}/content?token={token}")
        assert response.status_code == 200
        assert response.content == SNAPSHOT
        assert expires_at > int(dt.datetime.now(dt.UTC).timestamp())

        rows = _audit_rows(factory.session, "evidence.view")
        assert rows[0].details["via"] == "asset_token"
        assert rows[0].actor_id == session.user.id

    def test_a_token_for_one_asset_cannot_be_traded_for_another(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        first, _i1, _c1 = _asset(factory, cloud_settings, storage_key="inc-relay/first.jpg")
        second, _i2, _c2 = _asset(factory, cloud_settings, storage_key="inc-relay/second.jpg")
        factory.session.commit()
        token, _exp = mint(cloud_settings, asset_id=first.id, user_id=session.user.id)
        response = cloud_app.get(f"/api/v1/evidence/{second.id}/content?token={token}")
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "evidence_token_invalid"

    def test_a_token_stops_working_when_its_holder_loses_the_grant(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        """The proposal's rule that a revocation takes effect now, not when a link expires."""
        gate_group = factory.group(code="GRP-NIGHT")
        yard_group = factory.group(code="GRP-DAY")
        session = signed_in("security_supervisor")
        asset, _incident, _camera = _asset(
            factory, cloud_settings, group_id=yard_group.id
        )
        factory.session.commit()
        token, _exp = mint(cloud_settings, asset_id=asset.id, user_id=session.user.id)
        url = f"/api/v1/evidence/{asset.id}/content?token={token}"
        assert cloud_app.get(url).status_code == 200

        _reload(factory.session)
        assignment = factory.session.scalar(
            select(UserRole).where(UserRole.user_id == session.user.id)
        )
        assignment.camera_group_id = gate_group.id
        factory.session.commit()

        response = cloud_app.get(url)
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "not_found"

    def test_an_expired_or_malformed_token_is_refused_without_detail(
        self, cloud_app, cloud_settings, factory
    ):
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        stale, _exp = mint(cloud_settings, asset_id=asset.id, user_id=1, ttl_seconds=-10)
        response = cloud_app.get(f"/api/v1/evidence/{asset.id}/content?token={stale}")
        assert response.status_code == 410
        assert response.json()["error"]["code"] == "evidence_token_expired"

        for junk in ("garbage", "a" * 80, "  "):
            response = cloud_app.get(f"/api/v1/evidence/{asset.id}/content?token={junk}")
            assert response.status_code == 401, junk
            assert response.json()["error"]["code"] in (
                "evidence_token_invalid",
                "evidence_token_required",
            ), junk

    def test_an_evidence_token_is_not_a_session_token(self, cloud_app, cloud_settings, factory):
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()
        token, _exp = mint(cloud_settings, asset_id=asset.id, user_id=1)
        response = cloud_app.get(
            "/api/v1/auth/me", headers={"authorization": f"Bearer {token}"}
        )
        assert response.status_code == 401
        assert response.json()["error"]["code"] == "invalid_token"

    def test_the_incident_evidence_list_hands_out_one_purpose_links(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        session = signed_in("security_supervisor")
        incident = factory.incident()
        asset, _incident, _camera = _asset(factory, cloud_settings, incident=incident)
        _missing, _i2, _c2 = _asset(
            factory, cloud_settings,
            incident=incident, storage_key="inc-relay/not-here.jpg", write_bytes=False
        )
        factory.session.commit()

        body = cloud_app.get(
            f"/api/v1/incidents/{incident.id}/evidence", headers=session.actor.headers
        ).json()
        assert body["incident_id"] == incident.id
        by_id = {item["id"]: item for item in body["items"]}
        assert by_id[asset.id]["state"] == "available"
        assert by_id[asset.id]["url"].startswith(
            f"{cloud_settings.public_base_url.rstrip('/')}/api/v1/evidence/{asset.id}/content"
            "?token="
        )
        assert by_id[asset.id]["expires_at_token"] is not None
        # Nothing is invented for bytes that have not arrived: the app shows "still arriving".
        assert by_id[_missing.id]["state"] == "processing"
        assert by_id[_missing.id]["url"] is None

        path = by_id[asset.id]["url"].replace(cloud_settings.public_base_url, "")
        assert cloud_app.get(path).status_code == 200


class TestExport:
    def test_export_is_a_separate_permission_and_is_audited_with_the_digest(
        self, signed_in, cloud_app, cloud_settings, factory
    ):
        supervisor = signed_in("security_supervisor")
        operator = signed_in("security_operator")
        asset, _incident, _camera = _asset(factory, cloud_settings)
        factory.session.commit()

        refused = cloud_app.post(
            f"/api/v1/evidence/{asset.id}/export", headers=operator.actor.headers
        )
        assert refused.status_code == 403
        assert refused.json()["error"]["code"] == "forbidden"

        response = cloud_app.post(
            f"/api/v1/evidence/{asset.id}/export", headers=supervisor.actor.headers
        )
        assert response.status_code == 200
        assert response.content == SNAPSHOT
        assert "attachment" in response.headers["content-disposition"]
        assert asset.filename in response.headers["content-disposition"]
        assert response.headers["cache-control"] == "no-store"

        rows = _audit_rows(factory.session, "evidence.export")
        assert len(rows) == 1
        assert rows[0].details["sha256"] == asset.sha256
        assert rows[0].actor_id == supervisor.user.id
