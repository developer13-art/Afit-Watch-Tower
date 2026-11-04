"""Evidence capture, integrity, retention and access scoping (proposal sections 12, 14, 16).

Three defects are pinned here, because each one silently reduced what a reviewer could see:

1. A snapshot written by the analysis pass was never registered in `evidence_assets`, so it had
   no SHA-256 check, no retention expiry, no audited download, and did not appear on the incident
   a reviewer escalated the candidate into.
2. Two alerts inside the same second produced the same snapshot filename, so the second overwrote
   the first and the first event's recorded digest pointed at bytes it never wrote.
3. The download route scoped the incident only, never the camera group of the asset's own camera.
"""

from __future__ import annotations

import datetime as dt
import hashlib
from pathlib import Path

import pytest
from sqlalchemy import select

from watchtower.analysis.events import EvidenceRef, LocalEvidenceWriter
from watchtower.models import AuditLog, DetectionEvent, EvidenceAsset
from watchtower.services.evidence import EvidenceError, IntegrityMismatch
from watchtower.services.evidence import EvidenceStore

SNAPSHOT = b"\xff\xd8\xff\xe0synthetic-jpeg-body\xff\xd9"
SECOND_SNAPSHOT = b"\xff\xd8\xff\xe0a-different-frame\xff\xd9"
OCCURRED_AT = dt.datetime(2026, 3, 4, 9, 8, 7, tzinfo=dt.UTC)


def _stamp(value: dt.datetime) -> dt.datetime:
    """SQLite hands naive datetimes back, the API accepts aware ones; compare the wall clock."""
    return value.replace(tzinfo=None) if value.tzinfo else value


def assets_in(db) -> list[EvidenceAsset]:
    db.expire_all()
    return db.scalars(select(EvidenceAsset).order_by(EvidenceAsset.id)).all()


def store_for(settings, db) -> EvidenceStore:
    return EvidenceStore(settings, db)


def written(db, settings, camera, *, data=SNAPSHOT, **kwargs):
    result = store_for(settings, db).write_snapshot(camera.id, data, **kwargs)
    db.commit()
    return result


def audit_rows(db) -> list[AuditLog]:
    db.commit()
    return db.scalars(select(AuditLog).order_by(AuditLog.id)).all()


# --------------------------------------------------------------------------- #
# Integrity: the digest is recorded at write time and verified on read
# --------------------------------------------------------------------------- #


def test_a_written_snapshot_carries_its_digest_size_and_expiry(db, factory, settings):
    camera = factory.camera()
    result = written(db, settings, camera)

    asset = result.asset
    assert asset.sha256 == hashlib.sha256(SNAPSHOT).hexdigest()
    assert asset.byte_size == len(SNAPSHOT)
    assert asset.content_type == "image/jpeg"
    assert asset.kind == "snapshot"
    assert asset.expires_at == asset.captured_at + dt.timedelta(days=settings.evidence_retention_days)
    assert result.path.read_bytes() == SNAPSHOT
    assert store_for(settings, db).read(asset) == SNAPSHOT


def test_a_tampered_file_is_reported_instead_of_being_served(db, factory, settings):
    camera = factory.camera()
    asset = written(db, settings, camera).asset

    (Path(settings.evidence_dir) / asset.storage_key).write_bytes(SECOND_SNAPSHOT)

    with pytest.raises(IntegrityMismatch):
        store_for(settings, db).read(asset)


def test_a_missing_file_is_reported_as_a_failure_not_empty_bytes(db, factory, settings):
    camera = factory.camera()
    asset = written(db, settings, camera).asset

    (Path(settings.evidence_dir) / asset.storage_key).unlink()

    with pytest.raises(EvidenceError):
        store_for(settings, db).read(asset)


def test_an_empty_asset_is_refused_before_it_reaches_storage(db, factory, settings):
    camera = factory.camera()

    with pytest.raises(EvidenceError):
        store_for(settings, db).write_snapshot(camera.id, b"")
    db.commit()
    assert assets_in(db) == []


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #


def test_a_crafted_relative_key_cannot_escape_the_evidence_root(db, factory, settings):
    camera = factory.camera()
    asset = written(db, settings, camera).asset

    outside = Path(settings.evidence_dir).parent / "outside.jpg"
    outside.write_bytes(SNAPSHOT)
    asset.storage_key = "../outside.jpg"
    db.commit()

    with pytest.raises(EvidenceError):
        store_for(settings, db).read(asset)


def test_an_absolute_key_is_rejected_too(db, factory, settings):
    camera = factory.camera()
    asset = written(db, settings, camera).asset
    asset.storage_key = str(Path(settings.evidence_dir).parent / "outside.jpg")
    db.commit()

    with pytest.raises(EvidenceError):
        store_for(settings, db).read(asset)


# --------------------------------------------------------------------------- #
# Defect 1: the analysis pass wrote evidence the database never saw
# --------------------------------------------------------------------------- #


def ref_for(writer: LocalEvidenceWriter, *, code="CAM-0001", at=None, jpeg=SNAPSHOT) -> EvidenceRef:
    return writer.write_snapshot(
        camera_code=code,
        category="restricted_zone_entry",
        occurred_at=at or dt.datetime.now(dt.UTC),
        jpeg=jpeg,
    )


def candidate_event(db, camera, *, metadata=None):
    event = DetectionEvent(
        camera_id=camera.id,
        category="restricted_zone_entry",
        confidence=0.81,
        occurred_at=OCCURRED_AT,
        event_metadata={"zone_id": "gate", **(metadata or {})},
    )
    db.add(event)
    db.commit()
    return event


def test_adopting_a_candidate_snapshot_gives_it_a_digest_and_an_expiry(
    db, factory, settings, tmp_path
):
    camera = factory.camera()
    snapshot = ref_for(LocalEvidenceWriter(settings.evidence_dir)).as_metadata()
    event = candidate_event(db, camera, metadata={"snapshot": snapshot})

    asset = store_for(settings, db).adopt(
        camera_id=camera.id,
        detection_event_id=event.id,
        snapshot=event.event_metadata["snapshot"],
        captured_at=event.occurred_at,
    )
    db.commit()

    assert asset is not None
    assert asset.detection_event_id == event.id
    assert asset.storage_key == snapshot["storage_key"]
    assert asset.sha256 == snapshot["sha256"] == hashlib.sha256(SNAPSHOT).hexdigest()
    assert asset.byte_size == len(SNAPSHOT)
    assert _stamp(asset.captured_at) == _stamp(OCCURRED_AT)
    assert _stamp(asset.expires_at) - _stamp(asset.captured_at) == dt.timedelta(
        days=settings.evidence_retention_days
    )
    # The adopted asset is readable through the governed path, which is the point of adopting it.
    assert store_for(settings, db).read(asset) == SNAPSHOT


def test_adopting_twice_registers_one_asset_not_two(db, factory, settings):
    camera = factory.camera()
    event = candidate_event(db, camera)
    snapshot = ref_for(LocalEvidenceWriter(settings.evidence_dir)).as_metadata()

    first = store_for(settings, db).adopt(
        camera_id=camera.id, detection_event_id=event.id, snapshot=snapshot,
        captured_at=event.occurred_at,
    )
    db.commit()
    second = store_for(settings, db).adopt(
        camera_id=camera.id, detection_event_id=event.id, snapshot=snapshot,
        captured_at=event.occurred_at,
    )
    db.commit()

    assert first is not None and second.id == first.id
    assert len(assets_in(db)) == 1


def test_adopting_a_snapshot_that_is_not_on_disk_fails_loudly(db, factory, settings):
    camera = factory.camera()
    ghost = {
        "storage_key": "2026/03/04/ghost.jpg",
        "sha256": hashlib.sha256(SNAPSHOT).hexdigest(),
        "byte_size": len(SNAPSHOT),
        "content_type": "image/jpeg",
    }

    with pytest.raises(EvidenceError):
        store_for(settings, db).adopt(
            camera_id=camera.id, detection_event_id=1, snapshot=ghost,
            captured_at=dt.datetime.now(dt.UTC),
        )


def test_a_reference_without_a_digest_is_not_registered(db, factory, settings):
    camera = factory.camera()

    assert store_for(settings, db).adopt(
        camera_id=camera.id, detection_event_id=1,
        snapshot={"storage_key": "2026/03/04/x.jpg"},
        captured_at=dt.datetime.now(dt.UTC),
    ) is None
    db.commit()
    assert assets_in(db) == []


# --------------------------------------------------------------------------- #
# Retention
# --------------------------------------------------------------------------- #


def test_expired_evidence_is_collected_and_a_deleted_asset_is_unreadable(db, factory, settings):
    camera = factory.camera()
    stale = written(
        db, settings, camera,
        captured_at=dt.datetime(2024, 1, 1, tzinfo=dt.UTC), retention_days=1,
    ).asset
    fresh = written(db, settings, camera).asset
    stale_key = stale.storage_key

    purged = store_for(settings, db).purge_expired(now=dt.datetime(2024, 6, 1, tzinfo=dt.UTC))
    db.commit()

    assert purged == 1
    assert stale.deleted_at is not None
    assert not (Path(settings.evidence_dir) / stale_key).exists()
    with pytest.raises(EvidenceError):
        store_for(settings, db).read(stale)
    assert store_for(settings, db).read(fresh) == SNAPSHOT


def test_purging_twice_does_not_double_count(db, factory, settings):
    written(db, settings, factory.camera(),
            captured_at=dt.datetime(2024, 1, 1, tzinfo=dt.UTC), retention_days=1)
    now = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)

    assert store_for(settings, db).purge_expired(now=now) == 1
    db.commit()
    assert store_for(settings, db).purge_expired(now=now) == 0


# --------------------------------------------------------------------------- #
# Defect 1, second half: escalation must not strand the snapshot
# --------------------------------------------------------------------------- #


def test_escalating_a_candidate_links_its_snapshot_to_the_incident(db, factory, settings):
    camera = factory.camera()
    event = candidate_event(db, camera)
    snapshot = ref_for(LocalEvidenceWriter(settings.evidence_dir)).as_metadata()
    asset = store_for(settings, db).adopt(
        camera_id=camera.id, detection_event_id=event.id, snapshot=snapshot,
        captured_at=event.occurred_at,
    )
    db.commit()
    incident = factory.incident(camera)

    evidence = store_for(settings, db)
    assert evidence.link_to_incident(detection_event_id=event.id, incident_id=incident.id) == 1
    db.commit()

    assert asset.incident_id == incident.id
    assert evidence.assets_for_incident(incident.id) == [asset]
    # A second escalation of the same candidate must not re-tag it.
    assert store_for(settings, db).link_to_incident(
        detection_event_id=event.id, incident_id=incident.id
    ) == 0


def test_a_deleted_asset_stops_appearing_on_its_incident(db, factory, settings):
    camera = factory.camera()
    incident = factory.incident(camera)
    written(db, settings, camera, incident_id=incident.id)
    evidence = store_for(settings, db)
    assert len(evidence.assets_for_incident(incident.id)) == 1

    evidence.delete(assets_in(db)[0], reason="test")
    db.commit()

    assert store_for(settings, db).assets_for_incident(incident.id) == []


# --------------------------------------------------------------------------- #
# Defect 2: two alerts in one second
# --------------------------------------------------------------------------- #


def test_two_snapshots_in_the_same_second_keep_their_own_bytes(tmp_path):
    writer = LocalEvidenceWriter(tmp_path / "evidence")
    at = dt.datetime(2026, 3, 4, 9, 0, 0, tzinfo=dt.UTC)

    first = ref_for(writer, at=at, jpeg=SNAPSHOT)
    second = ref_for(writer, at=at, jpeg=SECOND_SNAPSHOT)

    assert first.storage_key != second.storage_key
    root = tmp_path / "evidence"
    assert (root / first.storage_key).read_bytes() == SNAPSHOT
    assert (root / second.storage_key).read_bytes() == SECOND_SNAPSHOT
    assert first.sha256 == hashlib.sha256(SNAPSHOT).hexdigest()
    assert second.sha256 == hashlib.sha256(SECOND_SNAPSHOT).hexdigest()


def test_a_non_jpeg_payload_is_never_written_as_evidence(tmp_path):
    writer = LocalEvidenceWriter(tmp_path / "evidence")

    assert writer.write_snapshot(
        camera_code="CAM-0001", category="restricted_zone_entry",
        occurred_at=dt.datetime.now(dt.UTC), jpeg=b"not-a-jpeg",
    ) is None
    assert list((tmp_path / "evidence").rglob("*")) == []


def test_an_unsafe_camera_code_cannot_escape_the_snapshot_key(tmp_path):
    writer = LocalEvidenceWriter(tmp_path / "evidence")
    root = tmp_path / "evidence"

    ref = writer.write_snapshot(
        camera_code="../../etc/passwd", category="restricted_zone_entry",
        occurred_at=dt.datetime.now(dt.UTC), jpeg=SNAPSHOT,
    )

    assert ref is not None
    assert "/" not in ref.storage_key.rsplit("/", 1)[-1]
    written_path = (root / ref.storage_key).resolve()
    assert root.resolve() in written_path.parents
    assert written_path.exists()


# --------------------------------------------------------------------------- #
# Defect 3 and permissions, at the HTTP boundary
# --------------------------------------------------------------------------- #


@pytest.fixture
def evidence_factory(db, factory, settings):
    """A camera (optionally in a group) with one incident and one readable asset."""

    def _make(*, group_id: int | None = None, username: str | None = None) -> dict:
        camera = factory.camera(group_id=group_id)
        incident = factory.incident(camera)
        result = written(db, settings, camera, incident_id=incident.id)
        return {
            "camera": camera,
            "incident": incident,
            "asset_id": result.asset.id,
            "asset_path": result.path,
        }

    return _make


class TestEvidenceHttpAccess:
    def test_anonymous_callers_get_no_bytes(self, client, evidence_factory):
        asset = evidence_factory()["asset_id"]

        assert client.get(f"/api/evidence/{asset}").status_code == 401

    def test_a_supervisor_reads_evidence_and_the_read_is_audited(
        self, actor, db, evidence_factory
    ):
        asset = evidence_factory()["asset_id"]
        supervisor = actor("security_supervisor", username="reading.supervisor")

        response = supervisor.client.get(f"/api/evidence/{asset}")

        assert response.status_code == 200
        assert response.content == SNAPSHOT
        assert response.headers["content-disposition"].startswith("inline")
        assert response.headers["cache-control"] == "no-store"
        assert "evidence.view" in [row.action for row in audit_rows(db)]

    def test_export_needs_a_permission_view_does_not(self, actor, db, evidence_factory):
        asset = evidence_factory()["asset_id"]
        operator = actor("security_operator", username="operator.export")
        supervisor = actor("security_supervisor", username="supervisor.export")

        assert operator.client.get(f"/api/evidence/{asset}").status_code == 200
        denied = operator.client.get(f"/api/evidence/{asset}", params={"export": "true"})
        assert denied.status_code == 403
        assert "evidence.export" in denied.json()["detail"]["message"]

        granted = supervisor.client.get(f"/api/evidence/{asset}", params={"export": "true"})
        assert granted.status_code == 200
        assert granted.headers["content-disposition"].startswith("attachment")
        assert "evidence.export" in [row.action for row in audit_rows(db)]

    def test_an_asset_whose_camera_is_outside_the_scope_is_refused(
        self, actor, db, factory, evidence_factory
    ):
        north = factory.group(code="GRP-NORTH")
        south = factory.group(code="GRP-SOUTH")
        db.commit()
        inside = evidence_factory(group_id=north.id)
        outside = evidence_factory(group_id=south.id)
        reviewer = actor("security_supervisor", username="north.only", group_id=north.id)

        assert reviewer.client.get(f"/api/evidence/{inside['asset_id']}").status_code == 200
        refused = reviewer.client.get(f"/api/evidence/{outside['asset_id']}")
        assert refused.status_code == 403
        assert refused.json()["detail"]["code"] == "forbidden"
        assert refused.content != SNAPSHOT

    def test_an_asset_from_an_unscoped_camera_is_invisible_to_a_scoped_reviewer(
        self, actor, db, factory, evidence_factory
    ):
        scoped_group = factory.group(code="GRP-SCOPED")
        db.commit()
        bundle = evidence_factory(group_id=None)
        reviewer = actor("security_supervisor", username="scoped.only", group_id=scoped_group.id)

        assert reviewer.client.get(f"/api/evidence/{bundle['asset_id']}").status_code == 403

    def test_a_role_without_evidence_permissions_is_refused(self, actor, evidence_factory):
        asset = evidence_factory()["asset_id"]
        technician = actor("technical_operator", username="tech.export")

        response = technician.client.get(f"/api/evidence/{asset}")

        assert response.status_code == 403
        assert response.content != SNAPSHOT

    def test_a_deleted_asset_returns_404_not_its_bytes(self, actor, db, evidence_factory, settings):
        bundle = evidence_factory()
        supervisor = actor("security_supervisor", username="deleting.supervisor")
        store_for(settings, db).delete(
            db.get(EvidenceAsset, bundle["asset_id"]), reason="test"
        )
        db.commit()

        assert supervisor.client.get(f"/api/evidence/{bundle['asset_id']}").status_code == 404

    def test_a_tampered_asset_fails_closed_and_the_failure_is_audited(
        self, actor, db, evidence_factory, settings
    ):
        bundle = evidence_factory()
        supervisor = actor("security_supervisor", username="tampering.supervisor")
        bundle["asset_path"].write_bytes(SECOND_SNAPSHOT)
        db.commit()

        response = supervisor.client.get(f"/api/evidence/{bundle['asset_id']}")

        assert response.status_code == 500
        assert response.json()["detail"]["code"] == "evidence_unreadable"
        assert response.content != SECOND_SNAPSHOT
        relevant = [
            row
            for row in audit_rows(db)
            if row.action == "evidence.view" and row.object_id == str(bundle["asset_id"])
        ]
        assert [row.outcome for row in relevant] == ["failure"]

    def test_an_unknown_asset_is_404_for_everyone(self, actor, evidence_factory):
        supervisor = actor("security_supervisor", username="searching.supervisor")

        assert supervisor.client.get("/api/evidence/424242").status_code == 404

    def test_retention_purge_is_a_write_and_not_a_get(self, admin, evidence_factory):
        evidence_factory()

        assert admin.client.get("/api/admin/retention/purge").status_code == 405

    def test_retention_purge_refuses_an_unauthenticated_caller(self, client):
        assert client.post("/api/admin/retention/purge").status_code in (401, 403)

    def test_retention_purge_removes_expired_rows_and_the_download_then_404s(
        self, admin, db, evidence_factory, settings
    ):
        bundle = evidence_factory()
        asset = db.get(EvidenceAsset, bundle["asset_id"])
        asset.captured_at = dt.datetime(2020, 1, 1, tzinfo=dt.UTC)
        asset.expires_at = dt.datetime(2020, 1, 2, tzinfo=dt.UTC)
        db.commit()

        response = admin.client.post("/api/admin/retention/purge")

        assert response.status_code == 200
        assert response.json()["evidence_assets_removed"] == 1
        assert admin.client.get(f"/api/evidence/{asset.id}").status_code == 404

    def test_an_escalated_candidate_shows_its_snapshot_on_the_incident(
        self, actor, db, factory, settings
    ):
        camera = factory.camera()
        event = candidate_event(db, camera)
        snapshot = ref_for(LocalEvidenceWriter(settings.evidence_dir), code=camera.code).as_metadata()
        store_for(settings, db).adopt(
            camera_id=camera.id, detection_event_id=event.id, snapshot=snapshot,
            captured_at=event.occurred_at,
        )
        db.commit()
        supervisor = actor("security_supervisor", username="escalating.supervisor")

        response = supervisor.client.post(
            f"/api/events/{event.id}/review",
            json={"decision": "escalate", "note": "Confirmed on the gate feed."},
        )

        assert response.status_code == 200, response.text
        incident = response.json()["incident"]
        assert [asset["sha256"] for asset in incident["evidence"]] == [snapshot["sha256"]]
        detail = supervisor.client.get(f"/api/incidents/{incident['id']}")
        assert len(detail.json()["incident"]["evidence"]) == 1
