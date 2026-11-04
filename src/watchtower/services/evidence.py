"""Evidence storage with integrity and retention (proposal sections 12 and 16).

Snapshots and clips live on the filesystem, never in database rows. The database keeps the
storage key, size, SHA-256 and an expiry derived from the approved retention policy, so a
tampered file is detectable on read and an expired asset is collectable. Every access,
export and deletion is audited by the calling service.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import EvidenceAsset


class EvidenceError(RuntimeError):
    pass


class IntegrityMismatch(EvidenceError):
    pass


@dataclass(slots=True)
class WrittenEvidence:
    asset: EvidenceAsset
    path: Path


def _as_utc(value: dt.datetime | None) -> dt.datetime | None:
    """A naive timestamp is UTC by this project's convention; SQLite drops the offset."""
    if value is None:
        return None
    return value.replace(tzinfo=dt.UTC) if value.tzinfo is None else value


class EvidenceStore:
    def __init__(self, settings: Settings, session: Session) -> None:
        self._settings = settings
        self._session = session
        self._root = Path(settings.evidence_dir)
        self._root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, storage_key: str) -> Path:
        # storage_key is generated here, but re-deriving the path defensively keeps a
        # hand-edited row from escaping the evidence root via path traversal.
        candidate = (self._root / storage_key).resolve()
        root = self._root.resolve()
        if root not in candidate.parents and candidate != root:
            raise EvidenceError("evidence path escapes the configured storage root")
        return candidate

    def write_snapshot(
        self,
        camera_id: uuid.UUID | str,
        data: bytes,
        *,
        kind: str = "snapshot",
        incident_id: int | None = None,
        detection_event_id: int | None = None,
        content_type: str = "image/jpeg",
        captured_at: dt.datetime | None = None,
        retention_days: int | None = None,
    ) -> WrittenEvidence:
        if not data:
            raise EvidenceError("refusing to store an empty evidence asset")
        captured_at = captured_at or dt.datetime.now(dt.UTC)
        days = (
            retention_days
            if retention_days is not None
            else self._settings.evidence_retention_days
        )
        storage_key = f"{captured_at:%Y/%m/%d}/{uuid.uuid4().hex}.jpg"
        path = self._path_for(storage_key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

        asset = EvidenceAsset(
            incident_id=incident_id,
            camera_id=uuid.UUID(str(camera_id)),
            detection_event_id=detection_event_id,
            kind=kind,
            filename=path.name,
            storage_key=storage_key,
            content_type=content_type,
            byte_size=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            captured_at=captured_at,
            expires_at=captured_at + dt.timedelta(days=days),
        )
        self._session.add(asset)
        self._session.flush()
        return WrittenEvidence(asset=asset, path=path)

    def adopt(
        self,
        *,
        camera_id: uuid.UUID | str,
        detection_event_id: int,
        snapshot: Mapping[str, Any],
        captured_at: dt.datetime,
    ) -> EvidenceAsset | None:
        """Register a snapshot the analysis pass already wrote as a governed evidence asset.

        The bytes are on disk under the same root this store uses; what the database row adds is
        the integrity digest, the retention expiry and the audited access path (section 12).
        """
        storage_key = str(snapshot.get("storage_key") or "")
        sha256 = str(snapshot.get("sha256") or "")
        if not storage_key or not sha256:
            return None
        existing = self._session.scalar(
            select(EvidenceAsset).where(EvidenceAsset.storage_key == storage_key)
        )
        if existing is not None:
            return existing
        path = self._path_for(storage_key)
        if not path.exists():
            raise EvidenceError("the candidate snapshot is missing from storage")
        captured_at = _as_utc(captured_at) or dt.datetime.now(dt.UTC)
        asset = EvidenceAsset(
            camera_id=uuid.UUID(str(camera_id)),
            detection_event_id=detection_event_id,
            kind="snapshot",
            filename=path.name,
            storage_key=storage_key,
            content_type=str(snapshot.get("content_type") or "image/jpeg"),
            byte_size=int(snapshot.get("byte_size") or path.stat().st_size),
            sha256=sha256,
            captured_at=captured_at,
            expires_at=captured_at + dt.timedelta(days=self._settings.evidence_retention_days),
        )
        self._session.add(asset)
        self._session.flush()
        return asset

    def link_to_incident(self, *, detection_event_id: int, incident_id: int) -> int:
        """Attach a candidate's snapshots to the incident it was escalated into."""
        assets = self._session.scalars(
            select(EvidenceAsset).where(
                EvidenceAsset.detection_event_id == detection_event_id,
                EvidenceAsset.incident_id.is_(None),
            )
        ).all()
        for asset in assets:
            asset.incident_id = incident_id
        self._session.flush()
        return len(assets)

    def read(self, asset: EvidenceAsset) -> bytes:
        """Read and verify integrity; a mismatch is surfaced, not silently repaired."""
        path = self._path_for(asset.storage_key)
        if asset.deleted_at is not None:
            raise EvidenceError("this evidence asset has been deleted")
        if not path.exists():
            raise EvidenceError("the evidence file is missing from storage")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != asset.sha256:
            raise IntegrityMismatch(
                f"evidence {asset.id} does not match its recorded SHA-256 digest"
            )
        return data

    def delete(self, asset: EvidenceAsset, *, reason: str) -> None:
        path = self._path_for(asset.storage_key)
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            raise EvidenceError(f"could not remove the evidence file: {exc}") from exc
        asset.deleted_at = dt.datetime.now(dt.UTC)
        asset.storage_key = f"deleted/{asset.storage_key}"
        self._session.flush()

    def purge_expired(self, *, now: dt.datetime | None = None) -> int:
        """Apply the retention policy (section 16: defined retention and deletion)."""
        now = now or dt.datetime.now(dt.UTC)
        expired = self._session.scalars(
            select(EvidenceAsset).where(
                EvidenceAsset.expires_at.is_not(None),
                EvidenceAsset.expires_at <= now,
                EvidenceAsset.deleted_at.is_(None),
            )
        ).all()
        for asset in expired:
            try:
                self.delete(asset, reason="retention_expired")
            except EvidenceError:
                # The file is already gone; the record still has to retire.
                asset.deleted_at = now
                asset.storage_key = f"deleted/{asset.storage_key}"
        self._session.flush()
        return len(expired)

    def assets_for_incident(self, incident_id: int) -> list[EvidenceAsset]:
        return self._session.scalars(
            select(EvidenceAsset)
            .where(EvidenceAsset.incident_id == incident_id, EvidenceAsset.deleted_at.is_(None))
            .order_by(EvidenceAsset.captured_at)
        ).all()
