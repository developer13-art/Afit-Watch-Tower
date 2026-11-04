"""Cloud-side evidence storage.

The monitoring host owns `evidence_assets`; this module only holds the *relayed copy* of the
bytes, because the phone cannot reach the monitoring PC and must not be able to. Whether a given
asset's bytes have arrived is a fact the cloud reports honestly through
`evidence_relay_states.state` - `pending_upload` renders as "evidence still arriving" in the app
rather than as a broken image or an empty pane.

Every path is confined to `CLOUD_EVIDENCE_DIR`. The storage key originates on another machine,
so a traversal attempt (`../../etc/passwd`), an absolute path, or a key that resolves outside the
directory is refused before any filesystem call is made.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
from pathlib import Path

from ..models import EvidenceAsset
from .config import CloudSettings
from .errors import CloudError

LOGGER = logging.getLogger("watchtower.cloud.storage")

_SAFE_KINDS = frozenset({"snapshot", "clip", "frame", "upload"})
# Only what the product captures. An arbitrary `content_type` arriving from another host is
# input, not a declaration: the response header would otherwise be the browser's instruction.
_ALLOWED_CONTENT_TYPES = frozenset(
    {
        "image/jpeg",
        "image/png",
        "video/mp4",
        "application/octet-stream",
    }
)


def _confine(settings: CloudSettings, storage_key: str) -> Path:
    root = settings.evidence_dir.resolve()
    key = (storage_key or "").strip()
    if not key:
        raise CloudError("evidence_key_invalid", "This evidence reference is not usable.", status_code=404)
    if key.startswith("/") or key.startswith("\\") or ".." in key.replace("\\", "/").split("/"):
        raise CloudError("evidence_key_invalid", "This evidence reference is not usable.", status_code=404)
    candidate = (root / key.replace("\\", "/")).resolve()
    if root not in candidate.parents and candidate != root:
        # The answer is the same 404 either way: telling a caller that the path was *rejected*
        # as unsafe would confirm how the storage is laid out.
        raise CloudError("evidence_key_invalid", "This evidence reference is not usable.", status_code=404)
    return candidate


def path_for(settings: CloudSettings, storage_key: str) -> Path:
    return _confine(settings, storage_key)


def store_bytes(
    settings: CloudSettings,
    storage_key: str,
    data: bytes,
    *,
    expected_sha256: str | None = None,
) -> Path:
    target = _confine(settings, storage_key)
    if len(data) > settings.max_evidence_bytes:
        raise CloudError(
            "payload_too_large",
            f"A single evidence asset is limited to "
            f"{settings.max_evidence_bytes // (1024 * 1024)} MiB.",
            status_code=413,
        )
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(target.suffix + ".part")
    temporary.write_bytes(data)
    # The digest is checked before the file becomes visible: a relay that corrupted the bytes,
    # or delivered the wrong ones under this key, must not be served to a phone as evidence.
    digest = hashlib.sha256(data).hexdigest()
    if expected_sha256 is not None and digest != expected_sha256:
        temporary.unlink(missing_ok=True)
        raise CloudError(
            "evidence_digest_mismatch",
            "The bytes received do not match the digest the sender declared.",
            status_code=422,
        )
    temporary.replace(target)
    return target


def read_bytes(settings: CloudSettings, storage_key: str) -> bytes | None:
    target = _confine(settings, storage_key)
    if not target.is_file():
        return None
    return target.read_bytes()


def read_range(settings: CloudSettings, storage_key: str, start: int, length: int) -> bytes:
    """`length` bytes from `start`, or fewer if the file is shorter than asked.

    A range read rather than a whole-file read: a phone seeking through a clip asks for one slice,
    and loading the entire file to answer it would make the cost of a seek proportional to the
    recording.
    """
    target = _confine(settings, storage_key)
    if not target.is_file() or length <= 0:
        return b""
    with target.open("rb") as handle:
        handle.seek(max(start, 0))
        return handle.read(length)


def sha256_of(settings: CloudSettings, storage_key: str) -> str | None:
    target = _confine(settings, storage_key)
    if not target.is_file():
        return None
    digest = hashlib.sha256()
    with target.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def size_of(settings: CloudSettings, storage_key: str) -> int | None:
    target = _confine(settings, storage_key)
    return target.stat().st_size if target.is_file() else None


def asset_state(settings: CloudSettings, asset: EvidenceAsset) -> str:
    """`available | processing | expired | deleted | unavailable` for the contract's response."""
    if asset.deleted_at is not None:
        return "deleted"
    if asset.expires_at is not None:
        expires = asset.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.UTC)
        if expires <= dt.datetime.now(dt.UTC):
            return "expired"
    # A key the confinement rules refuse is not "still arriving": the bytes behind it will never
    # be served, and an app told `processing` would refresh forever after something that cannot
    # happen. The reason is logged, not returned - the response must not describe how the storage
    # directory is laid out.
    try:
        target = _confine(settings, asset.storage_key)
    except CloudError:
        LOGGER.warning("asset %s has a storage key this service will not read", asset.id)
        return "unavailable"
    if not target.is_file():
        return "processing"
    return "available"


def content_type_allowed(asset: EvidenceAsset) -> bool:
    return asset.kind in _SAFE_KINDS and asset.content_type in _ALLOWED_CONTENT_TYPES
