"""Evidence retrieval (contract sections 7.2 and 13).

Two ways to be authorised, one set of checks. A short-lived asset token rides in the query string
so a plain `<img>` or `<video>` element can fetch the bytes; a signed-in session can call the same
endpoint with its bearer token. Either way the asset must exist, not be deleted or past retention,
belong to a camera inside the reader's group, and the reader must still hold `evidence.view`.

The bytes come from `CLOUD_EVIDENCE_DIR` and nowhere else. If the monitoring host has not relayed
them, the answer is `evidence_unavailable` and the app says "still arriving" - which is the truth -
rather than showing a broken image or redirecting to a private camera a phone must never address.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from dataclasses import dataclass

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from .. import storage
from ..config import CloudSettings
from ..deps import (
    Caller,
    current_caller,
    get_db,
    get_settings,
    require_password_changed,
    require_permission,
)
from ..errors import CloudError
from ..evidence_tokens import redeem
from ...models import Camera, EvidenceAsset, User
from ...security.audit import record as audit_record
from ...security.rbac import can_view_camera, resolve_principal

LOGGER = logging.getLogger("watchtower.cloud.evidence")

router = APIRouter(prefix="/evidence", tags=["evidence"])

_RANGE_RE = re.compile(r"^bytes=(\d*)-(\d*)$")


@dataclass(slots=True)
class Reader:
    """Who is reading this asset, and how they proved it."""

    user_id: int
    via_token: bool
    source_ip: str | None


def _reader_from_token(
    session: Session, settings: CloudSettings, token: str, asset_id: int, request: Request
) -> Reader:
    grant = redeem(settings, token)
    if grant.asset_id != asset_id:
        # A well-formed token for a different asset. Refused without saying which half matched.
        raise CloudError(
            "evidence_token_invalid", "This link is not valid for that asset.", status_code=401
        )
    user = session.get(User, grant.user_id)
    if user is None or not user.is_active:
        raise CloudError("evidence_token_invalid", "This link is no longer valid.", status_code=401)
    principal = resolve_principal(session, user)
    if not principal.allows("evidence.view"):
        raise CloudError("forbidden", "This account may not view evidence.", status_code=403)
    return Reader(
        grant.user_id,
        via_token=True,
        source_ip=request.client.host if request.client else None,
    )


def _reader_from_bearer(request: Request, session: Session) -> Reader:
    # Called directly rather than as a dependency because the asset-token branch above already
    # answered this request; FastAPI's `Depends` cannot choose between two authorisation styles.
    caller = require_password_changed(
        current_caller(request, session, request.app.state.container)
    )
    if not caller.principal.allows("evidence.view"):
        raise CloudError("forbidden", "This account may not view evidence.", status_code=403)
    return Reader(caller.user_id, via_token=False, source_ip=caller.source_ip)


def _reader(request: Request, session: Session, settings: CloudSettings, asset_id: int) -> Reader:
    # The branch turns on whether a token was *offered*, not on whether it parsed. A request that
    # arrives with an empty or blank `token=` is asking the asset-token question, and the answer it
    # needs is "that link is not valid" - not a lesson in bearer syntax it never asked for.
    if "token" in request.query_params:
        return _reader_from_token(
            session, settings, request.query_params["token"], asset_id, request
        )
    if not request.headers.get("authorization"):
        raise CloudError(
            "authentication_required",
            "Present an asset token or a bearer access token.",
            status_code=401,
        )
    return _reader_from_bearer(request, session)


def _load_asset(session: Session, settings: CloudSettings, asset_id: int, reader: Reader):
    asset = session.get(EvidenceAsset, asset_id)
    if asset is None or asset.deleted_at is not None:
        raise CloudError("not_found", "No such evidence for this account.", status_code=404)
    if asset.expires_at is not None:
        expires = asset.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.UTC)
        if expires <= dt.datetime.now(dt.UTC):
            raise CloudError(
                "evidence_expired", "This evidence is past its retention date.", status_code=410
            )
    camera = session.get(Camera, asset.camera_id) if asset.camera_id else None
    if camera is not None:
        user = session.get(User, reader.user_id)
        if user is None or not can_view_camera(
            resolve_principal(session, user), "evidence.view", camera
        ):
            raise CloudError("not_found", "No such evidence for this account.", status_code=404)
    if not storage.content_type_allowed(asset):
        LOGGER.warning("asset %s presents an unpermitted type %r", asset_id, asset.content_type)
        raise CloudError(
            "evidence_type_unsupported", "This evidence cannot be displayed.", status_code=415
        )
    return asset


def _range(header: str | None, total: int) -> tuple[int, int]:
    if not header:
        return 0, max(total - 1, 0)
    match = _RANGE_RE.match(header.strip())
    if match is None:
        raise CloudError(
            "range_invalid", "Only a single byte range like `bytes=start-end` is supported.",
            status_code=416,
        )
    if total <= 0:
        raise CloudError("range_unsatisfiable", "This asset has no bytes.", status_code=416)
    raw_start, raw_end = match.group(1), match.group(2)
    if raw_start == "" and raw_end == "":
        raise CloudError("range_invalid", "The byte range is empty.", status_code=416)
    if raw_start == "":
        # Suffix form `bytes=-500`: the last 500 bytes, which is what a seeking player asks for.
        suffix = int(raw_end)
        if suffix <= 0:
            raise CloudError("range_invalid", "The byte range is not satisfiable.", status_code=416)
        return max(total - suffix, 0), total - 1
    start = int(raw_start)
    if start >= total:
        raise CloudError(
            "range_unsatisfiable", "The range starts past the end of the file.", status_code=416
        )
    end = int(raw_end) if raw_end else total - 1
    return start, min(end, total - 1)


@router.get("/{asset_id}/content")
def read_content(
    asset_id: int,
    request: Request,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
):
    """The bytes, with range support, and `evidence.view` audited on every successful read."""
    from ..ratelimit import enforce

    reader = _reader(request, session, settings, asset_id)
    asset = _load_asset(session, settings, asset_id, reader)
    enforce(
        request.app.state.container.limiter,
        "evidence",
        str(reader.user_id),
        limit=settings.evidence_attempts_per_minute,
        window_seconds=60,
        code="too_many_evidence_reads",
    )

    total = storage.size_of(settings, asset.storage_key)
    if total is None:
        raise CloudError(
            "evidence_unavailable",
            "This evidence has not reached the cloud service yet.",
            status_code=503,
        )
    start, end = _range(request.headers.get("range"), total)
    length = end - start + 1
    whole_file = start == 0 and length == total
    if whole_file:
        # Checking the digest is only meaningful against the complete file, and it must happen
        # before any byte is handed out: a response half-sent cannot be withdrawn.
        digest = storage.sha256_of(settings, asset.storage_key)
        if digest != asset.sha256:
            LOGGER.error("asset %s does not match the digest on its row", asset_id)
            raise CloudError(
                "evidence_integrity_failed",
                "This evidence did not pass its integrity check.",
                status_code=503,
            )
    body = storage.read_range(settings, asset.storage_key, start, length)

    user = session.get(User, reader.user_id)
    audit_record(
        session,
        principal=resolve_principal(session, user) if user else None,
        action="evidence.view",
        object_type="evidence_asset",
        object_id=str(asset.id),
        details={
            "incident_id": asset.incident_id,
            "kind": asset.kind,
            "bytes": length,
            "via": "asset_token" if reader.via_token else "session",
            "partial": not whole_file,
        },
        source_ip=reader.source_ip,
    )

    headers = {
        "accept-ranges": "bytes",
        "content-length": str(length),
        # `no-store` because these are security records behind an access decision: a shared cache
        # on a phone's network path would hold them past the moment the person lost the right.
        "cache-control": "no-store",
        "content-disposition": "inline",
    }
    if not whole_file:
        headers["content-range"] = f"bytes {start}-{end}/{total}"
    return Response(
        content=body,
        status_code=206 if not whole_file else 200,
        media_type=asset.content_type,
        headers=headers,
    )


@router.get("/{asset_id}")
def read_metadata(
    asset_id: int,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("evidence.view")),
):
    from ..views import timestamp

    asset = _load_asset(
        session,
        settings,
        asset_id,
        Reader(caller.user_id, via_token=False, source_ip=caller.source_ip),
    )
    return {
        "id": asset.id,
        "kind": asset.kind,
        "content_type": asset.content_type,
        "byte_size": asset.byte_size,
        "sha256": asset.sha256,
        "captured_at": timestamp(asset.captured_at),
        "expires_at": timestamp(asset.expires_at),
        "state": storage.asset_state(settings, asset),
        "incident_id": asset.incident_id,
        "camera_id": str(asset.camera_id) if asset.camera_id else None,
    }


@router.post("/{asset_id}/export")
def export(
    asset_id: int,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("evidence.export")),
):
    """Authorised separately from a view, because export is the act that leaves the device.

    The audit row carries the digest so a later question - "was this the file they took?" - has
    an answer that does not depend on the file still being there.
    """
    asset = _load_asset(
        session,
        settings,
        asset_id,
        Reader(caller.user_id, via_token=False, source_ip=caller.source_ip),
    )
    data = storage.read_bytes(settings, asset.storage_key)
    if data is None:
        raise CloudError(
            "evidence_unavailable",
            "This evidence has not reached the cloud service yet.",
            status_code=503,
        )
    audit_record(
        session,
        principal=caller.principal,
        action="evidence.export",
        object_type="evidence_asset",
        object_id=str(asset.id),
        details={
            "incident_id": asset.incident_id,
            "sha256": asset.sha256,
            "byte_size": asset.byte_size,
        },
        source_ip=caller.source_ip,
    )
    return Response(
        content=data,
        media_type=asset.content_type,
        headers={
            "content-disposition": f'attachment; filename="{asset.filename}"',
            "cache-control": "no-store",
        },
    )
