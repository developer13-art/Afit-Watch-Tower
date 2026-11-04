"""Device registration (contract section 3).

The handset tells the service it exists; the service decides whether it may be paged. A push
token is only ever accepted over TLS, is stored sealed, and never comes back in a response -
`GET /devices` reports push *state*, not the token, because the app has no reason to read back
what it already holds and a screen-share of a device list should not expose a bearer capability.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import devices as device_store
from ..deps import Caller, CloudContainer, get_container, get_db, require_password_changed
from ..errors import CloudError

router = APIRouter(prefix="/devices", tags=["devices"])


class DeviceBody(BaseModel):
    installation_id: str = Field(min_length=8, max_length=64)
    platform: str = "android"
    push_provider: str = "fcm"
    push_token: str | None = Field(default=None, max_length=512)
    model: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=32)
    app_version: str | None = Field(default=None, max_length=32)


@router.post("")
def register_device(
    body: DeviceBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    caller: Caller = Depends(require_password_changed),
):
    device, token_changed = device_store.register(
        session,
        container,
        user_id=caller.user_id,
        installation_id=body.installation_id,
        platform=body.platform,
        push_provider=body.push_provider,
        push_token=body.push_token,
        model=body.model,
        os_version=body.os_version,
        app_version=body.app_version,
    )
    return {
        "id": device.id,
        "installation_id": device.installation_id,
        "platform": device.platform,
        "push_provider": device.push_provider,
        "push_state": device.push_state,
        "installed_at": device.registered_at.isoformat(),
        "last_seen_at": device.last_seen_at.isoformat(),
        "token_changed": token_changed,
    }


@router.get("")
def list_devices(
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_password_changed),
):
    return {"items": device_store.list_for_user(session, caller.user_id)}


@router.delete("/{installation_id}")
def forget_device(
    installation_id: str,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    caller: Caller = Depends(require_password_changed),
):
    device = device_store.deactivate(
        session, user_id=caller.user_id, installation_id=installation_id
    )
    # Forgetting a handset ends the sessions minted from it; the person keeps their account.
    revoked = container.tokens.revoke_for_device(session, device.id)
    return {"deactivated": True, "sessions_revoked": revoked}


@router.post("/{installation_id}/push-token")
def rotate_push_token(
    installation_id: str,
    body: DeviceBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    caller: Caller = Depends(require_password_changed),
):
    """FCM rotated the registration token mid-session; the app re-POSTs it here.

    A separate endpoint because the `token` callback fires while the person is signed in and the
    installation id is already known - and because an unknown installation id must not silently
    create a second device row.
    """
    known = device_store.find(session, user_id=caller.user_id, installation_id=installation_id)
    if known is None:
        raise CloudError("not_found", "This device is not registered on your account.", status_code=404)
    if not body.push_token:
        raise CloudError(
            "push_token_required", "A registration token is required.", status_code=422
        )
    device, changed = device_store.register(
        session,
        container,
        user_id=caller.user_id,
        installation_id=installation_id,
        platform=body.platform or known.platform,
        push_provider=body.push_provider or known.push_provider,
        push_token=body.push_token,
        model=body.model,
        os_version=body.os_version,
        app_version=body.app_version,
    )
    return {"id": device.id, "push_state": device.push_state, "token_changed": changed}
