"""Personnel authentication (contract section 2).

The account itself is created by an administrator in the monitoring console. There is no
registration endpoint here and no password-reset email: those need a mail gateway AFIT has not
approved, and open self-registration against a security-incident system would be the front door
of the estate rather than a convenience.

Passwords are verified against the same `users.password_hash` column the console uses. Argon2id
hashes are produced for new passwords, existing PBKDF2 hashes still verify and are lifted on the
next successful sign-in - so the mobile launch does not force a reset on every account.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ...models import User, utcnow
from ...security.audit import record as audit_record
from ...security.passwords import MIN_PASSWORD_LENGTH, hash_password, verify_password
from ...security.rbac import resolve_principal
from .. import devices as device_store
from ..config import CloudSettings
from ..deps import (
    Caller,
    CloudContainer,
    current_caller,
    get_container,
    get_db,
    get_settings,
    require_password_changed,
    source_ip,
)
from ..errors import CloudError
from ..ratelimit import enforce
from ..tokens import IssuedSession
from ..views import user_view

LOGGER = logging.getLogger("watchtower.cloud.auth")

router = APIRouter(prefix="/auth", tags=["auth"])


class DeviceAtLogin(BaseModel):
    installation_id: str = Field(min_length=8, max_length=64)
    platform: str = "android"
    push_token: str | None = Field(default=None, max_length=512)
    model: str | None = Field(default=None, max_length=128)
    os_version: str | None = Field(default=None, max_length=32)
    app_version: str | None = Field(default=None, max_length=32)


class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=256)
    password: str = Field(min_length=1, max_length=512)
    device: DeviceAtLogin | None = None


class RefreshBody(BaseModel):
    refresh_token: str = Field(min_length=16, max_length=512)


class LogoutBody(BaseModel):
    refresh_token: str | None = Field(default=None, max_length=512)
    forget_device: bool = False


class PasswordBody(BaseModel):
    current_password: str = Field(min_length=1, max_length=512)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=512)
    keep_other_sessions: bool = False


def _session_payload(issued: IssuedSession) -> dict:
    return {
        "access_token": issued.access_token,
        "token_type": "Bearer",
        "expires_in": issued.expires_in,
        "refresh_token": issued.refresh_token,
        "refresh_expires_in": issued.refresh_expires_in,
    }


def _register_optional_device(
    session: Session, container: CloudContainer, *, user: User, body: LoginBody
) -> int | None:
    if body.device is None:
        return None
    device, _changed = device_store.register(
        session,
        container,
        user_id=user.id,
        installation_id=body.device.installation_id,
        platform=body.device.platform,
        push_token=body.device.push_token,
        model=body.device.model,
        os_version=body.device.os_version,
        app_version=body.device.app_version,
    )
    return device.id


@router.post("/login")
def login(
    body: LoginBody,
    request: Request,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    client_ip: str | None = Depends(source_ip),
):
    name = body.username.strip().lower()
    enforce(
        container.limiter,
        "login-username",
        name,
        limit=settings.login_attempts_per_5_minutes,
        window_seconds=300,
        code="too_many_login_attempts",
    )
    enforce(
        container.limiter,
        "login-ip",
        client_ip or "unknown",
        limit=settings.login_attempts_per_ip_per_minute,
        window_seconds=60,
        code="too_many_login_attempts",
    )

    user, outcome = container.tokens.authenticate(
        session, username=body.username, password=body.password, source_ip=client_ip
    )
    if outcome != "ok" or user is None:
        reason = "account_locked" if outcome == "account_locked" else "invalid_credentials"
        audit_record(
            session,
            principal=None,
            action="auth.login_failed",
            object_type="user",
            object_id=name,
            details={"reason": reason},
            outcome="failure",
            source_ip=client_ip,
        )
        if reason == "account_locked":
            raise CloudError(
                "account_locked",
                "This account is temporarily locked after repeated failed sign-ins.",
                status_code=401,
                headers={"retry-after": "300"},
            )
        # One answer for "no such account" and "wrong password", with no hint which was tried.
        raise CloudError("invalid_credentials", "Username or password is not correct.", status_code=401)

    device_id = _register_optional_device(session, container, user=user, body=body)
    issued = container.tokens.issue(
        session,
        user=user,
        device_id=device_id,
        client_ip=client_ip,
        user_agent=request.headers.get("user-agent"),
    )
    principal = resolve_principal(session, user)
    audit_record(
        session,
        principal=principal,
        action="auth.login",
        object_type="user",
        object_id=str(user.id),
        details={"family": issued.family, "device_id": device_id},
        source_ip=client_ip,
    )
    # A temporary password only buys a session and a password change; the app reads
    # `must_change_password` from here and routes to that screen before anything else.
    return {**_session_payload(issued), "user": user_view(session, user, principal)}


@router.post("/refresh")
def refresh(
    body: RefreshBody,
    request: Request,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
):
    enforce(
        container.limiter,
        "refresh",
        body.refresh_token[:16],
        limit=settings.refresh_attempts_per_5_minutes,
        window_seconds=300,
        code="too_many_refresh_attempts",
    )
    issued = container.tokens.rotate(
        session,
        body.refresh_token,
        client_ip=source_ip(request),
        user_agent=request.headers.get("user-agent"),
    )
    return _session_payload(issued)


@router.post("/logout")
def logout(
    body: LogoutBody,
    request: Request,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    caller: Caller = Depends(current_caller),
):
    family = container.tokens.logout(
        session,
        body.refresh_token or "",
        access_claims={"jti": caller.access_jti, "exp": caller.access_expires_at},
    )
    forgotten = False
    if body.forget_device and caller.installation_id:
        device_store.deactivate(
            session, user_id=caller.user_id, installation_id=caller.installation_id
        )
        forgotten = True
    audit_record(
        session,
        principal=caller.principal,
        action="auth.logout",
        object_type="session",
        object_id=caller.session_id,
        details={"family": family, "device_forgotten": forgotten},
        source_ip=caller.source_ip,
    )
    return {"signed_out": True, "device_forgotten": forgotten}


@router.post("/password")
def change_password(
    body: PasswordBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    caller: Caller = Depends(current_caller),
):
    enforce(
        container.limiter,
        "password",
        str(caller.user_id),
        limit=5,
        window_seconds=900,
        code="too_many_password_attempts",
    )
    user = session.get(User, caller.user_id)
    if user is None:
        raise CloudError("invalid_credentials", "This account no longer exists.", status_code=401)
    if not verify_password(body.current_password, user.password_hash):
        audit_record(
            session,
            principal=caller.principal,
            action="auth.password.change",
            object_type="user",
            object_id=str(user.id),
            details={"reason": "current_password_incorrect"},
            outcome="failure",
            source_ip=caller.source_ip,
        )
        raise CloudError(
            "current_password_incorrect", "The current password is not correct.", status_code=401
        )

    user.password_hash = hash_password(body.new_password)
    user.must_change_password = False
    user.password_changed_at = utcnow()
    session.flush()

    revoked = (
        0
        if body.keep_other_sessions
        else container.tokens.revoke_all_for_user(session, user.id)
    )
    audit_record(
        session,
        principal=caller.principal,
        action="auth.password.change",
        object_type="user",
        object_id=str(user.id),
        details={
            "other_sessions_revoked": revoked,
            "keep_other_sessions": body.keep_other_sessions,
        },
        source_ip=caller.source_ip,
    )
    return {"changed": True, "other_sessions_revoked": revoked}


@router.get("/me")
def me(
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_password_changed),
):
    user = session.get(User, caller.user_id)
    if user is None:
        raise CloudError("invalid_credentials", "This account no longer exists.", status_code=401)
    return user_view(session, user, caller.principal)
