"""Login, logout and session identity endpoints."""

from __future__ import annotations

import datetime as dt
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..deps import (
    TOKEN_COOKIE,
    Container,
    _bearer,
    authenticate,
    current_principal,
    get_container,
    get_db,
    get_settings,
    issue_token,
)
from ... import __version__
from ...config import Settings
from ...models import User
from ...security.audit import record as audit_record
from ...security.passwords import MIN_PASSWORD_LENGTH, hash_password, verify_password
from ...security.rbac import Principal

router = APIRouter(tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class Identity(BaseModel):
    username: str
    display_name: str
    permissions: list[str]
    is_administrative: bool
    # Reported by the process answering the request, not by the browser, so the Settings screen can
    # tell an operator which build they are actually looking at.
    version: str


class PasswordChange(BaseModel):
    # The same floor the administration form uses, so an operator cannot weaken their own
    # account by choosing something the account-creation path would have refused.
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=256)


@router.post("/password")
def change_password(
    payload: PasswordChange,
    request: Request,
    response: Response,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    settings: Settings = Depends(get_settings),
    principal: Principal = Depends(current_principal),
) -> dict:
    """An operator changing their own console password.

    The account is taken from the session, never from the body, so this cannot be pointed at
    somebody else's account. Neither password is ever echoed or logged: the audit row records that
    a change happened and what it was answered with. The presented token is revoked and a fresh one
    is issued, so a stolen cookie does not survive the change.
    """
    user = session.get(User, principal.user_id)
    source_ip = request.client.host if request.client else None
    if user is None or not user.is_active:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, detail={"code": "session_expired", "message": "Sign in again."}
        )

    if not verify_password(payload.current_password, user.password_hash):
        audit_record(
            session,
            principal=principal,
            action="auth.password_change",
            object_type="user",
            object_id=str(user.id),
            details={"reason": "current_password_incorrect"},
            outcome="failure",
            source_ip=source_ip,
        )
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"code": "current_password_incorrect", "message": "The current password you entered is not correct."},
        )

    if payload.new_password == payload.current_password:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={"code": "password_unchanged", "message": "The new password must be different from the current one."},
        )

    user.password_hash = hash_password(payload.new_password)
    user.password_changed_at = dt.datetime.now(dt.UTC)
    # The mobile app blocks until this flag clears; a self-service change satisfies it.
    user.must_change_password = False
    session.flush()

    token, expires_at = issue_token(settings, container, user.id)
    presented = request.cookies.get(TOKEN_COOKIE) or _bearer(request)
    if presented:
        import jwt

        try:
            claims = jwt.decode(presented, container.token_key, algorithms=["HS256"], options={"verify_exp": False})
            container.revocations.revoke(claims.get("jti", ""), float(claims.get("exp", time.time())))
        except jwt.PyJWTError:
            pass

    audit_record(
        session,
        principal=principal,
        action="auth.password_change",
        object_type="user",
        object_id=str(user.id),
        details={"reason": "changed"},
        source_ip=source_ip,
    )
    response.set_cookie(
        TOKEN_COOKIE,
        token,
        httponly=True,
        secure=settings.require_https,
        samesite="strict",
        max_age=settings.jwt_ttl_minutes * 60,
        path="/",
    )
    return {"status": "changed", "expires_at": expires_at}


@router.post("/login")
def login(
    payload: LoginRequest,
    response: Response,
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    settings: Settings = Depends(get_settings),
) -> dict:
    user, reason = authenticate(session, settings, container, payload.username, payload.password)
    source_ip = request.client.host if request.client else None

    if user is None:
        audit_record(
            session,
            principal=None,
            action="auth.login_failed",
            object_type="user",
            object_id=payload.username,
            details={"reason": reason},
            outcome="failure",
            source_ip=source_ip,
        )
        if reason.startswith("locked:"):
            raise HTTPException(
                status.HTTP_423_LOCKED,
                detail={
                    "code": "account_locked",
                    "message": (
                        "Too many failed attempts. This account is locked for a few "
                        "minutes; contact an administrator if it persists."
                    )
                },
            )
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail={"code": "invalid_credentials", "message": "Incorrect username or password."},
        )

    token, expires_at = issue_token(settings, container, user.id)
    principal = Principal(
        user_id=user.id, username=user.username, display_name=user.display_name
    )
    audit_record(
        session,
        principal=principal,
        action="auth.login",
        object_type="user",
        object_id=str(user.id),
        source_ip=source_ip,
    )

    response.set_cookie(
        TOKEN_COOKIE,
        token,
        httponly=True,
        secure=settings.require_https,
        samesite="strict",
        max_age=settings.jwt_ttl_minutes * 60,
        path="/",
    )
    return {"username": user.username, "display_name": user.display_name, "expires_at": expires_at}


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(current_principal),
) -> dict:
    token = request.cookies.get(TOKEN_COOKIE) or _bearer(request)
    if token:
        import jwt

        try:
            claims = jwt.decode(token, container.token_key, algorithms=["HS256"], options={"verify_exp": False})
            container.revocations.revoke(claims.get("jti", ""), float(claims.get("exp", time.time())))
        except jwt.PyJWTError:
            pass
    audit_record(
        session, principal=principal, action="auth.logout", object_type="user", object_id=str(principal.user_id)
    )
    response.delete_cookie(TOKEN_COOKIE, path="/")
    return {"status": "logged_out"}


@router.get("/me", response_model=Identity)
def me(principal: Principal = Depends(current_principal)) -> Identity:
    return Identity(
        username=principal.username,
        display_name=principal.display_name,
        permissions=sorted(principal.permissions()),
        is_administrative=principal.is_administrative,
        version=__version__,
    )
