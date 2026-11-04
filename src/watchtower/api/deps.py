"""Authentication and dependency wiring for the HTTP API."""

from __future__ import annotations

import datetime as dt
import secrets as _pysecrets
import time
from dataclasses import dataclass, field
from typing import Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import Settings
from ..models import User
from ..security.passwords import needs_rehash, verify_password
from ..security.rbac import Principal, resolve_principal
from ..security.secrets import derive_media_key

TOKEN_COOKIE = "watchtower_session"  # noqa: S105 - the cookie's name, never a secret
_ALGORITHM = "HS256"
_LOCKOUT_AFTER = 8
_LOCKOUT_SECONDS = 300


@dataclass
class Revocations:
    """Logout invalidation for otherwise-stateless tokens.

    A prototype keeps this in memory; a hardened deployment moves it into Postgres so a
    restart cannot resurrect a logged-out token.
    """

    _jtis: dict[str, float] = field(default_factory=dict)

    def revoke(self, jti: str, expires_at: float) -> None:
        self._jtis[jti] = expires_at
        now = time.time()
        self._jtis = {key: value for key, value in self._jtis.items() if value > now}

    def is_revoked(self, jti: str) -> bool:
        return jti in self._jtis


class Container:
    """Per-process service container built once at startup."""

    def __init__(self, settings: Settings) -> None:
        from ..ingest.supervisor import StreamSupervisor
        from ..security.secrets import KeyRing, SecretStore

        self.settings = settings
        self.key_ring = KeyRing(
            settings.secret_key_path,
            create_if_missing=not settings.is_production,
        )
        self.secret_store = SecretStore(self.key_ring)
        self.supervisor = StreamSupervisor(settings)
        self.revocations = Revocations()
        self.token_key = derive_media_key(settings.jwt_secret, "auth-token")
        self.live_sessions: dict[str, LiveViewSession] = {}

    def shutdown(self) -> None:
        self.supervisor.shutdown()


@dataclass(slots=True)
class LiveViewSession:
    camera_id: str
    user_id: int
    token: str
    started_at: float
    last_seen: float
    released: bool = False


def issue_token(settings: Settings, container: Container, user_id: int) -> tuple[str, int]:
    now = int(time.time())
    expires_at = now + settings.jwt_ttl_minutes * 60
    payload = {
        "sub": str(user_id),
        "jti": _pysecrets.token_hex(8),
        "iat": now,
        "exp": expires_at,
        "scope": "watchtower.session",
    }
    token = jwt.encode(payload, container.token_key, algorithm=_ALGORITHM)
    return token, expires_at


def get_db(request: Request) -> Any:
    session = request.app.state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_container(request: Request) -> Container:
    return request.app.state.container


def get_settings(request: Request) -> Settings:
    return request.app.state.container.settings


def authenticate(
    session: Session, settings: Settings, container: Container, username: str, password: str
) -> tuple[User | None, str]:
    """Verify credentials and enforce lockout on repeated failures (section 16)."""
    user = session.scalar(select(User).where(User.username == username))
    now = dt.datetime.now(dt.UTC)

    if user is None or not user.is_active:
        # Identical timing and message for unknown user vs disabled user.
        return None, "invalid_credentials"

    if user.locked_until is not None:
        locked_until = _as_utc(user.locked_until)
        if locked_until > now:
            remaining = int((locked_until - now).total_seconds())
            return None, f"locked:{remaining}"

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= _LOCKOUT_AFTER:
            user.locked_until = now + dt.timedelta(seconds=_LOCKOUT_SECONDS)
            user.failed_login_count = 0
        # The route answers a rejected login by raising, and get_db rolls back on the way out.
        # The lockout counter has to survive that rollback or repeated failures never accumulate.
        session.commit()
        return None, "invalid_credentials"

    if user.password_hash and needs_rehash(user.password_hash):
        # The plaintext is available exactly here, so the cost parameter can be raised
        # without a migration that strands existing accounts.
        from ..security.passwords import hash_password

        user.password_hash = hash_password(password)
    user.failed_login_count = 0
    user.locked_until = None
    user.last_login_at = now
    session.flush()
    return user, "ok"


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def current_principal(
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
) -> Principal:
    token = request.cookies.get(TOKEN_COOKIE) or _bearer(request)
    if not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="authentication_required")
    try:
        claims = jwt.decode(
            token, container.token_key, algorithms=[_ALGORITHM], audience=None, leeway=5
        )
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="invalid_credentials" if not isinstance(exc, jwt.ExpiredSignatureError) else "session_expired",
        ) from exc
    if container.revocations.is_revoked(claims.get("jti", "")):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="session_expired")

    user = session.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")
    return resolve_principal(session, user)


def _bearer(request: Request) -> str | None:
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header.removeprefix("Bearer ").strip()
    return None


def require_permission(permission: str):
    def dependency(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.allows(permission):
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"code": "forbidden", "message": f"Missing permission {permission}."},
            )
        return principal

    return dependency
