"""Personnel session tokens: short access tokens, rotating device-bound refresh tokens.

Two decisions in here are load-bearing for the security argument, so they are documented at the
point they are made rather than in a design note:

  * **Permissions are never in the access token.** A token carries identity only (`sub`, `sid`).
    Every request re-resolves the effective grants from the database, so removing a camera-group
    grant takes effect on the next call rather than up to 15 minutes later, and a stolen token
    cannot be used to see a camera its holder was never allowed to see.
  * **A refresh token is stored as a SHA-256 digest and is single-use.** Rotating presents the
    old value and returns a new one in the same transaction. If a value that was already rotated
    comes back, somebody holds both copies, which only happens if one was exfiltrated: the whole
    family is revoked and the legitimate user is signed out at their next refresh.

`WATCHTOWER_JWT_SECRET` is never used here; the cloud signs with its own secret and a different
derived key, so a personnel token is worthless against the monitoring console.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import secrets
import threading
import time
import uuid
from dataclasses import dataclass

import jwt
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from ..models import User, utcnow
from ..security.secrets import derive_media_key
from .config import CloudSettings
from .errors import CloudError

ALGORITHM = "HS256"
SCOPE = "watchtower.personnel"
REFRESH_BYTES = 32  # 256 bits of entropy, the value a phone holds onto


@dataclass(slots=True)
class IssuedSession:
    access_token: str
    expires_in: int
    refresh_token: str
    refresh_expires_in: int
    session_id: str
    family: str
    access_expires_at: int


def token_digest(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode()).hexdigest()


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


class RevokedAccessTokens:
    """Logout for an otherwise stateless bearer token.

    A 15-minute token is short enough that keeping the revoked `jti` set in memory for its
    remaining lifetime is a reasonable trade; the alternative (a database write on every request
    to check it) would make every read cost a round trip. The caveat is the same one as the rate
    limiter: a restart forgets the list, so a logged-out token can live out its remaining
    minutes. Anything with a longer TTL must move this into the database.
    """

    def __init__(self) -> None:
        self._entries: dict[str, float] = {}
        self._lock = threading.Lock()

    def revoke(self, jti: str, expires_at: float) -> None:
        if not jti:
            return
        with self._lock:
            self._entries[jti] = expires_at
            self._prune_locked(time.time())

    def is_revoked(self, jti: str) -> bool:
        with self._lock:
            expires_at = self._entries.get(jti)
            if expires_at is None:
                return False
            if expires_at <= time.time():
                self._entries.pop(jti, None)
                return False
            return True

    def _prune_locked(self, now: float) -> None:
        if len(self._entries) < 4096:
            return
        self._entries = {k: v for k, v in self._entries.items() if v > now}

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


class TokenService:
    def __init__(self, settings: CloudSettings) -> None:
        self._settings = settings
        self._key = derive_media_key(settings.jwt_secret, "personnel-access-token")
        self.revoked = RevokedAccessTokens()

    # -- access tokens ---------------------------------------------------- #

    def access_token(self, user_id: int, session_id: str) -> tuple[str, int, str]:
        now = int(time.time())
        expires_at = now + self._settings.access_token_ttl_seconds
        jti = secrets.token_hex(12)
        claims = {
            "sub": str(user_id),
            "sid": session_id,
            "jti": jti,
            "iat": now,
            "exp": expires_at,
            "iss": self._settings.token_issuer,
            "scope": SCOPE,
        }
        return jwt.encode(claims, self._key, algorithm=ALGORITHM), expires_at, jti

    def decode_access(self, token: str) -> dict:
        try:
            claims = jwt.decode(
                token,
                self._key,
                algorithms=[ALGORITHM],
                issuer=self._settings.token_issuer,
                leeway=5,
            )
        except jwt.ExpiredSignatureError as exc:
            raise CloudError(
                "access_expired", "The session token has expired.", status_code=401
            ) from exc
        except jwt.PyJWTError as exc:
            raise CloudError(
                "invalid_token", "The session token is not recognised.", status_code=401
            ) from exc
        if claims.get("scope") != SCOPE:
            # A console or third-party token presented here is not a personnel session, even if
            # some other service in this deployment signed it with a key that happens to match.
            raise CloudError("invalid_scope", "This token is not a personnel session.", status_code=401)
        if self.revoked.is_revoked(claims.get("jti", "")):
            raise CloudError("session_revoked", "This session has been signed out.", status_code=401)
        return claims

    # -- refresh tokens --------------------------------------------------- #

    def issue(
        self,
        session: Session,
        *,
        user: User,
        device_id: int | None = None,
        family: uuid.UUID | None = None,
        session_id: str | None = None,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        from ..mobile.models import RefreshToken

        parent = None
        generation = 1
        if family is not None:
            latest = session.scalar(
                select(RefreshToken)
                .where(RefreshToken.family == family)
                .order_by(RefreshToken.generation.desc())
                .limit(1)
            )
            if latest is not None:
                parent = latest
                generation = latest.generation + 1
        else:
            family = uuid.uuid4()

        plaintext = secrets.token_urlsafe(REFRESH_BYTES)
        row = RefreshToken(
            user_id=user.id,
            device_id=device_id,
            token_hash=token_digest(plaintext),
            family=family,
            generation=generation,
            expires_at=utcnow() + dt.timedelta(seconds=self._settings.refresh_token_ttl_seconds),
            client_ip=client_ip,
            user_agent=(user_agent or "")[:256] or None,
        )
        session.add(row)
        session.flush()
        if parent is not None:
            parent.rotated_at = utcnow()
            parent.replaced_by_id = row.id

        sid = session_id or secrets.token_hex(8)
        access, token_expires_at, _jti = self.access_token(user.id, sid)
        return IssuedSession(
            access_token=access,
            expires_in=self._settings.access_token_ttl_seconds,
            refresh_token=plaintext,
            refresh_expires_in=self._settings.refresh_token_ttl_seconds,
            session_id=sid,
            family=str(family),
            access_expires_at=token_expires_at,
        )

    def rotate(
        self,
        session: Session,
        plaintext: str,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        """Spend a refresh token and get a new pair. Reuse revokes the family."""
        from ..mobile.models import RefreshToken

        if not plaintext:
            raise CloudError("refresh_required", "A refresh token is required.", status_code=401)
        row = session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == token_digest(plaintext))
        )
        if row is None:
            raise CloudError("invalid_refresh", "This refresh token is not recognised.", status_code=401)

        if row.rotated_at is not None or row.revoked_at is not None:
            # The value was already spent, so two parties hold it. Revoke everything minted
            # from this login and let the audit row explain the sign-out.
            from ..security.audit import record as audit_record
            from ..security.rbac import resolve_principal

            self._revoke_family(session, row.family, detected_from=row.id)
            holder = session.get(User, row.user_id)
            audit_record(
                session,
                principal=resolve_principal(session, holder) if holder else None,
                action="auth.refresh_reuse",
                object_type="refresh_token",
                object_id=str(row.id),
                details={"family": str(row.family), "generation": row.generation},
                outcome="failure",
            )
            raise CloudError(
                "refresh_reused",
                "This session was signed out because the refresh token was presented twice.",
                status_code=401,
            )

        user = session.get(User, row.user_id)
        if user is None or not user.is_active:
            raise CloudError("invalid_refresh", "This account can no longer sign in.", status_code=401)

        now = utcnow()
        if _as_utc(row.expires_at) <= now:
            row.revoked_at = now
            raise CloudError("refresh_expired", "This session has expired.", status_code=401)

        return self.issue(
            session,
            user=user,
            device_id=row.device_id,
            family=row.family,
            client_ip=client_ip,
            user_agent=user_agent,
        )

    def logout(self, session: Session, plaintext: str, *, access_claims: dict | None) -> str:
        """Sign the caller out. An unknown token is not an error: the client is leaving."""
        from ..mobile.models import RefreshToken

        revoked = "no_session"
        if plaintext:
            row = session.scalar(
                select(RefreshToken).where(RefreshToken.token_hash == token_digest(plaintext))
            )
            if row is not None:
                if row.revoked_at is None:
                    row.revoked_at = utcnow()
                revoked = str(row.family)
        if access_claims:
            self.revoked.revoke(
                access_claims.get("jti", ""), float(access_claims.get("exp", time.time()))
            )
        return revoked

    def _revoke_family(self, session: Session, family: uuid.UUID, *, detected_from: int) -> int:
        from ..mobile.models import RefreshToken

        now = utcnow()
        result = session.execute(
            update(RefreshToken)
            .where(RefreshToken.family == family, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now, reuse_detected=True)
        )
        session.flush()
        return int(result.rowcount or 0)

    def revoke_all_for_user(self, session: Session, user_id: int) -> int:
        """Every device, e.g. after a password change or an administrator disable."""
        from ..mobile.models import RefreshToken

        now = utcnow()
        result = session.execute(
            update(RefreshToken)
            .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        session.flush()
        return int(result.rowcount or 0)

    def revoke_for_device(self, session: Session, device_id: int) -> int:
        from ..mobile.models import RefreshToken

        now = utcnow()
        result = session.execute(
            update(RefreshToken)
            .where(RefreshToken.device_id == device_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
        session.flush()
        return int(result.rowcount or 0)

    # -- login ------------------------------------------------------------ #

    def authenticate(
        self, session: Session, *, username: str, password: str, source_ip: str | None = None
    ) -> tuple[User | None, str]:
        """Verify credentials against the shared `users` table and enforce lockout.

        Mirrors the monitoring console's rule (8 failures, 5 minutes) rather than inventing a
        second one: an attacker who can spray the phone API and an attacker who can spray the
        console are the same attacker, and a weaker limit on either side is the effective limit.
        """
        from ..security.passwords import hash_password, needs_rehash, verify_password

        name = (username or "").strip().lower()
        user = session.scalar(
            select(User).where((User.username.ilike(name)) | (User.email.ilike(name)))
        )
        now = utcnow()

        if user is None or not user.is_active:
            # Same message and same work for unknown account and disabled account. Hashing a
            # throwaway password keeps the response time comparable to a real attempt.
            verify_password(password or "", "$argon2id$dummy$0$0$0")
            return None, "invalid_credentials"

        if user.locked_until is not None and _as_utc(user.locked_until) > now:
            return None, "account_locked"

        if not verify_password(password or "", user.password_hash):
            user.failed_login_count += 1
            if user.failed_login_count >= 8:
                user.locked_until = now + dt.timedelta(seconds=300)
                user.failed_login_count = 0
            # A rejected login answers 401 and the request session rolls back on the way out.
            # The counter has to survive that or failures never accumulate.
            session.commit()
            return None, "invalid_credentials"

        if needs_rehash(user.password_hash):
            # The plaintext exists only here, which is the one moment a PBKDF2 hash can be
            # lifted to Argon2id without a bulk migration or a forced password reset.
            user.password_hash = hash_password(password)
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        session.flush()
        return user, "ok"
