"""Request wiring for the cloud service: one container, one session per call, bearer identity.

The identity dependency resolves a token to a `Caller` (principal plus the claims it came with)
and nothing more. Permissions are read from the database on every request, so a revoked grant is
gone on the next call rather than when the access token happens to expire.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from ..security.rbac import Principal, can_view_camera, resolve_principal
from .config import CloudSettings, load_cloud_settings
from .errors import CloudError
from .ratelimit import RateLimiter
from .tokens import TokenService

LOGGER = logging.getLogger("watchtower.cloud.deps")


class CloudContainer:
    """Per-process services, built once at startup and hung on `app.state.container`."""

    def __init__(self, settings: CloudSettings) -> None:
        from ..security.secrets import KeyRing, SecretStore

        self.settings = settings
        self.key_ring = KeyRing(
            settings.secret_key_path,
            # Production must not silently mint a new encryption key at boot: that would
            # strand every stored FCM token, and the operator would learn from failed pushes.
            create_if_missing=not settings.is_production,
        )
        self.secret_store = SecretStore(self.key_ring)
        self.tokens = TokenService(settings)
        self.limiter = RateLimiter()
        from .streaming import StreamRoom

        self.streams = StreamRoom(settings.stream_max_connections)
        self.engine = None
        self.session_factory = None
        self._push = None
        self.delivery = None
        self.escalation = None

    # -- push token custody ------------------------------------------------ #

    def seal_push_token(self, plaintext: str) -> tuple[bytes, str]:
        sealed = self.secret_store.seal(plaintext)
        return sealed.ciphertext, sealed.key_id

    def unseal_push_token(self, ciphertext: bytes | None, key_id: str | None) -> str | None:
        if not ciphertext or not key_id:
            return None
        from cryptography.fernet import InvalidToken

        try:
            return self.key_ring.fernet(key_id).decrypt(bytes(ciphertext)).decode()
        except InvalidToken as exc:
            # The token is gone but the device row is not. Report it as a delivery failure so
            # the console shows why this handset stopped receiving alerts.
            LOGGER.warning("stored push token could not be decrypted: %s", exc)
            return None

    # -- lifecycle ---------------------------------------------------------- #

    @property
    def push(self):
        if self._push is None:
            from .push import build_push_sender

            self._push = build_push_sender(self.settings, self.secret_store)
        return self._push

    def use_push_sender(self, sender) -> None:
        """Install the push client before the first delivery.

        A deployment that brings its own provider uses this instead of editing the settings; a test
        uses it to watch what an attempt recorded without anybody calling Google. It only replaces
        a sender that has not been built yet, because silently swapping one that requests are
        already flying through would hide which host actually accepted a message.
        """
        if self._push is not None:
            raise RuntimeError("a push sender is already installed on this container")
        self._push = sender

    def new_evidence_store(self, session: Session):
        """A request-scoped handle on `CLOUD_EVIDENCE_DIR`.

        The cloud never writes evidence of its own - the bytes arrive from the monitoring host
        through `cloud.storage` - but `IncidentService` is the console's service and asks for a
        store, so the phone gets the same one rather than a stub that could hide a real call.
        """
        from ..services.evidence import EvidenceStore

        return EvidenceStore(self.settings, session)

    def incident_service(self, session: Session):
        """The console's own workflow service, so a phone cannot invent a second state machine.

        `settings=None` is deliberate: the monitoring host owns the outbox that reaches the
        cloud. An action taken *on* the cloud is delivered by `cloud.delivery` in the same
        request, and enqueueing it into the outbox as well would page every recipient twice.
        """
        from ..services.incidents import IncidentService
        from ..services.notifications import NotificationService

        return IncidentService(
            session,
            NotificationService(session),
            self.new_evidence_store(session),
            settings=None,
        )

    def shutdown(self) -> None:
        if self.escalation is not None:
            self.escalation.stop()


@dataclass(slots=True)
class Caller:
    """Who is asking, what they may do, and which session they asked from."""

    principal: Principal
    user_id: int
    session_id: str
    must_change_password: bool
    source_ip: str | None
    installation_id: str | None
    # Kept so signing out can retire this exact access token without decoding it a second time.
    access_jti: str = ""
    access_expires_at: float = 0.0


def get_container(request: Request) -> CloudContainer:
    return request.app.state.container


def get_settings(container: CloudContainer = Depends(get_container)) -> CloudSettings:
    return container.settings


def get_db(request: Request):
    session = request.app.state.session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def source_ip(request: Request) -> str | None:
    """The peer address, not `X-Forwarded-For`.

    A phone cannot spoof the TCP peer; it can spoof a forwarded header, so a header would make
    the login rate limit trivially bypassable. Put the real client address into the peer by
    terminating TLS and proxying on the same host, or configure the proxy to rewrite it.
    """
    return request.client.host if request.client else None


def bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise CloudError(
            "authentication_required",
            "A bearer access token is required.",
            status_code=401,
        )
    token = header.removeprefix("Bearer ").removeprefix("bearer ").strip()
    if not token:
        raise CloudError(
            "authentication_required", "A bearer access token is required.", status_code=401
        )
    return token


def current_caller(
    request: Request,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
) -> Caller:
    claims = container.tokens.decode_access(bearer_token(request))
    from ..models import User

    user = session.get(User, int(claims["sub"]))
    if user is None or not user.is_active:
        # Revoked mid-session: the token is still cryptographically valid, the person is not.
        raise CloudError("invalid_credentials", "This account is no longer active.", status_code=401)
    principal = resolve_principal(session, user)
    installation_id = request.headers.get("x-installation-id", "").strip() or None
    return Caller(
        principal=principal,
        user_id=user.id,
        session_id=claims.get("sid", ""),
        must_change_password=bool(user.must_change_password),
        source_ip=source_ip(request),
        installation_id=installation_id,
        access_jti=str(claims.get("jti") or ""),
        access_expires_at=float(claims.get("exp") or 0),
    )


def require_permission(permission: str):
    """The gate for every route that touches incident data.

    It sits on top of `require_password_changed` rather than beside it so that the rule -
    an account still holding a password somebody else chose can do nothing but change it -
    cannot be forgotten on a new endpoint. `POST /auth/logout` and `POST /auth/password`
    depend on `current_caller` directly, because those two are the way out of that state.
    """

    def dependency(caller: Caller = Depends(require_password_changed)) -> Caller:
        if not caller.principal.allows(permission):
            raise CloudError(
                "forbidden",
                f"This account is not permitted to {permission}.",
                status_code=403,
            )
        return caller

    return dependency


def require_password_changed(caller: Caller = Depends(current_caller)) -> Caller:
    """Everything except signing out and fixing the password, while a change is pending."""
    if caller.must_change_password:
        raise CloudError(
            "password_change_required",
            "An administrator issued this account a temporary password. Change it before use.",
            status_code=403,
        )
    return caller


def camera_is_visible(principal: Principal, permission: str, camera) -> bool:
    return camera is None or can_view_camera(principal, permission, camera)


__all__ = [
    "Caller",
    "CloudContainer",
    "current_caller",
    "get_container",
    "get_db",
    "get_settings",
    "load_cloud_settings",
    "require_password_changed",
    "require_permission",
    "source_ip",
]
