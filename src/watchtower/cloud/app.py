"""The cloud service process: `watchtower.cloud.app`.

Separate from the monitoring console on purpose. The console listens inside the AFIT network and
holds the camera credentials; this service listens on the public HTTPS origin, holds no camera
credential at all, and shares only the database. Mounting the two in one process would mean the
host a phone can reach also happens to be the host that can open an RTSP stream.

Startup order is the security story:

  1. refuse to start on a non-PostgreSQL URL (`load_cloud_settings` already did this);
  2. refuse to mint an encryption key silently in production (`CloudContainer`);
  3. every failure leaves through one error envelope with a request id (`install_error_handlers`);
  4. plain HTTP is answered with a redirect or a refusal, never with data.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import text
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from ..db import build_engine, build_sessionmaker
from ..security.secrets import redact
from .config import CloudSettings, load_cloud_settings
from .deps import CloudContainer
from .errors import error_body, install_error_handlers, new_request_id
from .routers import ROUTERS
from .worker import CloudWorker, build_worker

LOGGER = logging.getLogger("watchtower.cloud.app")

API_PREFIX = "/api/v1"

# An inbound `x-request-id` is echoed into logs and error bodies, so it is treated as untrusted
# text: a value that cannot survive that trip without changing meaning is replaced, not honoured.
_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_LOOPBACK = {"127.0.0.1", "::1", "localhost", "testserver"}

OPEN_DEEP_LINK_RE = re.compile(r"^/open/incidents/(?P<incident_id>\d{1,12})$")

# The paths a load balancer may reach without TLS termination or a token. `/readyz` is not one of
# them: this service answers readiness on `/healthz`, which returns 503 when the database is not
# reachable, and the monitoring console is the app that has a separate `/readyz`.
_PROBE_PATHS = frozenset({"/healthz", "/"})

_SERVICE_NAME = "AFIT WATCH TOWER personnel API"
_PROTOCOL_VERSION = "1"


def _request_id(scope: Scope) -> str:
    headers = dict(scope.get("headers") or ())
    inbound = headers.get(b"x-request-id", b"").decode("latin-1").strip()
    return inbound if _REQUEST_ID_RE.match(inbound) else new_request_id()


class RequestIdMiddleware:
    """One id per request, set before anything can fail, echoed on the way out."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = _request_id(scope)
        scope.setdefault("state", {})["request_id"] = request_id

        async def _send(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.append((b"x-request-id", request_id.encode("latin-1")))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, _send)


class HttpsOnlyMiddleware:
    """`CLOUD_REQUIRE_HTTPS` is a guarantee, not a comment.

    Behind a TLS-terminating proxy, run the server with `--proxy-headers` and
    `--forwarded-allow-ips` set to the proxy's address; that is what makes the ASGI scheme `https`
    here. Without it, the requests this service receives really are in the clear, and the correct
    answer is to refuse them rather than serve incident data over plain HTTP.

    GET and HEAD are redirected so a person who typed `http://` lands on the right place. Every
    other method is refused: a redirect of a POST would silently re-send a body, and an
    unauthenticated POST to a security API is not something to guess about.
    """

    def __init__(self, app: ASGIApp, *, settings: CloudSettings) -> None:
        self.app = app
        self._settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope["type"] != "http"
            or not self._settings.require_https
            or scope.get("scheme") == "https"
            or _is_loopback(scope)
            or _is_unauthenticated_probe(scope)
        ):
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        request_id = str(scope.get("state", {}).get("request_id", ""))
        if method in {"GET", "HEAD"}:
            target = _https_url(scope, self._settings)
            response = RedirectResponse(url=target, status_code=307)
        else:
            response = JSONResponse(
                status_code=403,
                content=error_body(
                    "https_required",
                    "This service answers over HTTPS only.",
                    request_id,
                ),
            )
        LOGGER.warning("plain HTTP refused on %s %s", method, scope.get("path", ""))
        await response(scope, receive, send)


def _is_loopback(scope: Scope) -> bool:
    client = scope.get("client")
    host = str(client[0]) if client else ""
    return host in _LOOPBACK or host.startswith("127.")


def _is_unauthenticated_probe(scope: Scope) -> bool:
    """`/healthz` and `/open/*` must be reachable by a load balancer with no TLS termination.

    Only paths this app actually serves belong here. Each entry is a door through the HTTPS rule,
    so a name left over from a route that was never added is a permanent exemption for a 404.
    """
    return scope.get("path", "") in _PROBE_PATHS or bool(
        OPEN_DEEP_LINK_RE.match(scope.get("path", ""))
    )


def _https_url(scope: Scope, settings: CloudSettings) -> str:
    """Redirect to the configured public origin, never to whatever `Host` the client sent.

    Trusting `Host` would turn the redirect into a phishing generator: one spoofed header and a
    supervisor's browser is sent to an attacker's path-for-path copy.
    """
    base = settings.public_base_url.rstrip("/")
    if not base.startswith("https://"):
        base = "https://" + base.split("://", 1)[-1]
    path = scope.get("path", "")
    query = scope.get("query_string", b"").decode("latin-1")
    return f"{base}{path}" + (f"?{query}" if query else "")


def create_app(
    settings: CloudSettings | None = None,
    *,
    session_factory: Any = None,
    start_worker: bool = False,
    docs_enabled: bool | None = None,
    push_sender: Any = None,
) -> FastAPI:
    """Build the service.

    `session_factory` is the test seam: a caller that already owns an engine - a pytest fixture on
    a temporary database - hands it in, and the app neither connects nor disconnects. In a real
    deployment it is omitted and the lifespan opens the Neon connection pool from
    `CLOUD_DATABASE_URL`.

    `push_sender` is the delivery seam: the object that actually hands a message to FCM. Production
    leaves it unset and takes `CLOUD_FIREBASE_*` from the environment; a caller with its own
    provider, or a test that must not contact Google while checking what an attempt recorded,
    passes one here.
    """
    resolved = settings or load_cloud_settings()
    public_docs = (not resolved.is_production) if docs_enabled is None else docs_enabled

    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        container: CloudContainer = app.state.container
        owns_engine = session_factory is None
        engine = None
        factory = session_factory
        if owns_engine:
            engine = build_engine(resolved)
            factory = build_sessionmaker(engine)
        container.engine = engine
        container.session_factory = factory
        app.state.session_factory = factory
        resolved.evidence_dir.mkdir(parents=True, exist_ok=True)

        worker: CloudWorker | None = None
        if start_worker and factory is not None:
            worker = build_worker(container)
            if worker is not None:
                container.escalation = worker
                worker.start()
        _log_startup(
            resolved,
            worker_started=worker is not None,
            push_ready=container.push.configured,
        )
        try:
            yield
        finally:
            if worker is not None:
                worker.stop()
            if engine is not None:
                engine.dispose()

    app = FastAPI(
        title=_SERVICE_NAME,
        version=_PROTOCOL_VERSION,
        docs_url="/docs" if public_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if public_docs else None,
        lifespan=_lifespan,
    )
    app.state.settings = resolved
    app.state.container = CloudContainer(resolved)
    if push_sender is not None:
        app.state.container.use_push_sender(push_sender)
    app.state.session_factory = session_factory
    app.state.started_at = dt.datetime.now(dt.UTC)

    # Added innermost-first: the stack ends up CORS outside request-id outside HTTPS outside the
    # router, so a browser pre-flight is answered with its headers even when the answer is "no".
    app.add_middleware(HttpsOnlyMiddleware, settings=resolved)
    app.add_middleware(RequestIdMiddleware)
    if resolved.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved.allowed_origins),
            # The app authenticates with a bearer header, not cookies. Allowing credentials would
            # let any listed origin ride a session the person established some other way.
            allow_credentials=False,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=[
                "authorization",
                "content-type",
                "x-installation-id",
                "x-request-id",
                "range",
            ],
            expose_headers=["x-request-id", "content-range", "accept-ranges", "retry-after"],
            max_age=600,
        )

    install_error_handlers(app)
    _mount_routes(app)
    _add_operational_routes(app)
    return app


def _mount_routes(app: FastAPI) -> None:
    for router in ROUTERS:
        app.include_router(router, prefix=API_PREFIX)


def _add_operational_routes(app: FastAPI) -> None:
    settings: CloudSettings = app.state.settings

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> JSONResponse:
        """Liveness plus an honest statement of what this process can actually do.

        `database` is the only thing that can be broken from here. `push` and `ingest` being
        `disabled` is a configuration state, not a fault, and the app's support screen shows it
        that way rather than as a failure.
        """
        database = "unavailable"
        detail = ""
        factory = app.state.session_factory
        if factory is not None:
            try:
                with factory() as session:
                    session.execute(text("SELECT 1"))
                database = "ok"
            except Exception as exc:  # noqa: BLE001 - a probe answers any driver fault with 503
                detail = str(exc).splitlines()[0][:120]
                LOGGER.error("health probe could not reach the database: %s", redact(detail))
        uptime = (dt.datetime.now(dt.UTC) - app.state.started_at).total_seconds()
        body = {
            "status": "ok" if database == "ok" else "degraded",
            "service": _SERVICE_NAME,
            "protocol_version": _PROTOCOL_VERSION,
            "database": database,
            # The installed sender answers this, not the settings: a Firebase project named in the
            # environment whose key file cannot be read is not a working push, and a health
            # endpoint that called that "enabled" would be the one lie an operator relied on.
            "push": "enabled" if app.state.container.push.configured else "disabled",
            "ingest": "enabled" if settings.ingest_enabled else "disabled",
            # Reported separately from `push` because they fail for different reasons and an
            # operator reading this needs to know which half of alert delivery is standing.
            "live_channel": "enabled" if settings.stream_enabled else "disabled",
            "uptime_seconds": round(uptime, 1),
            "time": dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z"),
        }
        if detail:
            # Logged in full (redacted) because an operator needs the reason; answered with a
            # fixed phrase because a connection error's text contains the host and, on some
            # drivers, the user name of the database.
            body["database_detail"] = "connection failed"
        return JSONResponse(
            status_code=200 if database == "ok" else 503,
            content=body,
            headers={"cache-control": "no-store"},
        )

    @app.get("/", include_in_schema=False)
    def index() -> dict[str, Any]:
        return {
            "service": _SERVICE_NAME,
            "api": f"{settings.public_base_url}{API_PREFIX}",
            "protocol_version": _PROTOCOL_VERSION,
            "docs": "/docs" if app.openapi_url else None,
            "authentication": "bearer access token from POST /api/v1/auth/login",
        }

    @app.get("/open/incidents/{incident_id}", include_in_schema=False, response_class=HTMLResponse)
    def open_incident(incident_id: int) -> HTMLResponse:
        """The HTTPS form of the deep link. Carries no incident data and makes no query.

        On a handset with the app installed, the operating system intercepts this URL and opens
        the app, so nobody sees the page. It exists for the cases the OS cannot intercept -
        a link pasted into a desktop browser, a colleague's chat message on an unregistered
        device - where a person needs one button and one explanation.

        Whether the visitor is signed in, and whether they may see incident
        `{incident_id}`, is decided by the app against the API, so this page must not answer
        either question in advance. It contains no script, no request, and no data.
        """
        return HTMLResponse(
            content=_DEEP_LINK_PAGE.format(incident_id=int(incident_id)),
            status_code=200,
            headers={
                "cache-control": "no-store",
                "x-frame-options": "DENY",
                "referrer-policy": "no-referrer",
                "content-security-policy": _DEEP_LINK_CSP,
            },
        )


_DEEP_LINK_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)

# An Android App Link or an iOS universal link is intercepted by the operating system before this
# renders, so the page is only ever seen where that association is missing. Inline styles are for
# the two colours above; there is no script, no image and no fetch on this page.
_DEEP_LINK_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>WATCH TOWER - open incident</title>
<style>
  body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#0b1220;
         color:#e6edf7; font:16px/1.5 system-ui, sans-serif; }}
  main {{ max-width:34rem; padding:2rem 1.5rem; text-align:center; }}
  h1 {{ font-size:1.15rem; margin:0 0 .5rem; font-weight:600; }}
  p {{ margin:.35rem 0 1.25rem; color:#9fb0c8; }}
  a.btn {{ display:inline-block; padding:.75rem 1.25rem; border-radius:.6rem; background:#2f6fed;
          color:#fff; text-decoration:none; font-weight:600; }}
  small {{ display:block; margin-top:1.25rem; color:#6d7f97; }}
</style>
</head>
<body>
<main>
  <h1>Open incident {incident_id} in WATCH TOWER</h1>
  <p>If the app is installed on this device, it opens when you choose the button.</p>
  <a class="btn" href="watchtower://incidents/{incident_id}">Open the app</a>
  <small>Nothing about this incident is shown on this page. Signing in, and your access to
  incident {incident_id}, are checked inside the app.</small>
</main>
</body>
</html>
"""


__all__ = [
    "API_PREFIX",
    "HttpsOnlyMiddleware",
    "RequestIdMiddleware",
    "create_app",
]


def _log_startup(settings: CloudSettings, *, worker_started: bool, push_ready: bool) -> None:
    """What the operator needed to know, once, at the moment it was true."""
    LOGGER.info(
        "personnel API starting: environment=%s public_base_url=%s push=%s ingest_keys=%d "
        "worker=%s origins=%d live_channel=%s",
        settings.environment,
        settings.public_base_url,
        "configured" if push_ready else "NOT DELIVERING",
        len(settings.service_keys),
        "running" if worker_started else "not started",
        len(settings.allowed_origins),
        f"on (cap {settings.stream_max_connections})" if settings.stream_enabled else "off",
    )
    if settings.is_production and not push_ready:
        LOGGER.warning(
            "production with no working push client: alerts will be recorded as failed "
            "deliveries with the reason the sender reports rather than reaching any handset. "
            "That reason is `not_configured` when the Firebase variables are absent and "
            "`push_misconfigured` when they are present but unusable."
        )
    if not settings.ingest_enabled:
        LOGGER.warning(
            "no service keys configured: /api/v1/ingest/* will refuse every call from the "
            "monitoring host"
        )


def healthcheck(session_factory: Callable[[], Any]) -> dict[str, Any]:
    """The same probe `/healthz` runs, for the CLI's `verify` command."""
    try:
        with session_factory() as session:
            session.execute(text("SELECT 1"))
        return {"database": "ok"}
    except Exception as exc:  # noqa: BLE001 - the caller wants the verdict, not the exception
        return {"database": "unavailable", "detail": str(exc).splitlines()[0][:120]}
