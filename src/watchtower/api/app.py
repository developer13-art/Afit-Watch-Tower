"""Application factory: HTTP surface, transport security and lifecycle wiring."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import text

from .deps import Container, TOKEN_COOKIE
from .routers import admin, auth, cameras, incidents, live, notifications
from .. import __version__
from ..config import Settings, load_settings
from ..db import build_engine, build_sessionmaker
from ..mobile.outbox import OutboxForwarder
from ..mobile.worker import OutboxWorker, build_evidence_reader
from ..security.secrets import client_safe, redact
from ..services.runtime import SupervisionLoop

log = logging.getLogger("watchtower.app")

WEB_ROOT = Path(__file__).resolve().parent / "web"
CSRF_HEADER = "x-watchtower-client"
CSRF_HEADER_VALUE = "dashboard"

# Endpoints that must remain reachable without a session cookie.
PUBLIC_PATHS = {"/healthz", "/readyz", "/api/auth/login", "/login", "/static"}


class RevalidatedStaticFiles(StaticFiles):
    """Serve console assets with ``Cache-Control: no-cache``.

    The console is a hand-written ES module graph with no build step and no hashed file names, so
    a browser that reuses one stale module after an update fails the whole page - the import
    error lands on whichever operator reloads first. ``no-cache`` forces revalidation on every
    use; an unchanged file still costs only a 304.
    """

    async def get_response(self, path: str, scope):  # type: ignore[override]
        response = await super().get_response(path, scope)
        response.headers["Cache-Control"] = "no-cache"
        return response



@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.container.settings
    app.state.engine = build_engine(settings)
    app.state.session_factory = build_sessionmaker(app.state.engine)
    app.state.loop = SupervisionLoop(
        settings,
        app.state.session_factory,
        app.state.container.supervisor,
        analysis=app.state.analysis,
    )
    # The mobile queue is drained on its own thread so a slow HTTPS call to the cloud service
    # never delays the health loop. Without cloud configuration it starts and does nothing.
    app.state.outbox = OutboxWorker(
        settings,
        app.state.session_factory,
        forwarder=OutboxForwarder(
            settings,
            app.state.session_factory,
            evidence_reader=build_evidence_reader(settings, app.state.session_factory),
        ),
        app_version=app.version,
    )
    # Tests drive SupervisionLoop.cycle() directly so health transitions are asserted on
    # demand rather than raced against a background thread.
    if app.state.start_supervision:
        app.state.loop.start()
        app.state.outbox.start()
    log.info("watchtower started in %s mode", settings.environment)
    try:
        yield
    finally:
        app.state.loop.stop()
        app.state.outbox.stop()
        app.state.container.shutdown()
        app.state.engine.dispose()
        log.info("watchtower stopped; all managed streams released")


def create_app(
    settings: Settings | None = None,
    *,
    analysis=None,  # watchtower.analysis.engine.AnalysisEngine, or None
    enable_analysis: bool = False,
    start_supervision: bool = True,
) -> FastAPI:
    settings = settings or load_settings()
    container = Container(settings)

    if analysis is None and enable_analysis:
        # The engine has to bind to this process's supervisor, so it can only be built here,
        # after the container exists.
        from ..services.analysis_wiring import build_analysis_engine

        analysis = build_analysis_engine(settings, container.supervisor)

    app = FastAPI(
        title="AFIT WATCH TOWER",
        summary="AI-assisted security camera monitoring and incident management",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs" if not settings.is_production else None,
        redoc_url=None,
    )
    app.state.container = container
    app.state.analysis = analysis
    app.state.start_supervision = start_supervision

    @app.middleware("http")
    async def transport_security(request: Request, call_next):
        forwarded_proto = request.headers.get("x-forwarded-proto", "").split(",")[0].strip()
        scheme = forwarded_proto or request.url.scheme
        if settings.require_https and scheme != "https":
            if request.method == "GET":
                target = str(request.url).replace("http://", "https://", 1)
                return RedirectResponse(target, status_code=status.HTTP_307_TEMPORARY_REDIRECT)
            return JSONResponse(
                {
                    "detail": {
                        "code": "https_required",
                        "message": "This deployment accepts changes over HTTPS only.",
                    }
                },
                status_code=status.HTTP_403_FORBIDDEN,
            )
        response = await call_next(request)
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
            "script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'",
        )
        return response

    @app.middleware("http")
    async def csrf_defence(request: Request, call_next):
        """Same-Site=Strict cookies plus a required non-simple header.

        A cross-site form post cannot set a custom header, and a cross-origin fetch is
        blocked by CORS before it could set one, so cookie-authenticated writes need the
        dashboard header while bearer-token API clients do not.
        """
        cookie_auth = request.cookies.get(TOKEN_COOKIE) is not None
        has_bearer = request.headers.get("Authorization", "").startswith("Bearer ")
        if (
            request.method in {"POST", "PATCH", "PUT", "DELETE"}
            and cookie_auth
            and not has_bearer
            and not _is_public(request.url.path)
            and request.headers.get(CSRF_HEADER) != CSRF_HEADER_VALUE
        ):
            return JSONResponse(
                {
                    "detail": {
                        "code": "csrf_check_failed",
                        "message": "This request must come from the WATCH TOWER dashboard.",
                    }
                },
                status_code=status.HTTP_403_FORBIDDEN,
            )
        return await call_next(request)

    app.include_router(auth.router, prefix="/api/auth")
    app.include_router(cameras.router)
    app.include_router(live.router)
    app.include_router(incidents.router)
    app.include_router(notifications.router)
    app.include_router(admin.router)

    app.mount("/static", RevalidatedStaticFiles(directory=WEB_ROOT / "static"), name="static")
    templates = Jinja2Templates(directory=str(WEB_ROOT / "templates"))

    @app.get("/healthz", include_in_schema=False)
    def liveness() -> dict:
        return {"status": "ok", "environment": settings.environment}

    @app.get("/readyz", include_in_schema=False)
    def readiness(request: Request) -> JSONResponse:
        """Prove the primary database is actually reachable before serving traffic."""
        try:
            with request.app.state.engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except Exception as exc:  # noqa: BLE001 - readiness reports any fault, it must not raise
            return JSONResponse(
                {"status": "unavailable", "reason": client_safe(str(exc))},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return JSONResponse({"status": "ready"})

    @app.get("/login", include_in_schema=False)
    def login_page(request: Request):
        return templates.TemplateResponse(request, "login.html")

    @app.get("/dashboard", include_in_schema=False)
    def dashboard(request: Request):
        return templates.TemplateResponse(request, "dashboard.html")

    @app.get("/", include_in_schema=False)
    def index() -> RedirectResponse:
        return RedirectResponse("/dashboard")

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Never echo the exception text to a client: an FFmpeg or driver fault can carry the
        # credential-bearing URL. The redacted form is logged instead.
        log.error("unhandled error on %s: %s", request.url.path, redact(str(exc)))
        return JSONResponse(
            {"detail": {"code": "internal_error", "message": "The request could not be completed."}},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )

    return app


def _is_public(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PUBLIC_PATHS)
