"""`python -m watchtower.cloud ...` - serve, work, and verify the cloud service.

`verify` exists because most of what this service needs is supplied by AFIT rather than by this
repository: a Firebase project, a TLS origin, a shared database at the current schema revision.
Running it prints which of those are in place and which are still missing, so "what is operational"
is a fact collected from the live configuration rather than a claim made from a document.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import secrets
import sys
import threading
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import urlparse

from sqlalchemy import inspect

from ..db import build_engine, build_sessionmaker
from ..security.secrets import redact
from .app import API_PREFIX, create_app, healthcheck
from .config import CloudConfigError, CloudSettings, load_cloud_settings
from .deps import CloudContainer
from .worker import DELIVERY, ESCALATION, CloudWorker

LOG_LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

DEFAULT_PORT = 8080

# The three start commands a managed platform needs: the API, the push sender, the escalation
# sweep. `both` is the single-host default, so an operator running one box keeps getting delivery
# and escalation out of one process exactly as before this flag existed.
JOB_BOTH = "both"
JOB_CHOICES = (JOB_BOTH, DELIVERY, ESCALATION)

# Tables the cloud service writes on its own path. A missing one is an unapplied migration, and
# every request that touches it would answer 503 with a database fault behind it.
REQUIRED_TABLES = (
    "users",
    "roles",
    "user_roles",
    "incidents",
    "notifications",
    "mobile_devices",
    "notification_attempts",
    "refresh_tokens",
    "personnel_preferences",
    "incident_acknowledgements",
    "notification_outbox",
    "ingest_nonces",
    "ingest_records",
    "evidence_relay_states",
    "monitoring_heartbeats",
)


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    # A DSN in an exception text is the one string that must not reach the log file.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def _load_env_file(path: str) -> None:
    """Populate the environment without overwriting what is already set."""
    file = Path(path)
    if not file.exists():
        raise SystemExit(f"no such environment file: {path}")
    for line in file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def _settings_from(args: argparse.Namespace) -> CloudSettings:
    if getattr(args, "env_file", None):
        _load_env_file(args.env_file)
    return load_cloud_settings(dict(os.environ))


def _resolve_port(
    explicit: int | None, env: Mapping[str, str] | None = None
) -> tuple[int, str]:
    """The port to bind, and where it came from.

    A managed platform assigns the port and publishes it as `PORT`; a service that ignores it
    binds somewhere the proxy is not looking and answers nothing but health checks to nobody. So
    `PORT` is honoured, `--port` still overrides it for a local run, and 8080 is the last resort.
    A `PORT` that is neither empty nor a number is refused rather than quietly dropped - the
    alternative is a service that starts, looks healthy and cannot be reached.
    """
    if explicit is not None:
        return int(explicit), "--port"
    raw = ((env if env is not None else os.environ).get("PORT") or "").strip()
    if not raw:
        return DEFAULT_PORT, "default"
    try:
        port = int(raw)
    except ValueError:
        raise CloudConfigError(
            f"PORT is not a port number: {redact(raw)[:40]!r} (refusing to guess a port)"
        ) from None
    if not 1 <= port <= 65535:
        raise CloudConfigError(f"PORT {port} is outside 1-65535")
    return port, "PORT"


def _jobs(args: argparse.Namespace) -> str | None:
    """`both` means the whole job set, which the worker spells as `None`."""
    value = getattr(args, "jobs", JOB_BOTH)
    return None if value == JOB_BOTH else value


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = _settings_from(args)
    port, port_source = _resolve_port(args.port)
    _configure_logging(args.log_level)
    app = create_app(settings, start_worker=not args.no_worker)
    config = uvicorn.Config(
        app,
        host=args.host,
        port=port,
        # TLS terminates at the proxy in front of this service; `--proxy-headers` is what lets
        # the HTTPS guarantee in `app.HttpsOnlyMiddleware` see the real scheme.
        proxy_headers=True,
        forwarded_allow_ips=args.trusted_proxy,
        root_path=args.root_path,
        log_config=None,
        access_log=args.access_log,
    )
    server = uvicorn.Server(config)
    logging.getLogger("watchtower.cloud").info(
        "serving on %s:%s (port from %s; no reload, workers handled by the process manager)",
        args.host,
        port,
        port_source,
    )
    server.run()
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    """Run the selected jobs without serving HTTP.

    For a deployment that wants one API process and background work in another - and, with
    `--jobs`, delivery and escalation in two separate processes so a faulty push sender can be
    restarted without stopping the escalation sweep. In-process delivery (the default for `serve`)
    is the right choice for a single host. The container is built here rather than by entering the
    web application's lifespan, because a process that serves no requests should not depend on the
    ASGI loop staying alive.
    """
    settings = _settings_from(args)
    _configure_logging(args.log_level)
    container = CloudContainer(settings)
    engine = build_engine(settings)
    container.engine = engine
    container.session_factory = build_sessionmaker(engine)
    try:
        Path(settings.evidence_dir).mkdir(parents=True, exist_ok=True)
        worker = CloudWorker(settings, container.session_factory, container, jobs=_jobs(args))
        worker.start()
        stop = _StopRequest()
        while not stop.requested:
            stop.wait(1.0)
        worker.stop()
        return 0
    finally:
        engine.dispose()


class _StopRequest:
    """Ctrl-C ends the worker loop; the exit code says the operator stopped it, not a crash."""

    def __init__(self) -> None:
        import signal

        self.requested = False
        self._event = threading.Event()

        def _handler(signum, frame):
            del signum, frame
            self.requested = True
            self._event.set()

        for name in ("SIGINT", "SIGTERM"):
            if hasattr(signal, name):
                with contextlib.suppress(ValueError):
                    # ValueError means this is not the main thread (a test, or an embedding
                    # process); leave the caller's handlers alone.
                    signal.signal(getattr(signal, name), _handler)

    def wait(self, seconds: float) -> None:
        self._event.wait(seconds)
        self._event.clear()


def cmd_verify(args: argparse.Namespace) -> int:
    settings = _settings_from(args)
    _configure_logging("WARNING")
    print(f"AFIT WATCH TOWER cloud service - configuration check ({settings.environment})")
    print("-" * 68)

    blocking: list[str] = []
    warnings: list[str] = []

    def line(ok: bool, label: str, detail: str = "") -> None:
        print(f"[{'ok' if ok else '!!'}] {label}{': ' + detail if detail else ''}")

    # 1. Database.
    engine = build_engine(settings)
    try:
        probe = healthcheck(build_sessionmaker(engine))
        line(probe["database"] == "ok", "database connection", settings_redacted(settings))
        if probe["database"] != "ok":
            blocking.append(f"database unreachable: {redact(probe.get('detail', ''))}")
    except Exception as exc:  # noqa: BLE001 - a check command reports, it does not raise
        line(False, "database connection", redact(str(exc))[:100])
        blocking.append("database connection failed")
        engine = None

    if engine is not None:
        try:
            from alembic.runtime import migration

            with engine.connect() as connection:
                revision = migration.MigrationContext.configure(connection).get_current_revision()
            line(bool(revision), "schema revision", revision or "no alembic revision recorded")
            if not revision:
                blocking.append("no schema: run `python -m watchtower migrate`")
            names = set(inspect(engine).get_table_names())
            missing = [table for table in REQUIRED_TABLES if table not in names]
            line(not missing, "personnel tables", "all present" if not missing
                 else f"missing {', '.join(missing)}")
            if missing:
                blocking.append("missing tables: " + ", ".join(missing))
        finally:
            engine.dispose()

    # 2. Secrets and token custody.
    key_path = Path(settings.secret_key_path)
    if key_path.exists():
        line(True, "encryption key ring", str(key_path))
    elif settings.is_production:
        line(False, "encryption key ring", "absent, and production will not create one")
        blocking.append(f"create {key_path} before starting in production")
    else:
        line(True, "encryption key ring", f"will be created at {key_path} on first start")

    line(len(settings.jwt_secret) >= 32, "token signing secret", "configured")

    # 3. The two doors.
    if settings.ingest_enabled:
        line(True, "monitoring-host ingest", f"{len(settings.service_keys)} service key(s)")
    else:
        line(False, "monitoring-host ingest", "no CLOUD_SERVICE_KEYS_JSON / ingest key pair")
        warnings.append(
            "without a service key the monitoring host's forwarder is refused; alerts stay local"
        )

    if settings.push_enabled:
        account = Path(settings.firebase_service_account_file or "")
        line(account.is_file(), "Firebase service account", str(account))
        if not account.is_file():
            blocking.append("the Firebase service account file is configured but not readable")
    else:
        line(False, "push delivery", "not configured")
        warnings.append(
            "alerts are recorded as failed with notification_attempts.error_code="
            "not_configured instead of paging"
        )

    # 4. What the phone needs to be able to reach us.
    public_ok = settings.public_base_url.startswith("https://") or not settings.is_production
    line(public_ok, "public origin", settings.public_base_url)
    if not public_ok:
        blocking.append("CLOUD_PUBLIC_BASE_URL must be https in production")
    line(bool(settings.allowed_origins) or not settings.is_production, "browser origins",
         ", ".join(settings.allowed_origins) or "none (native app only)")

    if settings.require_https:
        line(True, "HTTPS enforcement", "on (run the server with --proxy-headers behind a proxy)")
    else:
        line(not settings.is_production, "HTTPS enforcement", "off")
        if settings.is_production:
            blocking.append("CLOUD_REQUIRE_HTTPS=0 in production")

    print("-" * 68)
    for warning in warnings:
        print(f"note: {warning}")
    if blocking:
        print(f"\n{len(blocking)} blocking item(s):")
        for item in blocking:
            print(f"  - {item}")
        return 1
    print("\nReady to serve. API root: " + f"{settings.public_base_url}{API_PREFIX}")
    return 0


def settings_redacted(settings: CloudSettings) -> str:
    """The database host only - never the user, and never the password."""
    parsed = urlparse(settings.database_url)
    port = f":{parsed.port}" if parsed.port else ""
    return f"{parsed.scheme}://{parsed.hostname}{port}"


def cmd_service_key(_: argparse.Namespace) -> int:
    key_id = "host-1"
    secret = secrets.token_urlsafe(48)
    print("# Paste into the cloud service environment, and into the monitoring host's .env.")
    print(f"CLOUD_SERVICE_KEYS_JSON={{\"{key_id}\":\"{secret}\"}}")
    print("# The monitoring host reads the same object from WATCHTOWER_CLOUD_SERVICE_KEYS_JSON.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m watchtower.cloud",
        description="AFIT WATCH TOWER personnel (cloud) API service",
    )
    parser.add_argument("--env-file", help="read configuration from this file first")
    parser.add_argument("--log-level", default="INFO", choices=LOG_LEVELS)
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="run the HTTPS API (and, by default, delivery)")
    serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address; the default stays loopback so a local run cannot be reached from the "
             "network. A hosted deployment passes 0.0.0.0 deliberately.",
    )
    serve.add_argument(
        "--port",
        type=int,
        default=None,
        help=f"bind port; overrides the platform's PORT, which is used when this is absent "
             f"(fallback {DEFAULT_PORT})",
    )
    serve.add_argument("--root-path", default="")
    serve.add_argument(
        "--trusted-proxy",
        default="127.0.0.1",
        help="comma-separated addresses whose X-Forwarded-* headers may be believed",
    )
    serve.add_argument(
        "--access-log", action="store_true",
        help="log one line per request; off by default because a request line carries a bearer "
             "token if anything ever puts one in a query string",
    )
    serve.add_argument(
        "--no-worker", action="store_true",
        help="serve HTTP only; run `worker` as a separate process. Required for any deployment "
             "with more than one API instance, or every instance pages the same person",
    )
    serve.set_defaults(func=cmd_serve)

    worker = sub.add_parser(
        "worker",
        help="run delivery and/or escalation only, as a separate process from the API",
    )
    worker.add_argument(
        "--jobs",
        choices=JOB_CHOICES,
        default=JOB_BOTH,
        help="delivery hands queued notifications to FCM; escalation queues a re-page for a "
             "critical incident nobody has acknowledged. Run them apart to restart one without "
             "stopping the other; run them together (`both`, the default) on a single host.",
    )
    worker.set_defaults(func=cmd_worker)

    verify = sub.add_parser("verify", help="report what is configured and what is still missing")
    verify.set_defaults(func=cmd_verify)

    key = sub.add_parser("service-key", help="print a fresh monitoring-host signing key pair")
    key.set_defaults(func=cmd_service_key)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv if argv is not None else sys.argv[1:])
    try:
        return int(args.func(args))
    except CloudConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":  # pragma: no cover - `python -m watchtower.cloud`
    raise SystemExit(main())
