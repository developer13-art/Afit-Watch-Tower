#!/usr/bin/env python
"""Local demo launcher for AFIT WATCH TOWER - read this before using it.

    python scripts/dev_serve.py --admin-password 'at least 12 characters'

This is NOT a supported deployment. Proposal section 8.1 makes PostgreSQL the primary
application database, and `watchtower.config.load_settings()` enforces that: the real
entry point (`python -m watchtower.cli serve`) refuses any non-PostgreSQL URL and will
keep refusing it. This script does not go through `load_settings()` at all - it builds a
`Settings` object in process with a SQLite file under `var/dev/`, the same way the pytest
harness does, so the guard in `src/` stays exactly as strict as it was.

What that means in practice:

  * the schema here comes from `Base.metadata.create_all()`, not from the Alembic
    migrations that an AFIT deployment runs. It is the same ORM mapping, but the
    PostgreSQL-only DDL (partial indexes, check-constraint naming) is not exercised.
  * it binds to 127.0.0.1 and turns HTTPS enforcement off, which is only acceptable
    because nothing leaves this machine. Do not forward the port.
  * a camera registered here is registered for real: the connection test opens a real
    RTSP socket, and a camera only reaches `online` after frames are confirmed
    (section 6.5 and 6.6). Nothing in this script fakes a result.

Use it to see the dashboard, to walk the registration -> test -> activation -> live view
flow against your own camera, and to review how incidents and evidence behave. Use
PostgreSQL for anything AFIT would rely on.
"""

from __future__ import annotations

import argparse
import secrets
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

DEV_DIR = PROJECT_ROOT / "var" / "dev"
MIN_PASSWORD_LENGTH = 12

BANNER = """
==============================================================================
 WATCH TOWER - LOCAL DEMO PROCESS
 database   : SQLite file ({db})
 migrations : not used; tables created from the ORM mapping
 HTTPS      : not enforced (loopback only)
 supported? : NO. Section 8.1 requires PostgreSQL; run
              `python -m watchtower.cli serve` for a real deployment.
==============================================================================
"""


def _jwt_secret() -> str:
    """A stable per-machine secret, so restarting the demo does not log everyone out."""
    path = DEV_DIR / "jwt.secret"
    if path.exists():
        value = path.read_text().strip()
        if value:
            return value
    value = secrets.token_urlsafe(48)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    return value


def _settings(database_url: str) -> object:
    from watchtower.config import Settings

    return Settings(
        database_url=database_url,
        secret_key_path=DEV_DIR / "watchtower.key",
        jwt_secret=_jwt_secret(),
        jwt_ttl_minutes=480,
        environment="development",
        require_https=False,
        evidence_dir=DEV_DIR / "evidence",
    )


def _prepare_database(settings, username: str, password: str | None) -> str | None:
    """Create tables, seed access control and return a generated password, if any."""
    from sqlalchemy import select

    from watchtower.db import build_engine, build_sessionmaker, session_scope
    from watchtower.mobile import models as _mobile_models  # noqa: F401 - registers tables
    from watchtower.models import Base, Role, User, UserRole
    from watchtower.security.passwords import hash_password
    from watchtower.security.rbac import bootstrap_access_control

    engine = build_engine(settings)
    Base.metadata.create_all(engine)
    session_factory = build_sessionmaker(engine)

    generated = None
    with session_scope(session_factory) as session:
        bootstrap_access_control(session)
        existing = session.scalar(select(User).where(User.username == username))
        if existing is None:
            if password is None:
                password = secrets.token_urlsafe(18)
                generated = password
            role = session.scalar(select(Role).where(Role.code == "system_administrator"))
            if role is None:
                raise SystemExit("the system_administrator role was not seeded; check rbac bootstrap")
            user = User(
                username=username,
                display_name="Local Administrator",
                email=f"{username}@localhost.local",
                password_hash=hash_password(password),
                is_active=True,
            )
            session.add(user)
            session.flush()
            # No camera group: institution-wide scope, which is what section 8.4 gives the
            # system administrator role anyway.
            session.add(UserRole(user_id=user.id, role_id=role.id, camera_group_id=None))
            print(f"created administrator account {username!r}")
        elif password is not None and password != "":
            existing.password_hash = hash_password(password)
            print(f"reset the password for {username!r}")
        else:
            print(
                f"{username!r} already exists - pass --admin-password to set its password"
            )
    engine.dispose()
    return generated


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8040)
    parser.add_argument("--username", default="watchtower_admin")
    parser.add_argument(
        "--admin-password",
        default=None,
        help=(
            "password for the local administrator (12+ characters). Omit it on the first "
            "run and one is generated and printed once."
        ),
    )
    parser.add_argument("--database", default=str(DEV_DIR / "watchtower.db"))
    parser.add_argument(
        "--no-analysis",
        action="store_true",
        help="start without the AI pass; live view, health and incidents still run",
    )
    args = parser.parse_args(argv)

    # uvicorn takes over the console; the banner and the one-time password have to be visible
    # before it does, even when stdout is a redirected file.
    sys.stdout.reconfigure(line_buffering=True)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "refusing to bind outside loopback. This demo runs without HTTPS, and camera "
            "streams must not be reachable from a network (section 16).",
            file=sys.stderr,
        )
        return 2
    if args.admin_password is not None and len(args.admin_password) < MIN_PASSWORD_LENGTH:
        print(
            f"the administrator password needs at least {MIN_PASSWORD_LENGTH} characters "
            "(section 8.4 policy applies here too).",
            file=sys.stderr,
        )
        return 2

    database_path = Path(args.database)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    settings = _settings(f"sqlite:///{database_path.as_posix()}")
    print(BANNER.format(db=database_path))

    generated = _prepare_database(settings, args.username, args.admin_password)

    import uvicorn

    from watchtower.api.app import create_app

    app = create_app(settings, enable_analysis=not args.no_analysis)
    if generated is not None:
        # Never written to a credentials file by this script - but if you redirect the console
        # to a log, the log holds it, so treat that file as a secret.
        print(f"login username : {args.username}")
        print(f"login password : {generated}   (shown once; restart with --admin-password to set your own)")
    print(f"\nopen http://{args.host}:{args.port}/login\n")
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
