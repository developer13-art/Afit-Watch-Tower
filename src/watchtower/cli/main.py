"""AFIT WATCH TOWER command line.

Migrations, first-administrator bootstrap, serving and retention. These run explicitly -
nothing here executes at application import time, so a stray process start cannot alter
access control or create accounts.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from alembic.config import Config
from alembic.runtime import migration
from sqlalchemy import select, text

from ..api.app import create_app
from ..config import ConfigError, load_settings
from ..db import build_engine, build_sessionmaker, session_scope
from ..models import User
from ..security.passwords import hash_password
from ..security.rbac import bootstrap_access_control

PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_PASSWORD_MIN_LENGTH = 12


def _alembic_config() -> Config:
    ini = PROJECT_ROOT / "alembic.ini"
    if not ini.exists():
        raise SystemExit(f"cannot find {ini}; run the CLI from the project root.")
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    return cfg


def _current_head(engine) -> str | None:
    with engine.connect() as connection:
        return migration.MigrationContext.configure(connection).get_current_revision()


def _scripts_head() -> tuple[str | None, str | None]:
    """The revision the migration files define: `(head, branch_if_not_linear)`.

    A second value means the scripts have forked, which no single database can match, so the
    caller has to treat that as a failure rather than a comparison.
    """
    from alembic.script import ScriptDirectory

    script = ScriptDirectory.from_config(_alembic_config())
    heads = script.get_heads()
    return (heads[0] if len(heads) == 1 else None), (None if len(heads) <= 1 else ",".join(heads))


def cmd_migrate(args: argparse.Namespace) -> int:
    """Apply pending migrations through migrations/env.py.

    env.py is what enforces the PostgreSQL-only rule, so the CLI defers to it rather than
    opening its own connection.
    """
    from alembic.command import upgrade

    load_settings(dict(os.environ))  # fail fast with the config error before touching DDL
    cfg = _alembic_config()
    upgrade(cfg, "head")
    engine = build_engine(load_settings(dict(os.environ)))
    revision = _current_head(engine)
    engine.dispose()
    print(f"database schema is now at revision {revision}")
    return 0


def cmd_check_schema(_: argparse.Namespace) -> int:
    settings = load_settings(dict(os.environ))
    engine = build_engine(settings)
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
            revision = _current_head(engine)
    except Exception as exc:  # noqa: BLE001 - the CLI reports the fault as its own exit message
        print(f"database unreachable: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()

    if revision is None:
        print("connected; NO SCHEMA - run migrate before anything else.", file=sys.stderr)
        return 1

    head, branches = _scripts_head()
    if branches:
        print(
            f"connected; alembic revision = {revision}, but the migration scripts have "
            f"branched ({branches}). A branched history cannot be compared to one database "
            "revision; resolve the branch before deploying.",
            file=sys.stderr,
        )
        return 1
    if revision != head:
        print(
            f"connected; alembic revision = {revision}, but the code in this checkout needs "
            f"{head}. The database is behind the application: every query that names a column "
            "added by the missing revision will fail at runtime, not at boot. Run migrate.",
            file=sys.stderr,
        )
        return 1
    print(f"connected; alembic revision = {revision} (matches this checkout)")
    return 0 if revision else 1


def cmd_bootstrap(args: argparse.Namespace) -> int:
    """Create the role catalogue and the first System Administrator."""
    settings = load_settings(dict(os.environ))
    engine = build_engine(settings)
    session_factory = build_sessionmaker(engine)

    with session_scope(session_factory) as session:
        bootstrap_access_control(session)
        first_existing = session.scalar(select(User).limit(1))
        if first_existing is not None and not args.force:
            # Said out loud because the catalogue above is already committed: the non-zero exit
            # below means "no administrator was created", not "the sync failed".
            print("role and permission catalogue synced from the code definitions.")
            print(
                f"users already exist (first: {first_existing.username}). This command will "
                "not guess what you want; re-run with --force to add another account.",
                file=sys.stderr,
            )
            engine.dispose()
            return 1
        username = args.username or input("Administrator username [watchtower_admin]: ").strip()
        username = username or "watchtower_admin"
        if session.scalar(select(User.id).where(User.username == username)):
            print(f"user {username!r} already exists", file=sys.stderr)
            return 1
        password = args.password or getpass.getpass("Password (12+ characters): ")
        if len(password) < DEFAULT_PASSWORD_MIN_LENGTH:
            print(
                f"password must be at least {DEFAULT_PASSWORD_MIN_LENGTH} characters",
                file=sys.stderr,
            )
            return 1
        confirmation = args.password or getpass.getpass("Repeat password: ")
        if password != confirmation:
            print("passwords did not match", file=sys.stderr)
            return 1

        from ..models import Role, UserRole

        role = session.scalar(select(Role).where(Role.code == "system_administrator"))
        if role is None:
            print("the system_administrator role is missing; check RBAC seeding", file=sys.stderr)
            return 1

        user = User(
            username=username,
            display_name=args.display_name or "System Administrator",
            email=args.email,
            password_hash=hash_password(password),
            is_active=True,
        )
        session.add(user)
        session.flush()
        session.add(UserRole(user_id=user.id, role_id=role.id, camera_group_id=None))
        print(f"created {username!r} with institution-wide System Administrator rights")
    engine.dispose()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = load_settings(dict(os.environ))
    if settings.is_production and not settings.require_https:
        print(
            "refusing to serve production with HTTPS enforcement disabled (section 16).",
            file=sys.stderr,
        )
        return 1
    # The analysis engine binds to the supervisor held inside the app container, so the choice
    # is passed down rather than built here against a supervisor that does not exist yet.
    app = create_app(settings, enable_analysis=not args.no_analysis)
    uvicorn.run(
        app,
        host=args.host,
        port=args.port,
        proxy_headers=True,
        forwarded_allow_ips=args.trusted_proxy,
        log_level="info",
    )
    return 0


def cmd_purge(args: argparse.Namespace) -> int:
    """Apply retention. Intended for a scheduled invocation, not a silent background job."""
    settings = load_settings(dict(os.environ))
    engine = build_engine(settings)
    session_factory = build_sessionmaker(engine)
    with session_scope(session_factory) as session:
        from ..services.evidence import EvidenceStore

        removed = EvidenceStore(settings, session).purge_expired()
        print(f"retired {removed} expired evidence asset(s)")
    engine.dispose()
    return 0


def cmd_secret_key(args: argparse.Namespace) -> int:
    settings = load_settings(dict(os.environ))
    from ..security.secrets import KeyRing

    path = Path(settings.secret_key_path)
    if path.exists() and not args.force:
        print(f"{path} already exists; use --force to add a new active key", file=sys.stderr)
        return 1
    ring = KeyRing(path, create_if_missing=True)
    if args.force and path.exists():
        key_id = ring.rotate()
        print(f"rotated; new active key id {key_id}")
    else:
        print(f"created key ring at {path} (active key id {ring.active_key_id})")
        print("record the location in the installation instructions and protect it.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="watchtower", description="AFIT WATCH TOWER control")
    parser.add_argument(
        "--env-file",
        help="optional KEY=VALUE file to load before reading the environment",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    migrate = sub.add_parser("migrate", help="apply database migrations")
    migrate.set_defaults(func=cmd_migrate)

    check = sub.add_parser("check-schema", help="verify the database is reachable and migrated")
    check.set_defaults(func=cmd_check_schema)

    boot = sub.add_parser("bootstrap", help="create roles, permissions and the first administrator")
    boot.add_argument("--username")
    boot.add_argument("--password")
    boot.add_argument("--email")
    boot.add_argument("--display-name")
    boot.add_argument("--force", action="store_true", help="add an account even if users exist")
    boot.set_defaults(func=cmd_bootstrap)

    serve = sub.add_parser("serve", help="run the dashboard and API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8040)
    serve.add_argument(
        "--trusted-proxy",
        default="",
        help="comma separated proxy IPs allowed to assert X-Forwarded-Proto",
    )
    serve.add_argument(
        "--no-analysis",
        action="store_true",
        help="start without the AI analysis pass (monitoring and live view still work)",
    )
    serve.set_defaults(func=cmd_serve)

    purge = sub.add_parser("purge", help="apply evidence retention")
    purge.set_defaults(func=cmd_purge)

    key = sub.add_parser("secret-key", help="create or rotate the credential key ring")
    key.add_argument("--force", action="store_true", help="rotate an existing ring")
    key.set_defaults(func=cmd_secret_key)
    return parser


def _load_env_file(path: str) -> None:
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    # --env-file is consumed before the subcommand's own arguments.
    env_file = None
    if "--env-file" in argv:
        index = argv.index("--env-file")
        try:
            env_file = argv[index + 1]
        except IndexError:
            parser.error("--env-file needs a path")
        del argv[index : index + 2]
    args = parser.parse_args(argv)
    if env_file:
        _load_env_file(env_file)

    try:
        return args.func(args)
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
