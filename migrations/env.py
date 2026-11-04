"""Alembic environment for AFIT WATCH TOWER.

The database URL is taken from WATCHTOWER_DATABASE_URL and must be PostgreSQL (proposal
section 8.1). There is deliberately no hard-coded fallback: a migration against the wrong
database is worse than a migration that refuses to start.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from watchtower.config import load_settings  # noqa: E402
from watchtower.models import Base  # noqa: E402

# The personnel-mobile tables live in a separate metadata module but share the `Base` of the
# monitoring schema, so importing it here is what makes `alembic revision --autogenerate`
# see all ten extra tables. Without this line a migration silently omits them.
from watchtower.mobile import models as _mobile_models  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata

POSTGRES_SCHEMES = ("postgresql://", "postgresql+psycopg://")


def _database_url() -> str:
    try:
        settings = load_settings(dict(os.environ))
    except Exception as exc:  # ConfigError covers both missing and non-PostgreSQL URLs
        raise SystemExit(f"refusing to migrate: {exc}") from exc
    url = settings.database_url
    if not url.startswith(POSTGRES_SCHEMES):
        raise SystemExit(f"refusing to migrate: {url!r} is not a PostgreSQL URL.")
    return url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        render_as_batch=False,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()
    connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
