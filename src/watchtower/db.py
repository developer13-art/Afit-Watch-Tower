"""Database engine and session plumbing."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


class DatabaseUrlHolder(Protocol):
    """Anything that can say which database to bind to.

    `Settings` and the cloud service's `CloudSettings` both satisfy it, and both must get the same
    pool policy, UTC-pinned server sessions and pre-ping behaviour. A second copy of
    `build_engine` in the cloud would be a second set of numbers to drift.
    """

    database_url: str


def build_engine(settings: DatabaseUrlHolder) -> Engine:
    engine = create_engine(
        settings.database_url,
        pool_pre_ping=True,
        # A camera worker never shares a connection with the API process; the pool is
        # sized for the API and background services on one host (section 17).
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
    )

    if engine.dialect.name == "postgresql":

        @event.listens_for(engine, "connect")
        def _timezone(dbapi_connection, _record):  # pragma: no cover - driver specific
            # All timestamps are written with explicit zone info; this pins the server
            # session so that `func.now()` agrees with the application clock.
            cursor = dbapi_connection.cursor()
            cursor.execute("SET timezone = 'UTC'")
            cursor.close()

    return engine


def build_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)


@contextmanager
def session_scope(session_factory: sessionmaker[Session]) -> Iterator[Session]:
    session = session_factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
