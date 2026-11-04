"""The access-control catalogue itself (proposal section 14).

`bootstrap_access_control()` is the only supported way to build roles/permissions, and the
CLI calls it on a fresh database. These tests use a dedicated session over an empty schema so
the catalogue really is built from nothing.
"""

from __future__ import annotations

import pytest
from sqlalchemy import func, select

from watchtower import models as wt_models
from watchtower.security.rbac import (
    PERMISSIONS,
    ROLE_DEFINITIONS,
    bootstrap_access_control,
)


@pytest.fixture
def clean_session(session_factory, engine):
    """A session over a database with tables but no rows."""
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def _count(session, model) -> int:
    return session.scalar(select(func.count()).select_from(model)) or 0


def test_bootstrap_creates_the_five_documented_roles(clean_session):
    bootstrap_access_control(clean_session)
    clean_session.commit()

    codes = set(
        clean_session.scalars(select(wt_models.Role.code).order_by(wt_models.Role.code)).all()
    )
    assert codes == set(ROLE_DEFINITIONS)
    assert _count(clean_session, wt_models.Permission) == len(PERMISSIONS)


def test_video_rights_are_separate_from_administrative_rights(clean_session):
    """Section 14: watching a stream and configuring a camera are different grants."""
    bootstrap_access_control(clean_session)
    clean_session.commit()

    auditor = ROLE_DEFINITIONS["auditor_read_only"]["permissions"]
    assert "camera.view_live" not in auditor
    assert "camera.configure" not in auditor
    assert "camera.register" not in auditor

    operator = ROLE_DEFINITIONS["security_operator"]["permissions"]
    assert "camera.view_live" in operator
    assert "camera.configure" not in operator
    assert "camera.register" not in operator

    admin = ROLE_DEFINITIONS["system_administrator"]["permissions"]
    assert "admin.users" in admin
    assert "audit.view" in admin
    # an administrator is not implicitly allowed to watch live video
    assert "camera.view_live" not in admin


def test_bootstrap_on_an_empty_database_wires_every_role_to_its_permissions(clean_session):
    """Found while writing this suite: `bootstrap_access_control()` used to read
    `permission.id` before flushing, so every `role_permissions` row got permission_id 0 and
    bootstrapping a fresh database raised IntegrityError. `security/rbac.py` now flushes
    first and reads the ids back, so this asserts the promised catalogue.
    """
    bootstrap_access_control(clean_session)
    clean_session.commit()

    expected = sum(len(definition["permissions"]) for definition in ROLE_DEFINITIONS.values())
    granted = _count(clean_session, wt_models.RolePermission)
    assert granted == expected

    supervisor_role = clean_session.scalar(
        select(wt_models.Role).where(wt_models.Role.code == "security_supervisor")
    )
    granted_codes = set(
        clean_session.scalars(
            select(wt_models.Permission.code)
            .join(wt_models.RolePermission, wt_models.RolePermission.permission_id == wt_models.Permission.id)
            .where(wt_models.RolePermission.role_id == supervisor_role.id)
        ).all()
    )
    assert granted_codes == set(ROLE_DEFINITIONS["security_supervisor"]["permissions"])


def test_bootstrap_is_idempotent(clean_session):
    """Section 14's catalogue is declarative; re-running it must not duplicate grants."""
    bootstrap_access_control(clean_session)
    clean_session.commit()
    first = _count(clean_session, wt_models.RolePermission)

    bootstrap_access_control(clean_session)
    clean_session.commit()
    assert _count(clean_session, wt_models.RolePermission) == first
    assert _count(clean_session, wt_models.Permission) == len(PERMISSIONS)
    assert _count(clean_session, wt_models.Role) == len(ROLE_DEFINITIONS)
