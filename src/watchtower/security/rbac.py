"""Role-based access control (proposal section 14).

A role grant may be scoped to a camera group. An unscoped grant applies institution-wide,
so the same table expresses both "institutional technical operator" and "operator for the
Main Gate group only".

Administrative rights and video-viewing rights are deliberately separate permissions
(`camera.configure` vs `camera.view_live`), which is what lets an auditor review records
without being able to see or change a camera.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Camera, Permission, Role, RolePermission, User, UserRole

# fmt: off
PERMISSIONS: dict[str, str] = {
    "camera.register":     "Add a new camera to the registry",
    "camera.configure":    "Edit camera connection settings and trigger connection tests",
    "camera.disable":      "Disable a camera and stop its managed stream",
    "camera.view_live":    "Watch a live browser feed",
    "camera.list":         "See camera records and health state",
    "health.view":         "Inspect camera-health history",
    "event.view":          "See candidate detection events",
    "event.review":        "Acknowledge, dismiss or escalate a candidate event",
    "incident.view":       "See incident records",
    "incident.create":     "Raise an incident manually",
    "incident.acknowledge": "Accept responsibility for responding to an incident",
    "incident.assign":     "Assign or reassign an incident",
    "incident.escalate":   "Escalate an incident to other personnel",
    "incident.resolve":    "Resolve or close an incident and record the outcome",
    "evidence.view":       "Open evidence attached to a permitted incident",
    "evidence.export":     "Export evidence",
    "report.operational":  "Generate operational reports",
    "admin.users":         "Create and manage users and role grants",
    "admin.policies":      "Change monitoring, notification and retention policies",
    "audit.view":          "Read the audit log",
}
# fmt: on

ROLE_DEFINITIONS: dict[str, dict] = {
    "system_administrator": {
        "name": "System Administrator",
        "description": "Manages users, permissions, application configuration and system settings.",
        "is_administrative": True,
        "permissions": [
            "camera.register", "camera.configure", "camera.disable", "camera.list",
            "health.view", "event.view", "incident.view", "report.operational",
            "admin.users", "admin.policies", "audit.view",
        ],
    },
    "security_supervisor": {
        "name": "Security Supervisor",
        "description": "Oversees cameras, incident assignment, escalations and operational reports.",
        "is_administrative": False,
        "permissions": [
            "camera.list", "camera.view_live", "health.view", "event.view", "event.review",
            "incident.view", "incident.create", "incident.acknowledge", "incident.assign",
            "incident.escalate", "incident.resolve", "evidence.view", "evidence.export",
            "report.operational",
        ],
    },
    "security_operator": {
        "name": "Security Operator",
        "description": "Monitors assigned cameras, reviews alerts and records incident actions.",
        "is_administrative": False,
        "permissions": [
            "camera.list", "camera.view_live", "event.view", "event.review",
            "incident.view", "incident.create", "incident.acknowledge", "evidence.view",
        ],
    },
    "technical_operator": {
        "name": "Technical Operator",
        "description": "Registers cameras, verifies connectivity and manages camera health.",
        "is_administrative": False,
        "permissions": [
            "camera.register", "camera.configure", "camera.disable", "camera.list",
            "camera.view_live", "health.view",
        ],
    },
    "auditor_read_only": {
        "name": "Auditor / Read-Only Reviewer",
        "description": "Reviews permitted records, reports and audit history.",
        "is_administrative": False,
        "permissions": [
            "camera.list", "health.view", "event.view", "incident.view",
            "report.operational", "audit.view",
        ],
    },
}


@dataclass(slots=True)
class Grant:
    permission: str
    camera_group_id: int | None


@dataclass(slots=True)
class Principal:
    """The authenticated caller plus its resolved permissions."""

    user_id: int
    username: str
    display_name: str
    grants: list[Grant] = field(default_factory=list)
    is_administrative: bool = False

    def permissions(self) -> set[str]:
        return {grant.permission for grant in self.grants}

    def allows(self, permission: str) -> bool:
        return any(grant.permission == permission for grant in self.grants)

    def camera_scope(self, permission: str) -> set[int] | None:
        """Group ids this permission is limited to; None means institution-wide."""
        scoped = {
            grant.camera_group_id
            for grant in self.grants
            if grant.permission == permission
        }
        return None if None in scoped else scoped


def resolve_principal(session: Session, user: User) -> Principal:
    """Flatten this user's role grants into an effective permission set."""
    grants: list[Grant] = []
    is_admin = False
    for assignment in session.scalars(
        select(UserRole).where(UserRole.user_id == user.id)
    ).all():
        role = session.get(Role, assignment.role_id)
        if role is None:
            continue
        is_admin = is_admin or role.is_administrative
        permission_ids = session.scalars(
            select(RolePermission.permission_id).where(RolePermission.role_id == role.id)
        ).all()
        if not permission_ids:
            continue
        for code in session.scalars(
            select(Permission.code).where(Permission.id.in_(permission_ids))
        ).all():
            grants.append(Grant(code, assignment.camera_group_id))

    return Principal(
        user_id=user.id,
        username=user.username,
        display_name=user.display_name,
        grants=grants,
        is_administrative=is_admin,
    )


def can_view_camera(principal: Principal, permission: str, camera: Camera) -> bool:
    scope = principal.camera_scope(permission)
    if scope is None:
        return True
    if camera.camera_group_id is None:
        return False
    return camera.camera_group_id in scope


def filter_cameras_by_permission(principal: Principal, permission: str, cameras):
    scope = principal.camera_scope(permission)
    if scope is None:
        return list(cameras)
    return [camera for camera in cameras if camera.camera_group_id in scope]


def bootstrap_access_control(session: Session) -> None:
    """Create the permission and role catalogue from the definitions above.

    Idempotent, and run from the CLI rather than at import time so an accidental process
    start cannot silently change access control.
    """
    for code, description in PERMISSIONS.items():
        if not session.scalar(select(Permission.id).where(Permission.code == code)):
            session.add(Permission(code=code, description=description))
    # The ids only exist after this flush, so the map is read back here rather than taken
    # from the objects while they are still unassigned.
    session.flush()
    permission_ids = {
        code: pid for pid, code in session.execute(select(Permission.id, Permission.code)).all()
    }

    for role_code, definition in ROLE_DEFINITIONS.items():
        role = session.scalar(select(Role).where(Role.code == role_code))
        if role is None:
            role = Role(
                code=role_code,
                name=definition["name"],
                description=definition["description"],
                is_administrative=definition["is_administrative"],
            )
            session.add(role)
            session.flush()
        else:
            role.name = definition["name"]
            role.description = definition["description"]
            role.is_administrative = definition["is_administrative"]

        wanted = set(definition["permissions"])
        current_ids = session.scalars(
            select(RolePermission.permission_id).where(RolePermission.role_id == role.id)
        ).all()
        current = (
            set(
                session.scalars(
                    select(Permission.code).where(Permission.id.in_(current_ids))
                ).all()
            )
            if current_ids
            else set()
        )

        for code in wanted - current:
            session.add(
                RolePermission(role_id=role.id, permission_id=permission_ids[code])
            )
        for code in current - wanted:
            session.execute(
                RolePermission.__table__.delete().where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_id == permission_ids[code],
                )
            )
    session.flush()
