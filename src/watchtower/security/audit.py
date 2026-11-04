"""Audit logging (proposal sections 13, 16 and 18).

Every administrative action, camera-viewing session, evidence access and incident
transition is recorded here. Details are sanitised before they are written, so an
exception message that happens to contain an RTSP URL cannot leak a password into the
audit trail.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from ..models import AuditLog
from .rbac import Principal
from .secrets import REDACTED_PLACEHOLDER, key_is_secret, redact

# Actions that must appear in the audit trail even when they fail (section 18:
# "audit-log completeness").
SENSITIVE_ACTIONS = frozenset(
    {
        "auth.login",
        "auth.login_failed",
        "auth.logout",
        "auth.refresh_reuse",
        "camera.register",
        "camera.update",
        "camera.disable",
        "camera.connection_test",
        "camera.secret.rotate",
        "camera.live_view.start",
        "camera.live_view.stop",
        "incident.create",
        "incident.assign",
        "incident.escalate",
        "incident.resolve",
        "evidence.view",
        "evidence.export",
        "evidence.delete",
        "admin.user.create",
        "admin.role.grant",
        "admin.policy.update",
        # Both are attempts to take somebody's access away or take its place, so a refused one is
        # the record a reviewer is looking for.
        "admin.user.password_reset",
        "admin.device.revoke",
        # Changing a password from inside a live session replaces that person's credentials. A
        # refusal means somebody holding the session did not know the password they were asked
        # for, which is the one row that turns a stolen cookie into visible evidence.
        "auth.password_change",
    }
)


def sanitize(value: Any) -> Any:
    """Recursively redact credential material from anything destined for an audit row."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, dict):
        return {
            str(key): REDACTED_PLACEHOLDER if key_is_secret(key) else sanitize(item)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize(item) for item in value]
    if isinstance(value, (int, float, bool, type(None))):
        return value
    return redact(str(value))


def record(
    session: Session,
    *,
    principal: Principal | None,
    action: str,
    object_type: str | None = None,
    object_id: str | None = None,
    details: dict[str, Any] | None = None,
    outcome: str = "success",
    source_ip: str | None = None,
) -> AuditLog:
    row = AuditLog(
        actor_id=principal.user_id if principal else None,
        actor_username=principal.username if principal else None,
        action=action,
        object_type=object_type,
        object_id=str(object_id) if object_id is not None else None,
        details=sanitize(details or {}),
        outcome=outcome,
        source_ip=source_ip,
    )
    session.add(row)
    if outcome != "success" and action in SENSITIVE_ACTIONS:
        # A route that answers a failed attempt by raising never reaches get_db's commit, so the
        # request session rolls back and the record the trail promises would vanish. The audit row
        # is a fact about the attempt, not part of the business transaction being rejected.
        session.commit()
    return row
