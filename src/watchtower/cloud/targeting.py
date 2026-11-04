"""Who receives an alert, computed rather than assumed.

The mobile proposal is explicit that a push is not a broadcast. This module applies the five
filters in contract section 10 in order, and the reason a person was *not* paged is recorded,
because "nobody was notified" and "somebody was suppressed" are different facts an investigator
needs to tell apart.

Scope is the console's scope: the same `can_view_camera()` the web dashboard uses. A duty
officer granted one camera group receives nothing for a camera outside it, on a phone or
anywhere else, because two different authorisation rules for one estate is how an accident
gets reported as a policy.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..mobile.models import PersonnelPreference
from ..models import Camera, Severity, User
from ..security.rbac import can_view_camera, resolve_principal

SEVERITY_RANK = {
    Severity.LOW.value: 0,
    Severity.MEDIUM.value: 1,
    Severity.HIGH.value: 2,
    Severity.CRITICAL.value: 3,
}

# Contract 10.5. The duty roster, not a distribution list: low reaches the role that owns the
# camera, medium and high reach the people who can act on it, critical additionally reaches the
# role responsible for the estate - subject to the action filter below, which is why the
# administrative half of a critical page arrives through escalation rather than the first send.
ROLES_BY_SEVERITY = {
    Severity.CRITICAL.value: ("security_operator", "security_supervisor", "system_administrator"),
    Severity.HIGH.value: ("security_operator", "security_supervisor"),
    Severity.MEDIUM.value: ("security_operator", "security_supervisor"),
    Severity.LOW.value: ("security_operator",),
}
HEALTH_ROLES = ("technical_operator", "security_supervisor")

# The permission an alert is *read* under, chosen by the family its kind starts with. A
# camera-health alert is a health record, not an incident: the technical operator it exists to
# page holds `health.view` and holds no `incident.view`, so asking the incident permission here
# would silence every hardware alert in the estate.
PERMISSION_BY_FAMILY = {
    "event": "event.view",
    "incident": "incident.view",
    "camera": "health.view",
}
DEFAULT_PERMISSION = "incident.view"

KIND_EVENT = "event.new"
KIND_HEALTH = "camera.health"


@dataclass(slots=True)
class AlertIntent:
    """One alert, as the cloud sees it after ingest."""

    kind: str
    severity: str
    title: str
    body: str
    incident_id: int | None = None
    camera_id: UUID | None = None
    event_id: int | None = None
    requires_action: bool = True
    data: dict[str, str] = field(default_factory=dict)
    # Set by the escalation worker: page a wider role than the severity alone would reach.
    role_override: tuple[str, ...] | None = None
    # `""` for the first send, `escalated-1`, `escalated-2`... for the re-pages after it. The
    # stage is part of the dedupe key so an escalation writes a new row instead of colliding
    # with the alert it is escalating, and so a worker that runs twice cannot escalate twice.
    stage: str = ""

    @property
    def rank(self) -> int:
        return SEVERITY_RANK.get(self.severity, 1)

    def roles_for(self, wanted_roles: set[str]) -> set[str]:
        return set(self.role_override) if self.role_override else wanted_roles


@dataclass(slots=True)
class Target:
    user: User
    deliver: bool
    reason: str | None = None

    @classmethod
    def suppressed(cls, user: User, reason: str) -> Target:
        return cls(user=user, deliver=False, reason=reason)


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _role_codes(session: Session, user_id: int) -> set[str]:
    from ..models import Role, UserRole

    rows = session.execute(
        select(UserRole.role_id).where(UserRole.user_id == user_id)
    ).all()
    codes: set[str] = set()
    for (role_id,) in rows:
        code = session.scalar(select(Role.code).where(Role.id == role_id))
        if code:
            codes.add(code)
    return codes


def forced_reason(settings, intent: AlertIntent) -> bool:
    """A mandatory alert cannot be silenced by the individual who receives it."""
    forced = set(settings.forced_alerts)
    return intent.severity in forced or intent.kind in forced


def _within_quiet_hours(quiet: dict[str, Any], now: dt.datetime) -> bool:
    if not isinstance(quiet, dict) or not quiet.get("enabled"):
        return False
    start = _minutes(quiet.get("start"))
    end = _minutes(quiet.get("end"))
    if start is None or end is None:
        return False
    current = now.hour * 60 + now.minute
    if start <= end:
        return start <= current < end
    return current >= start or current < end  # window crosses midnight


def quiet_hours_active(quiet: Any, *, now: dt.datetime | None = None) -> bool:
    """Whether an enabled quiet-hours window covers this instant.

    The clock is the delivery worker's clock: `resolve_recipients()` compares the window against
    `datetime.now(UTC)`, so a diagnostic answered in the handset's own zone would describe a
    silence that the sender does not apply.
    """
    return _within_quiet_hours(
        quiet if isinstance(quiet, dict) else {}, now or dt.datetime.now(dt.UTC)
    )


def _minutes(value: object) -> int | None:
    text = str(value or "")
    parts = text.split(":")
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        return None
    hour, minute = int(parts[0]), int(parts[1])
    if hour > 23 or minute > 59:
        return None
    return hour * 60 + minute


def preferences_for(session: Session, user_id: int) -> PersonnelPreference | None:
    return session.scalar(
        select(PersonnelPreference).where(PersonnelPreference.user_id == user_id)
    )


def apply_preferences(
    settings, intent: AlertIntent, preference: PersonnelPreference | None, now: dt.datetime
) -> tuple[bool, str | None]:
    """Return (deliver, suppression_reason). Mandatory alerts ignore the individual's toggles."""
    if forced_reason(settings, intent):
        return True, None
    if preference is None:
        return True, None

    floor = SEVERITY_RANK.get(preference.min_severity, 0)
    if intent.rank < floor:
        return False, f"below_min_severity:{preference.min_severity}"

    kinds = preference.kinds if isinstance(preference.kinds, dict) else {}
    if kinds.get(intent.kind) is False:
        return False, f"kind_disabled:{intent.kind}"

    if _within_quiet_hours(preference.quiet_hours, now):
        return False, "quiet_hours"
    return True, None


def _visible_camera(session: Session, intent: AlertIntent) -> Camera | None:
    if intent.camera_id is None:
        return None
    return session.get(Camera, intent.camera_id)


def resolve_recipients(
    session: Session,
    settings,
    intent: AlertIntent,
    *,
    now: dt.datetime | None = None,
    exclude_user_ids: set[int] | None = None,
) -> list[Target]:
    """Every filter in contract section 10, in order, with the reason for each exclusion."""
    now = now or dt.datetime.now(dt.UTC)
    camera = _visible_camera(session, intent)
    permission = PERMISSION_BY_FAMILY.get(intent.kind.split(".", 1)[0], DEFAULT_PERMISSION)
    wanted_roles = set(
        intent.roles_for(
            HEALTH_ROLES
            if intent.kind.startswith("camera.")
            else ROLES_BY_SEVERITY.get(intent.severity, ROLES_BY_SEVERITY[Severity.MEDIUM.value])
        )
    )
    excluded = exclude_user_ids or set()

    targets: list[Target] = []
    for user in session.scalars(select(User).where(User.is_active.is_(True))).all():
        if user.id in excluded:
            continue
        principal = resolve_principal(session, user)
        if not principal.allows(permission):
            continue
        if intent.requires_action and not principal.allows("incident.acknowledge"):
            continue
        if camera is not None and not can_view_camera(principal, permission, camera):
            # Not a suppression - this person was never a recipient. Recording a suppressed row
            # for an out-of-scope user would say "we chose not to page you" when the truth is
            # "you are not responsible for this camera".
            continue
        if not (_role_codes(session, user.id) & wanted_roles):
            continue

        deliver, reason = apply_preferences(settings, intent, preferences_for(session, user.id), now)
        targets.append(Target(user=user, deliver=deliver, reason=reason))
    return targets
