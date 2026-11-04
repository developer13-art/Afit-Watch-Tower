"""The person's own profile and alert preferences (contract section 8).

Preferences say what an individual may silence. They never say what the service must send: the
mandatory set comes from configuration and is returned in every response as `forced`, so the app
can grey those toggles out with an explanation instead of letting someone believe they silenced
a duty alert.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from ...mobile.models import PersonnelPreference
from ...models import Severity, User
from ...security.audit import record as audit_record
from .. import devices as device_store
from ..config import CloudSettings
from ..deps import Caller, get_db, get_settings, require_password_changed
from ..errors import CloudError
from ..targeting import preferences_for
from ..views import user_view

router = APIRouter(prefix="/profile", tags=["profile"])

SEVERITIES = {item.value for item in Severity}
SOUNDS = frozenset({"default", "alarm", "silent"})
KNOWN_KINDS = frozenset(
    {
        "incident.created",
        "incident.assigned",
        "incident.escalated",
        "incident.resolved",
        "camera.health",
        "event.new",
    }
)


class QuietHours(BaseModel):
    enabled: bool = False
    start: str = Field(default="22:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")
    end: str = Field(default="06:00", pattern=r"^([01]\d|2[0-3]):[0-5]\d$")


class PreferenceBody(BaseModel):
    min_severity: str = Severity.LOW.value
    kinds: dict[str, bool] = Field(default_factory=dict)
    quiet_hours: QuietHours = Field(default_factory=QuietHours)
    sound: str = "default"

    @field_validator("min_severity")
    @classmethod
    def _severity_known(cls, value: str) -> str:
        if value not in SEVERITIES:
            raise ValueError("min_severity must be low, medium, high or critical")
        return value

    @field_validator("sound")
    @classmethod
    def _sound_known(cls, value: str) -> str:
        if value not in SOUNDS:
            raise ValueError(f"sound must be one of {', '.join(sorted(SOUNDS))}")
        return value

    @field_validator("kinds")
    @classmethod
    def _kinds_known(cls, value: dict[str, bool]) -> dict[str, bool]:
        unknown = sorted(set(value) - KNOWN_KINDS)
        if unknown:
            raise ValueError(f"unknown alert kinds: {', '.join(unknown)}")
        return value


def _preference_body(
    preference: PersonnelPreference | None, settings: CloudSettings
) -> dict[str, Any]:
    return {
        "min_severity": preference.min_severity if preference else Severity.LOW.value,
        "kinds": dict(preference.kinds) if preference and preference.kinds else {},
        "quiet_hours": (
            dict(preference.quiet_hours)
            if preference and preference.quiet_hours
            else {"enabled": False, "start": "22:00", "end": "06:00"}
        ),
        "sound": preference.sound if preference else "default",
        # The toggles the individual does not own. Sent with every response so the UI never has
        # to guess which switch is decorative.
        "forced": list(settings.forced_alerts),
        "updated_at": (
            preference.updated_at.isoformat() if preference and preference.updated_at else None
        ),
    }


@router.get("")
def profile(
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_password_changed),
):
    user = session.get(User, caller.user_id)
    if user is None:
        raise CloudError("invalid_credentials", "This account no longer exists.", status_code=401)
    preference = preferences_for(session, user.id)
    return {
        **user_view(session, user, caller.principal),
        "roles_with_descriptions": _roles(session, user.id),
        "devices": device_store.list_for_user(session, user.id),
        "preferences": _preference_body(preference, settings),
    }


def _roles(session: Session, user_id: int) -> list[dict[str, Any]]:
    from ...models import Role, UserRole

    rows = session.execute(
        select(Role.code, Role.name, Role.description)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.code)
    ).all()
    return [
        {"code": code, "name": name, "description": description} for code, name, description in rows
    ]


@router.get("/preferences")
def get_preferences(
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_password_changed),
):
    return _preference_body(preferences_for(session, caller.user_id), settings)


@router.put("/preferences")
def put_preferences(
    body: PreferenceBody,
    session: Session = Depends(get_db),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_password_changed),
):
    """Replace the caller's preferences. Silence is a preference, not a right."""
    preference = preferences_for(session, caller.user_id)
    if preference is None:
        preference = PersonnelPreference(user_id=caller.user_id)
        session.add(preference)
    preference.min_severity = body.min_severity
    preference.kinds = dict(body.kinds)
    preference.quiet_hours = body.quiet_hours.model_dump()
    preference.sound = body.sound
    session.flush()
    audit_record(
        session,
        principal=caller.principal,
        action="notification.preference.update",
        object_type="personnel_preference",
        object_id=str(preference.id),
        details={
            "min_severity": preference.min_severity,
            "kinds_disabled": sorted(kind for kind, on in body.kinds.items() if not on),
            "quiet_hours": preference.quiet_hours,
        },
        source_ip=caller.source_ip,
    )
    return _preference_body(preference, settings)
