"""Administrator actions the phone app needs (contract section 2.3 and section 6).

These endpoints exist so a supervisor on a handset can onboard a colleague, retire a lost phone
and hand out a fresh password without walking to the monitoring PC. They are the same
authorisation model as the console: `admin.users` is read from the database on every request, so a
grant removed at the console stops working on the next call rather than when the token expires.

One rule is specific to this service and is the reason this module is written separately from the
console's admin router: a temporary password is generated here, returned exactly once in the
response body, and never stored, logged, or audited. The account is created with
`must_change_password` set, so the value is only ever a key to the change-password screen. Nobody
else can read it back - not from this API, and not from the database.
"""

from __future__ import annotations

import datetime as dt
import logging
import secrets

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ...models import (
    Camera,
    CameraGroup,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
    utcnow,
)
from ...mobile.models import MobileDevice, PushState
from ...security.audit import record as audit_record
from ...security.passwords import MIN_PASSWORD_LENGTH, hash_password
from ...security.rbac import ROLE_DEFINITIONS, resolve_principal
from ...security.secrets import fingerprint
from .. import devices as device_store
from ..config import CloudSettings
from ..deps import Caller, CloudContainer, get_container, get_db, get_settings, require_permission
from ..errors import CloudError
from ..ratelimit import enforce
from ..views import timestamp

LOGGER = logging.getLogger("watchtower.cloud.admin")

router = APIRouter(prefix="/admin", tags=["admin"])

USERNAME_PATTERN = r"^[a-z0-9._-]+$"

# Characters an operator can read aloud over the phone without a second meaning. The ambiguous
# ones (I/l/1, O/0) are excluded because the password is spoken, not copy-pasted.
_UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
_LOWER = "abcdefghijkmnopqrstuvwxyz"
_DIGIT = "23456789"
_SYMBOL = "!?@#$%&*+-="
# Four classes, then a random fill: the account policy is length-based, but a password that has
# one character of each class will not be rejected by a handset's own strength meter.
TEMPORARY_PASSWORD_LENGTH = max(MIN_PASSWORD_LENGTH + 4, 16)


def _new_temporary_password() -> str:
    pool = _UPPER + _LOWER + _DIGIT + _SYMBOL
    chars = [
        secrets.choice(_UPPER),
        secrets.choice(_LOWER),
        secrets.choice(_DIGIT),
        secrets.choice(_SYMBOL),
    ]
    chars += [secrets.choice(pool) for _ in range(TEMPORARY_PASSWORD_LENGTH - len(chars))]
    # `secrets.SystemRandom.shuffle`, not `random.shuffle`: the order is part of the secret.
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


class PersonnelCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=USERNAME_PATTERN)
    display_name: str = Field(min_length=2, max_length=128)
    email: str | None = Field(default=None, max_length=256)
    phone: str | None = Field(default=None, max_length=32)
    password: str | None = Field(
        default=None, min_length=MIN_PASSWORD_LENGTH, max_length=256,
        description="Omit to have the service generate a temporary password.",
    )
    role_code: str | None = Field(default=None, max_length=48)
    camera_group_id: int | None = None
    force_password_change: bool | None = None


class RoleGrantBody(BaseModel):
    role_code: str = Field(min_length=2, max_length=48)
    camera_group_id: int | None = None


class ActiveBody(BaseModel):
    is_active: bool


def _rate_limit(container: CloudContainer, settings: CloudSettings, caller: Caller) -> None:
    enforce(
        container.limiter,
        "admin-action",
        str(caller.user_id),
        limit=settings.action_attempts_per_minute,
        window_seconds=60,
    )


def _role_by_code(session: Session, code: str) -> Role:
    role = session.scalar(select(Role).where(Role.code == code))
    if role is None:
        raise CloudError(
            "unknown_role",
            f"No role called {code!r} is defined. Call GET /api/v1/admin/roles first.",
            status_code=422,
        )
    return role


def _group_or_none(session: Session, group_id: int | None) -> CameraGroup | None:
    if group_id is None:
        return None
    group = session.get(CameraGroup, group_id)
    if group is None:
        raise CloudError("unknown_camera_group", "No such camera group.", status_code=422)
    return group


def _grants(session: Session, user_id: int) -> list[dict]:
    rows = session.execute(
        select(UserRole, Role.code, CameraGroup.name)
        .join(Role, Role.id == UserRole.role_id)
        .outerjoin(CameraGroup, CameraGroup.id == UserRole.camera_group_id)
        .where(UserRole.user_id == user_id)
        .order_by(Role.code)
    ).all()
    return [
        {
            "role_code": code,
            "camera_group_id": grant.camera_group_id,
            "camera_group_name": group_name,
            "scope": "institution-wide" if grant.camera_group_id is None else (group_name or str(
                grant.camera_group_id
            )),
        }
        for grant, code, group_name in rows
    ]


def _device_counts(session: Session, user_ids: list[int]) -> dict[int, tuple[int, int]]:
    """`{user_id: (total, push_capable)}` in one query, so a list page stays cheap."""
    if not user_ids:
        return {}
    rows = session.execute(
        select(
            MobileDevice.user_id,
            func.count(),
            func.count().filter(
                MobileDevice.push_state == PushState.ACTIVE.value,
                MobileDevice.push_token_ciphertext.is_not(None),
                MobileDevice.deactivated_at.is_(None),
            ),
        )
        .where(MobileDevice.user_id.in_(user_ids))
        .group_by(MobileDevice.user_id)
    ).all()
    return {int(user_id): (int(total), int(capable)) for user_id, total, capable in rows}


def _personnel_row(session: Session, user: User, *, devices: tuple[int, int]) -> dict:
    now = utcnow()
    return {
        "id": user.id,
        "username": user.username,
        "display_name": user.display_name,
        "email": user.email,
        "phone": user.phone,
        "is_active": bool(user.is_active),
        "must_change_password": bool(user.must_change_password),
        "locked_until": timestamp(user.locked_until),
        "is_locked": bool(user.locked_until and _as_utc(user.locked_until) > now),
        "failed_login_count": int(user.failed_login_count or 0),
        "last_login_at": timestamp(user.last_login_at),
        "password_changed_at": timestamp(user.password_changed_at),
        "devices": {"registered": devices[0], "push_capable": devices[1]},
        "grants": _grants(session, user.id),
    }


def _as_utc(value: dt.datetime) -> dt.datetime:
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _personnel_or_404(session: Session, user_id: int) -> User:
    user = session.get(User, user_id)
    if user is None:
        raise CloudError("not_found", "No such personnel account.", status_code=404)
    return user


@router.get("/personnel")
def list_personnel(
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("admin.users")),
    q: str | None = Query(default=None, max_length=64),
    role_code: str | None = Query(default=None, max_length=48),
    active: bool | None = None,
    limit: int | None = Query(default=None, ge=1, le=200),
):
    """Accounts, their grants and how many handsets could be reached.

    Search is by name or username because a supervisor at a gate needs to find a person, not a
    primary key. The phone number is included: it is the number the temporary password is read out
    to, and only an account with `admin.users` can see this page at all.
    """
    statement = select(User).order_by(User.display_name, User.username)
    if q:
        needle = f"%{q.strip().lower()}%"
        statement = statement.where(
            or_(
                func.lower(User.username).like(needle),
                func.lower(User.display_name).like(needle),
            )
        )
    if active is not None:
        statement = statement.where(User.is_active.is_(active))
    if role_code:
        scoped = select(UserRole.user_id).join(Role, Role.id == UserRole.role_id).where(
            Role.code == role_code
        )
        statement = statement.where(User.id.in_(scoped))
    row_count = min(limit or 100, 200)
    users = list(session.scalars(statement.limit(row_count)).all())
    counts = _device_counts(session, [user.id for user in users])
    return {
        "personnel": [
            _personnel_row(session, user, devices=counts.get(user.id, (0, 0))) for user in users
        ],
        "count": len(users),
    }


@router.post("/personnel", status_code=201)
def create_personnel(
    body: PersonnelCreate,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    """Create the account, grant the role, and return the password once.

    The username uniqueness check races the unique index on `users.username`. The index is the
    authority; this pre-check exists to answer a duplicate with a readable code rather than a
    database fault, so the path is deliberately not treated as a guarantee.
    """
    _rate_limit(container, settings, caller)
    if session.scalar(select(User.id).where(User.username == body.username)):
        raise CloudError(
            "duplicate_username", "That username is already taken.", status_code=409
        )
    role = _role_by_code(session, body.role_code) if body.role_code else None
    group = _group_or_none(session, body.camera_group_id) if body.camera_group_id else None
    if body.camera_group_id and role is None:
        raise CloudError(
            "role_required",
            "A camera group only means something alongside a role.",
            status_code=422,
        )

    generated = body.password is None
    password = _new_temporary_password() if generated else body.password
    # A hand-written password is normally a shared secret the administrator already told someone:
    # it stays an enforced change unless they say otherwise. A generated one always is.
    force_change = body.force_password_change if body.force_password_change is not None else True

    user = User(
        username=body.username,
        display_name=body.display_name,
        email=body.email,
        phone=body.phone,
        password_hash=hash_password(password),
        is_active=True,
        must_change_password=force_change,
        password_changed_at=utcnow(),
    )
    session.add(user)
    session.flush()
    if role is not None:
        session.add(
            UserRole(user_id=user.id, role_id=role.id, camera_group_id=group.id if group else None)
        )
        session.flush()

    audit_record(
        session,
        principal=caller.principal,
        action="admin.user.create",
        object_type="user",
        object_id=str(user.id),
        details={
            "username": user.username,
            "role": role.code if role else None,
            "camera_group_id": group.id if group else None,
            "password_source": "generated" if generated else "administrator",
            "force_password_change": force_change,
            "password_fingerprint": fingerprint(password),
        },
        source_ip=caller.source_ip,
    )
    principal = resolve_principal(session, user)
    return {
        "personnel": _personnel_row(session, user, devices=(0, 0)),
        "permissions": sorted(principal.permissions()),
        # Returned exactly once. There is no endpoint that reproduces this value, which is why
        # the account is created in the change-password state instead of with a known password.
        "temporary_password": password if generated else None,
        "password_was_generated": generated,
        "must_change_password": force_change,
        "handover_reminder": (
            "Read the password to the person over a channel they already trust. It cannot be "
            "retrieved after this response."
            if generated
            else None
        ),
    }


@router.get("/personnel/{user_id}")
def get_personnel(
    user_id: int,
    session: Session = Depends(get_db),
    _: Caller = Depends(require_permission("admin.users")),
):
    user = _personnel_or_404(session, user_id)
    counts = _device_counts(session, [user.id])
    return {
        "personnel": _personnel_row(session, user, devices=counts.get(user.id, (0, 0))),
        "devices": device_store.list_for_user(session, user.id),
    }


@router.get("/personnel/{user_id}/devices")
def personnel_devices(
    user_id: int,
    session: Session = Depends(get_db),
    _: Caller = Depends(require_permission("admin.users")),
):
    _personnel_or_404(session, user_id)
    return {"devices": device_store.list_for_user(session, user_id)}


@router.patch("/personnel/{user_id}")
def set_personnel_active(
    user_id: int,
    body: ActiveBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    """Enable or disable. Disabling also signs the account out everywhere, immediately.

    A disabled account whose refresh token is still valid would keep pulling fresh access tokens
    until the token aged out, which is not what "disabled" means to the person holding the phone.
    """
    _rate_limit(container, settings, caller)
    user = _personnel_or_404(session, user_id)
    if user.id == caller.user_id and not body.is_active:
        raise CloudError(
            "self_deactivation", "You cannot disable the account you are signed in with.",
            status_code=422,
        )
    user.is_active = body.is_active
    revoked = 0
    if not body.is_active:
        revoked = container.tokens.revoke_all_for_user(session, user.id)
        _retire_devices(session, user.id)
    session.flush()
    audit_record(
        session,
        principal=caller.principal,
        action="admin.user.activate" if body.is_active else "admin.user.deactivate",
        object_type="user",
        object_id=str(user.id),
        details={"sessions_revoked": revoked},
        source_ip=caller.source_ip,
    )
    return {"id": user.id, "is_active": user.is_active, "sessions_revoked": revoked}


def _retire_devices(session: Session, user_id: int) -> int:
    """Stop paging a disabled account, without deleting the history of what it was sent."""
    devices = session.scalars(
        select(MobileDevice).where(
            MobileDevice.user_id == user_id,
            MobileDevice.deactivated_at.is_(None),
        )
    ).all()
    for device in devices:
        device.push_state = PushState.REVOKED.value
        device.deactivated_at = utcnow()
        device.push_token_ciphertext = None
        device.push_token_key_id = None
        device.push_token_fingerprint = None
    session.flush()
    return len(devices)


@router.post("/personnel/{user_id}/reset-password")
def reset_password(
    user_id: int,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    """Issue a new temporary password and invalidate every other session for that account.

    This is the response to a lost handset, a colleague who has forgotten their password, and the
    suspicion that a password got around. The old password stops working here, in this transaction,
    rather than at the next sign-in attempt.
    """
    _rate_limit(container, settings, caller)
    user = _personnel_or_404(session, user_id)
    password = _new_temporary_password()
    user.password_hash = hash_password(password)
    user.must_change_password = True
    user.password_changed_at = utcnow()
    user.failed_login_count = 0
    user.locked_until = None
    session.flush()
    revoked = container.tokens.revoke_all_for_user(session, user.id)
    audit_record(
        session,
        principal=caller.principal,
        action="admin.user.password_reset",
        object_type="user",
        object_id=str(user.id),
        details={
            "target_username": user.username,
            "sessions_revoked": revoked,
            # The audit row records that a reset happened and which value it produced, without
            # being able to produce the value again.
            "password_fingerprint": fingerprint(password),
        },
        source_ip=caller.source_ip,
    )
    LOGGER.info(
        "temporary password issued for %s by %s (fingerprint %s)",
        user.username,
        caller.principal.username,
        fingerprint(password),
    )
    return {
        "id": user.id,
        "username": user.username,
        "temporary_password": password,
        "must_change_password": True,
        "sessions_revoked": revoked,
    }


@router.post("/personnel/{user_id}/unlock")
def unlock_account(
    user_id: int,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    user = _personnel_or_404(session, user_id)
    _rate_limit(container, settings, caller)
    was_locked = bool(user.locked_until and _as_utc(user.locked_until) > utcnow())
    user.locked_until = None
    user.failed_login_count = 0
    session.flush()
    audit_record(
        session,
        principal=caller.principal,
        action="admin.user.unlock",
        object_type="user",
        object_id=str(user.id),
        details={"was_locked": was_locked},
        source_ip=caller.source_ip,
    )
    return {"id": user.id, "unlocked": not was_locked, "was_locked": was_locked}


@router.post("/personnel/{user_id}/roles", status_code=201)
def grant_role(
    user_id: int,
    body: RoleGrantBody,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    _rate_limit(container, settings, caller)
    user = _personnel_or_404(session, user_id)
    role = _role_by_code(session, body.role_code)
    group = _group_or_none(session, body.camera_group_id)
    existing = session.scalar(
        select(UserRole).where(
            UserRole.user_id == user.id,
            UserRole.role_id == role.id,
            UserRole.camera_group_id.is_(body.camera_group_id),
        )
    )
    if existing is not None:
        raise CloudError(
            "already_granted",
            "This account already holds that role at that scope.",
            status_code=409,
        )
    session.add(UserRole(user_id=user.id, role_id=role.id, camera_group_id=group.id if group else None))
    session.flush()
    audit_record(
        session,
        principal=caller.principal,
        action="admin.role.grant",
        object_type="user",
        object_id=str(user.id),
        details={"role": role.code, "camera_group_id": body.camera_group_id},
        source_ip=caller.source_ip,
    )
    principal = resolve_principal(session, user)
    return {
        "granted": role.code,
        "camera_group_id": body.camera_group_id,
        "permissions": sorted(principal.permissions()),
        "camera_scope": "institution-wide" if principal.camera_scope("incident.view") is None
        else sorted(principal.camera_scope("incident.view")),
    }


@router.delete("/personnel/{user_id}/roles")
def revoke_role(
    user_id: int,
    role_code: str = Query(min_length=2, max_length=48),
    camera_group_id: int | None = None,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    """Remove a grant. Effective immediately, because permissions are not carried in the token."""
    _rate_limit(container, settings, caller)
    user = _personnel_or_404(session, user_id)
    role = _role_by_code(session, role_code)
    grant = session.scalar(
        select(UserRole).where(
            UserRole.user_id == user.id,
            UserRole.role_id == role.id,
            UserRole.camera_group_id.is_(camera_group_id),
        )
    )
    if grant is None:
        raise CloudError("not_found", "That role is not granted at that scope.", status_code=404)
    session.delete(grant)
    session.flush()
    audit_record(
        session,
        principal=caller.principal,
        action="admin.role.revoke",
        object_type="user",
        object_id=str(user.id),
        details={"role": role.code, "camera_group_id": camera_group_id},
        source_ip=caller.source_ip,
    )
    return {"revoked": role.code, "camera_group_id": camera_group_id}


@router.post("/devices/{device_id}/revoke", status_code=200)
def revoke_device(
    device_id: int,
    session: Session = Depends(get_db),
    container: CloudContainer = Depends(get_container),
    settings: CloudSettings = Depends(get_settings),
    caller: Caller = Depends(require_permission("admin.users")),
):
    """Retire one handset: stop paging it and sign its session out.

    The row survives with `push_state=revoked` and the sealed token destroyed. Keeping the row is
    what makes "which device was this alert sent to?" answerable in an incident review; the token
    is the part that must not survive a lost phone.
    """
    _rate_limit(container, settings, caller)
    device = session.get(MobileDevice, device_id)
    if device is None:
        raise CloudError("not_found", "No such registered device.", status_code=404)
    sessions_revoked = container.tokens.revoke_for_device(session, device.id)
    device_store.deactivate(
        session, user_id=device.user_id, installation_id=device.installation_id
    )
    audit_record(
        session,
        principal=caller.principal,
        action="admin.device.revoke",
        object_type="mobile_device",
        object_id=str(device.id),
        details={
            "owner_user_id": device.user_id,
            "installation_fingerprint": fingerprint(device.installation_id),
            "sessions_revoked": sessions_revoked,
        },
        source_ip=caller.source_ip,
    )
    return {
        "id": device.id,
        "push_state": device.push_state,
        "sessions_revoked": sessions_revoked,
        "revoked_at": timestamp(device.deactivated_at),
    }


@router.get("/roles")
def list_roles(
    session: Session = Depends(get_db),
    _: Caller = Depends(require_permission("admin.users")),
):
    """The roles an administrator may hand out, with the permissions each one carries.

    Read from the database, not from the code table, so the app lists what actually exists here
    rather than what this build of the software once knew about.
    """
    rows = session.scalars(select(Role).order_by(Role.code)).all()
    out = []
    for role in rows:
        definition = ROLE_DEFINITIONS.get(role.code, {})
        codes = session.execute(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == role.id)
            .order_by(Permission.code)
        ).all()
        out.append(
            {
                "code": role.code,
                "name": role.name,
                "description": role.description or definition.get("description"),
                "is_administrative": bool(role.is_administrative),
                "permissions": [code for (code,) in codes],
            }
        )
    return {"roles": out}


@router.get("/camera-groups")
def list_camera_groups(
    session: Session = Depends(get_db),
    _: Caller = Depends(require_permission("admin.policies")),
):
    """Group ids and names, for scoping a grant from a phone.

    This one asks for `admin.policies` rather than `admin.users`: a supervisor who may set which
    cameras a colleague can watch is not necessarily somebody who may create accounts.
    """
    rows = session.scalars(select(CameraGroup).order_by(CameraGroup.name)).all()
    camera_counts = dict(
        session.execute(
            select(Camera.camera_group_id, func.count()).group_by(Camera.camera_group_id)
        ).all()
    )
    return {
        "camera_groups": [
            {
                "id": group.id,
                "code": group.code,
                "name": group.name,
                "description": group.description,
                "camera_count": int(camera_counts.get(group.id, 0)),
            }
            for group in rows
        ]
    }
