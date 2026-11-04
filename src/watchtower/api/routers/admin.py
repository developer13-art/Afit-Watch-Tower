"""Administration and audit endpoints (sections 13, 14, 16, 18)."""

from __future__ import annotations

import datetime as dt
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..deps import Container, get_container, get_db, require_permission
from ...models import (
    AuditLog,
    Camera,
    CameraGroup,
    DetectionEvent,
    Incident,
    MonitoringPolicy,
    Notification,
    Permission,
    Role,
    RolePermission,
    User,
    UserRole,
)
from ...security.audit import record as audit_record
from ...security.passwords import hash_password
from ...security.rbac import PERMISSIONS, ROLE_DEFINITIONS, Principal, resolve_principal
from ...security.secrets import client_safe
from ...services.evidence import EvidenceStore

router = APIRouter(prefix="/api/admin", tags=["administration"])


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=64, pattern=r"^[a-z0-9._-]+$")
    display_name: str = Field(min_length=2, max_length=128)
    password: str = Field(min_length=12, max_length=256)
    email: str | None = Field(default=None, max_length=256)
    phone: str | None = Field(default=None, max_length=32)


class RoleGrant(BaseModel):
    role_code: str
    camera_group_id: int | None = None


class GroupCreate(BaseModel):
    code: str = Field(min_length=2, max_length=48)
    name: str = Field(min_length=2, max_length=128)
    description: str | None = None


class PolicyUpsert(BaseModel):
    code: str = Field(min_length=2, max_length=48)
    name: str = Field(min_length=2, max_length=128)
    enabled: bool = False
    detector_codes: list[str] = Field(default_factory=list)
    min_confidence: float = Field(default=0.55, ge=0.0, le=1.0)
    analysis_fps: float = Field(default=4.0, gt=0.0, le=30.0)
    zones: list[dict[str, Any]] = Field(default_factory=list)
    duplicate_window_seconds: int = Field(default=90, ge=5, le=3600)
    severity: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


def _utcnow() -> dt.datetime:
    return dt.datetime.now(dt.UTC)


@router.get("/users")
def list_users(
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.users")),
) -> list[dict]:
    out = []
    for user in session.scalars(select(User).order_by(User.username)).all():
        grants = session.scalars(select(UserRole).where(UserRole.user_id == user.id)).all()
        roles = []
        for grant in grants:
            role = session.get(Role, grant.role_id)
            roles.append(
                {
                    "role": role.code if role else None,
                    "camera_group_id": grant.camera_group_id,
                }
            )
        out.append(
            {
                "id": user.id,
                "username": user.username,
                "display_name": user.display_name,
                "email": user.email,
                "is_active": user.is_active,
                "locked": bool(user.locked_until and user.locked_until > _utcnow()),
                "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
                "roles": roles,
            }
        )
    return out


@router.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.users")),
) -> dict:
    if session.scalar(select(User.id).where(User.username == payload.username)):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail={"code": "duplicate_username", "message": "That username already exists."},
        )
    user = User(
        username=payload.username,
        display_name=payload.display_name,
        email=payload.email,
        phone=payload.phone,
        password_hash=hash_password(payload.password),
        is_active=True,
    )
    session.add(user)
    session.flush()
    audit_record(
        session,
        principal=principal,
        action="admin.user.create",
        object_type="user",
        object_id=str(user.id),
        details={"username": user.username},
    )
    return {"id": user.id, "username": user.username}


@router.post("/users/{user_id}/roles")
def grant_role(
    user_id: int,
    payload: RoleGrant,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.users")),
) -> dict:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such user.")
    role = session.scalar(select(Role).where(Role.code == payload.role_code))
    if role is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "unknown_role", "message": f"Unknown role {payload.role_code!r}."},
        )
    if payload.camera_group_id is not None and session.get(
        CameraGroup, payload.camera_group_id
    ) is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST, detail={"code": "unknown_group", "message": "Unknown camera group."}
        )
    existing = session.scalar(
        select(UserRole).where(
            UserRole.user_id == user_id,
            UserRole.role_id == role.id,
            UserRole.camera_group_id.is_(payload.camera_group_id)
            if payload.camera_group_id is not None
            else UserRole.camera_group_id.is_(None),
        )
    )
    if existing is None:
        session.add(UserRole(user_id=user_id, role_id=role.id, camera_group_id=payload.camera_group_id))
        session.flush()
    audit_record(
        session,
        principal=principal,
        action="admin.role.grant",
        object_type="user",
        object_id=str(user_id),
        details={"role": role.code, "camera_group_id": payload.camera_group_id},
    )
    return {"granted": role.code, "scope": payload.camera_group_id}


@router.delete("/users/{user_id}/roles")
def revoke_role(
    user_id: int,
    role_code: str,
    camera_group_id: int | None = None,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.users")),
) -> dict:
    role = session.scalar(select(Role).where(Role.code == role_code))
    if role is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail={"code": "unknown_role"})
    statement = select(UserRole).where(
        UserRole.user_id == user_id,
        UserRole.role_id == role.id,
        UserRole.camera_group_id.is_(camera_group_id)
        if camera_group_id is not None
        else UserRole.camera_group_id.is_(None),
    )
    grant = session.scalar(statement)
    if grant is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="That role is not granted.")
    session.delete(grant)
    session.flush()
    audit_record(
        session,
        principal=principal,
        action="admin.role.revoke",
        object_type="user",
        object_id=str(user_id),
        details={"role": role_code, "camera_group_id": camera_group_id},
    )
    return {"revoked": role_code}


@router.patch("/users/{user_id}")
def set_user_active(
    user_id: int,
    is_active: bool = Query(),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.users")),
) -> dict:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such user.")
    if user.id == principal.user_id and not is_active:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail={"code": "self_deactivation", "message": "You cannot disable your own account."},
        )
    user.is_active = is_active
    session.flush()
    audit_record(
        session,
        principal=principal,
        action="admin.user.activate" if is_active else "admin.user.deactivate",
        object_type="user",
        object_id=str(user.id),
    )
    return {"id": user.id, "is_active": user.is_active}


@router.get("/roles")
def list_roles(
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.users")),
) -> list[dict]:
    roles = session.scalars(select(Role).order_by(Role.code)).all()
    out = []
    for role in roles:
        permission_ids = session.scalars(
            select(RolePermission.permission_id).where(RolePermission.role_id == role.id)
        ).all()
        codes = session.scalars(
            select(Permission.code).where(Permission.id.in_(permission_ids))
        ).all() if permission_ids else []
        out.append(
            {
                "code": role.code,
                "name": role.name,
                "description": role.description,
                "is_administrative": role.is_administrative,
                "permissions": sorted(codes),
            }
        )
    return out


@router.get("/permissions")
def list_permissions(_: Principal = Depends(require_permission("admin.users"))) -> list[dict]:
    return [{"code": code, "description": text} for code, text in sorted(PERMISSIONS.items())]


@router.get("/role-definitions")
def role_definitions(_: Principal = Depends(require_permission("admin.users"))) -> list[dict]:
    return [
        {"code": code, **{key: value for key, value in definition.items() if key != "permissions"}}
        for code, definition in ROLE_DEFINITIONS.items()
    ]


@router.post("/groups", status_code=status.HTTP_201_CREATED)
def create_group(
    payload: GroupCreate,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.policies")),
) -> dict:
    if session.scalar(select(CameraGroup.id).where(CameraGroup.code == payload.code)):
        raise HTTPException(
            status.HTTP_409_CONFLICT, detail={"code": "duplicate_group_code"}
        )
    group = CameraGroup(code=payload.code, name=payload.name, description=payload.description)
    session.add(group)
    session.flush()
    audit_record(
        session,
        principal=principal,
        action="admin.group.create",
        object_type="camera_group",
        object_id=str(group.id),
        details={"code": group.code},
    )
    return {"id": group.id, "code": group.code, "name": group.name}


@router.get("/policies")
def list_monitoring_policies(
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("camera.list")),
) -> list[dict]:
    return [
        {
            "id": policy.id,
            "code": policy.code,
            "name": policy.name,
            "enabled": policy.enabled,
            "detector_codes": policy.detector_codes,
            "min_confidence": policy.min_confidence,
            "analysis_fps": policy.analysis_fps,
            "zones": policy.zones,
            "duplicate_window_seconds": policy.duplicate_window_seconds,
            "severity": policy.severity,
        }
        for policy in session.scalars(select(MonitoringPolicy).order_by(MonitoringPolicy.code)).all()
    ]


def _reject_unrunnable_detectors(codes: list[str]) -> None:
    """Refuse an enabled policy that names a detector this build cannot run.

    Section 11 registers categories such as altercation detection as unavailable on
    purpose. Accepting them into a policy would let an operator believe the camera is
    watched for fights when it is not, so the limit is stated at the point of configuration.
    """
    from ...analysis import detectors

    registered = detectors.detector_codes()
    available = detectors.available_detector_codes()
    problems = []
    for code in codes:
        if code not in registered:
            problems.append(f"{code!r} is not a registered category ({', '.join(registered)})")
        elif code not in available:
            problems.append(f"{code!r}: {detectors.unavailable_reason(code)}")
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "policy_detectors_unavailable",
                "message": " ".join(problems)
                + " Enable only categories this deployment can compute, or leave the "
                "policy disabled until a validated model exists.",
            },
        )


@router.post("/policies", status_code=status.HTTP_201_CREATED)
def upsert_policy(
    payload: PolicyUpsert,
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.policies")),
) -> dict:
    if payload.enabled and payload.detector_codes:
        _reject_unrunnable_detectors(payload.detector_codes)
    policy = session.scalar(select(MonitoringPolicy).where(MonitoringPolicy.code == payload.code))
    if policy is None:
        policy = MonitoringPolicy(code=payload.code)
        session.add(policy)
    for field_name, value in payload.model_dump().items():
        setattr(policy, field_name, value)
    session.flush()
    audit_record(
        session,
        principal=principal,
        action="admin.policy.update",
        object_type="monitoring_policy",
        object_id=str(policy.id),
        details={"code": policy.code, "enabled": policy.enabled, "detectors": policy.detector_codes},
    )
    return {"id": policy.id, "code": policy.code}


@router.get("/notification-settings")
def notification_settings(
    container: Container = Depends(get_container),
    _: Principal = Depends(require_permission("admin.policies")),
) -> dict:
    """Reports what is actually configured, rather than implying a channel works."""
    return {
        "dashboard": "enabled",
        "webhook": "enabled" if container.settings.webhook_url else "not_configured",
        "email": "not_configured",
        "sms": "not_configured",
        "mobile_push": "not_configured",
        "note": (
            "Unconfigured channels are recorded as failed deliveries so the gap is visible "
            "(section 15)."
        ),
    }


@router.get("/retention")
def retention_settings(
    container: Container = Depends(get_container),
    _: Principal = Depends(require_permission("admin.policies")),
) -> dict:
    settings = container.settings
    return {
        "evidence_retention_days": settings.evidence_retention_days,
        "health_retention_days": settings.health_retention_days,
        "audit_retention_days": settings.audit_retention_days,
    }


@router.post("/retention/purge")
def purge_retention(
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    principal: Principal = Depends(require_permission("admin.policies")),
) -> dict:
    purged = EvidenceStore(container.settings, session).purge_expired()
    audit_record(
        session,
        principal=principal,
        action="admin.retention.purge",
        object_type="system",
        details={"evidence_assets_removed": purged},
    )
    return {"evidence_assets_removed": purged}


@router.get("/audit")
def audit_trail(
    action: str | None = None,
    actor: str | None = None,
    since: dt.datetime | None = None,
    limit: int = Query(default=200, le=2000),
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("audit.view")),
) -> dict:
    statement = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        statement = statement.where(AuditLog.action.ilike(f"%{action}%"))
    if actor:
        statement = statement.where(AuditLog.actor_username.ilike(f"%{actor}%"))
    if since:
        statement = statement.where(AuditLog.created_at >= since)
    return {
        "entries": [
            {
                "id": entry.id,
                "created_at": entry.created_at.isoformat(),
                "actor": entry.actor_username,
                "action": entry.action,
                "object_type": entry.object_type,
                "object_id": entry.object_id,
                "outcome": entry.outcome,
                "source_ip": entry.source_ip,
                "details": entry.details,
            }
            for entry in session.scalars(statement).all()
        ]
    }


@router.post("/audit/purge")
def prune_audit(
    before: dt.datetime = Query(description="Delete audit rows older than this instant."),
    session: Session = Depends(get_db),
    principal: Principal = Depends(require_permission("admin.policies")),
) -> dict:
    """Retention for the audit trail itself, deliberately explicit rather than automatic."""
    count = session.scalar(select(func.count(AuditLog.id)).where(AuditLog.created_at < before)) or 0
    session.execute(AuditLog.__table__.delete().where(AuditLog.created_at < before))
    audit_record(
        session,
        principal=principal,
        action="admin.audit.purge",
        object_type="system",
        details={"removed": count, "before": before.isoformat()},
    )
    return {"removed": count}


def _aware(value: dt.datetime) -> dt.datetime:
    """A date-only query parameter arrives without an offset. Treating it as UTC rather than as
    local wall-clock time is what makes the report window the same for every operator; the same
    convention `cloud.views.timestamp` uses when it renders these instants. Boundaries are also
    normalised to UTC so a request carrying `+01:00` compares against the stored instants on the
    same clock."""
    return (value if value.tzinfo else value.replace(tzinfo=dt.UTC)).astimezone(dt.UTC)


# The trend is drawn from contiguous day buckets. A window wider than this is reported as its
# newest days with a flag, so the chart never silently becomes a one-in-thirty sample.
TREND_MAX_BUCKETS = 90


@router.get("/reports/operations")
def operations_report(
    since: dt.datetime | None = None,
    until: dt.datetime | None = None,
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("report.operational")),
) -> dict:
    """Measured figures for the evaluation metrics in section 21."""
    window_end = _aware(until) if until else _utcnow()
    window_start = _aware(since) if since else (window_end - dt.timedelta(days=30))
    if window_start >= window_end:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail={
                "code": "inverted_window",
                "message": "The report window end must be later than its start.",
            },
        )
    events = session.scalars(
        select(DetectionEvent)
        .where(DetectionEvent.occurred_at >= window_start)
        .where(DetectionEvent.occurred_at <= window_end)
    ).all()
    incidents = session.scalars(
        select(Incident)
        .where(Incident.created_at >= window_start)
        .where(Incident.created_at <= window_end)
    ).all()
    notifications = session.scalars(
        select(Notification)
        .where(Notification.created_at >= window_start)
        .where(Notification.created_at <= window_end)
    ).all()

    acknowledged = [event for event in events if event.reviewed_at is not None]
    latencies = [
        (event.reviewed_at - event.occurred_at).total_seconds()
        for event in acknowledged
        if event.reviewed_at and event.occurred_at
    ]
    false_positives = sum(1 for incident in incidents if incident.status == "false_positive")
    cameras = session.scalars(select(Camera)).all()
    online = sum(1 for camera in cameras if camera.status == "online")
    failed_notifications = [row for row in notifications if row.state == "failed"]
    cameras_by_id = {camera.id: camera for camera in cameras}

    return {
        "window_start": window_start.isoformat(),
        "window_end": window_end.isoformat(),
        "candidate_events": len(events),
        "events_reviewed": len(acknowledged),
        "mean_acknowledgement_seconds": round(sum(latencies) / len(latencies), 1) if latencies else None,
        "incidents_raised": len(incidents),
        "incidents_open": sum(1 for incident in incidents if incident.status in ("open", "investigating", "assigned")),
        "incidents_resolved": sum(1 for incident in incidents if incident.status in ("resolved", "closed")),
        "recorded_false_positives": false_positives,
        "incidents_by_severity": [
            {
                "severity": severity,
                "count": sum(1 for incident in incidents if incident.severity == severity),
            }
            for severity in ("critical", "high", "medium", "low")
        ],
        "daily_trend": _daily_trend(window_start, window_end, events, incidents),
        "top_cameras": _top_cameras(cameras_by_id, events, incidents),
        "notifications_created": len(notifications),
        "notifications_failed": len(failed_notifications),
        "notification_failure_reasons": sorted(
            {client_safe(row.failure_reason or "") for row in failed_notifications}
        )[:10],
        "cameras_total": len(cameras),
        "cameras_online": online,
        "cameras_registered": sum(1 for camera in cameras if camera.is_registered),
    }


def _as_utc(value: dt.datetime) -> dt.datetime:
    """Postgres hands back an aware datetime, the harness' SQLite file hands back a naive one that
    was written in UTC. Reading the naive form as local time would move a record near midnight into
    the neighbouring day bucket, so both are pinned to UTC before anything is grouped by day."""
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def _daily_trend(
    window_start: dt.datetime,
    window_end: dt.datetime,
    events: list[DetectionEvent],
    incidents: list[Incident],
) -> dict[str, Any]:
    """One bucket per calendar day in the window, gap-free: a day with nothing recorded has to
    appear as zero or the line chart would read a quiet weekend as missing data. A record with no
    camera still counts in the day's total - it happened, it is just not attributable to a site."""
    first_day = _as_utc(window_start).astimezone(dt.UTC).date()
    last_day = _as_utc(window_end).astimezone(dt.UTC).date()
    requested_days = (last_day - first_day).days + 1
    span = min(requested_days, TREND_MAX_BUCKETS)
    first_day = last_day - dt.timedelta(days=span - 1)
    buckets: dict[Any, dict[str, int]] = {
        day: {"detections": 0, "incidents": 0}
        for day in (first_day + dt.timedelta(days=offset) for offset in range(span))
    }
    for event in events:
        row = buckets.get(_as_utc(event.occurred_at).date())
        if row is not None:
            row["detections"] += 1
    for incident in incidents:
        row = buckets.get(_as_utc(incident.created_at).date())
        if row is not None:
            row["incidents"] += 1
    return {
        "days": [
            {"day": day.isoformat(), "detections": counts["detections"], "incidents": counts["incidents"]}
            for day, counts in buckets.items()
        ],
        # Days in the window that fall outside the plotted span, counted explicitly so the screen
        # can say so instead of showing a chart that looks like the whole request.
        "excluded_days": requested_days - span,
        "truncated": requested_days > span,
    }


def _top_cameras(
    cameras_by_id: dict[Any, Camera],
    events: list[DetectionEvent],
    incidents: list[Incident],
) -> list[dict[str, Any]]:
    """The busiest sites, measured as detections with incidents ranked second - a camera that
    produced one confirmed incident outranks one that produced many unreviewed detections."""
    tally: dict[Any, dict[str, int]] = {}
    for event in events:
        tally.setdefault(event.camera_id, {"detections": 0, "incidents": 0})["detections"] += 1
    for incident in incidents:
        if incident.camera_id is None:
            continue
        tally.setdefault(incident.camera_id, {"detections": 0, "incidents": 0})["incidents"] += 1
    ranked = sorted(
        tally.items(),
        key=lambda entry: (-entry[1]["detections"], -entry[1]["incidents"], entry[0].hex),
    )[:5]
    return [
        {
            "camera_id": str(camera_id),
            "code": cameras_by_id[camera_id].code if camera_id in cameras_by_id else "unknown",
            "display_name": (
                cameras_by_id[camera_id].display_name
                if camera_id in cameras_by_id
                else "Camera no longer registered"
            ),
            "campus_location": (
                cameras_by_id[camera_id].campus_location if camera_id in cameras_by_id else None
            ),
            "detections": counts["detections"],
            "incidents": counts["incidents"],
        }
        for camera_id, counts in ranked
    ]


@router.get("/system")
def system_status(
    request: Request,
    session: Session = Depends(get_db),
    container: Container = Depends(get_container),
    _: Principal = Depends(require_permission("audit.view")),
) -> dict:
    return {
        "environment": container.settings.environment,
        "require_https": container.settings.require_https,
        "max_concurrent_streams": container.settings.max_concurrent_streams,
        "max_concurrent_connection_tests": container.settings.max_concurrent_connection_tests,
        "managed_sessions": len(container.supervisor.snapshot_all()),
        "live_view_sessions": sum(
            1 for entry in container.live_sessions.values() if not entry.released
        ),
        "evidence_dir": str(container.settings.evidence_dir),
        "key_ring": str(container.settings.secret_key_path),
        # The personnel-mobile link. Reported from the queue itself, so a host that has cloud
        # settings but a dead network shows `pending` rather than pretending to be connected.
        "mobile": request.app.state.outbox.status(),
    }


@router.post("/users/{user_id}/effective-permissions")
def effective_permissions(
    user_id: int,
    session: Session = Depends(get_db),
    _: Principal = Depends(require_permission("admin.users")),
) -> dict:
    user = session.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No such user.")
    principal = resolve_principal(session, user)
    return {
        "username": user.username,
        "permissions": sorted(principal.permissions()),
        "scopes": {
            grant.permission: grant.camera_group_id for grant in principal.grants
        },
        "is_administrative": principal.is_administrative,
    }
