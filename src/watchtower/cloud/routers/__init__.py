"""HTTP surfaces of the cloud service.

Every module here is a `fastapi.APIRouter` mounted under `/api/v1` by `watchtower.cloud.app`.
Routers hold request handling and authorisation only; targeting, delivery, storage and token
rules live in the modules one level up, so the same decision is never implemented twice.
"""

from __future__ import annotations

from . import (
    admin,
    auth,
    dashboard,
    devices,
    events,
    evidence,
    incidents,
    ingest,
    notifications,
    profile,
)

ROUTERS = (
    auth.router,
    devices.router,
    dashboard.router,
    notifications.router,
    incidents.router,
    events.router,
    evidence.router,
    profile.router,
    ingest.router,
    admin.router,
)

__all__ = [
    "ROUTERS",
    "admin",
    "auth",
    "dashboard",
    "devices",
    "events",
    "evidence",
    "incidents",
    "ingest",
    "notifications",
    "profile",
]
