"""The live channel: one authenticated server-sent-events stream per handset.

Why the stream reads the database instead of being handed events in memory: the rows that make an
alert worth showing are written by two different processes. An ingest lands in the API process,
but `pending -> delivered` happens in the delivery worker, which may be a different process on a
different host (`python -m watchtower.cloud worker`). An in-process event bus would be a second,
private copy of the truth that only one of the two writers can see, and alerts would be silently
missing rather than merely late. Polling the shared tables costs one indexed query per interval
and is correct in every topology the deployment guide allows.

What the stream carries, and what it deliberately does not:

  * `notification`       - a row addressed to this caller, newly created. Not a state change: the
                           queue endpoint already reports `pending -> delivered -> read`, and the
                           app re-reads those on its own cadence.
  * `incident_activity`  - an action taken on an incident this caller may see, which is how
                           "acknowledged by another officer" and "escalated" reach a phone that is
                           sitting on the incident screen.
  * `heartbeat`          - proves the connection is alive to both sides, so a proxy that dropped it
                           silently shows as a reconnect instead of a quiet nothing.

Authorization is decided when the connection opens and re-decided when it closes: the cap on
connection lifetime is validated against the access-token TTL in `CloudSettings`, so a stream
cannot outlive the permissions it was checked against. The client reconnects, and the reconnect
runs `current_caller` again.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import logging
import re
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Camera, Incident, IncidentAction, Notification
from .config import CloudSettings
from .deps import Caller
from .views import actor_names, camera_scope_condition, notification_view, timestamp

LOGGER = logging.getLogger("watchtower.cloud.stream")

EVENT_READY = "ready"
EVENT_NOTIFICATION = "notification"
EVENT_ACTIVITY = "incident_activity"
EVENT_HEARTBEAT = "heartbeat"
EVENT_CLOSING = "closing"

# How many rows one feed may deliver in one pass. A phone that was away for a day gets several
# passes rather than one enormous frame, and the cursor advances so nothing is re-sent.
BATCH_LIMIT = 25

_CURSOR_RE = re.compile(r"^(\d{1,12}):(\d{1,12})$")


@dataclass(slots=True)
class Cursor:
    """Positions in the two feeds. Ids are database primary keys, so they only ever move forward."""

    notifications: int = 0
    actions: int = 0

    def encode(self) -> str:
        return f"{self.notifications}:{self.actions}"

    @classmethod
    def parse(cls, raw: str | None) -> Cursor | None:
        if not raw:
            return None
        match = _CURSOR_RE.match(raw.strip())
        if not match:
            return None
        return cls(int(match.group(1)), int(match.group(2)))


@dataclass(slots=True)
class StreamEvent:
    name: str
    data: dict[str, Any]
    id: str

    def frame(self) -> str:
        """The SSE wire form: an id line, a name line, one JSON data line, and a blank line."""
        return f"id: {self.id}\nevent: {self.name}\ndata: {json.dumps(self.data)}\n\n"


class StreamRoom:
    """How many live connections this process will hold.

    Each one is a task that wakes every poll interval and borrows a database connection from the
    same pool that answers logins. An unbounded stream route lets a phone retrying on a flaky
    network pile up half a dozen of them and starve the rest of the service, so the answer past
    the cap is a refusal the client can read - not a queue, because a queued stream would look to
    the app exactly like a live one that has not produced anything yet.
    """

    def __init__(self, limit: int) -> None:
        self.limit = max(1, int(limit))
        self.open = 0
        self.refusals = 0

    def acquire(self) -> bool:
        if self.open >= self.limit:
            self.refusals += 1
            return False
        self.open += 1
        return True

    def release(self) -> None:
        self.open = max(0, self.open - 1)


@dataclass(slots=True)
class DrainReport:
    events: list[StreamEvent] = field(default_factory=list)
    cursor: Cursor = field(default_factory=lambda: Cursor())


def latest_cursor(session: Session, caller: Caller) -> Cursor:
    """Where a connection with no cursor starts: the end of both feeds.

    A fresh connection is not a history lesson. The app already fetched its queue and its incident
    list when it loaded, and replaying every row an officer missed last week as a stack of banners
    would be worse than useless. Only the global maximum is consulted, not the scope-filtered one:
    new rows always carry a larger id than any row in the table, so starting here cannot skip
    something that arrives after the connection opened.
    """
    return Cursor(
        notifications=int(session.scalar(select(func.max(Notification.id))) or 0),
        actions=int(session.scalar(select(func.max(IncidentAction.id))) or 0),
    )


def drain(
    session: Session,
    caller: Caller,
    settings: CloudSettings,
    cursor: Cursor,
    *,
    limit: int = BATCH_LIMIT,
) -> DrainReport:
    """Read what happened since `cursor` and hand back the frames plus the new position.

    One session per call, opened by the caller: this runs inside a loop that must not hold a
    database connection while it sleeps, because a stream that outlives its pool slot is a stream
    that takes the pool away from the logins it is waiting for.
    """
    report = DrainReport()
    # The caller's cursor is read, never written: the loop keeps the position it started from
    # until every frame has actually gone out, so a drain that raised halfway through cannot
    # leave a connection resuming past rows it never delivered.
    position = Cursor(cursor.notifications, cursor.actions)
    report.cursor = position
    report.events.extend(_new_notifications(session, caller, settings, position, limit=limit))
    report.events.extend(_new_activity(session, caller, position, limit=limit))
    return report


def _new_notifications(
    session: Session, caller: Caller, settings: CloudSettings, cursor: Cursor, *, limit: int
) -> list[StreamEvent]:
    rows = list(
        session.scalars(
            select(Notification)
            .where(
                Notification.recipient_id == caller.user_id,
                Notification.id > cursor.notifications,
            )
            .order_by(Notification.id)
            .limit(limit)
        ).all()
    )
    if not rows:
        return []
    cameras = _cameras(session, {row.camera_id for row in rows if row.camera_id})
    references = _references(session, {row.incident_id for row in rows if row.incident_id})
    events = [
        StreamEvent(
            name=EVENT_NOTIFICATION,
            data=notification_view(
                session,
                row,
                settings=settings,
                camera=cameras.get(row.camera_id) if row.camera_id else None,
                incident_reference=references.get(row.incident_id) if row.incident_id else None,
            ),
            id=Cursor(row.id, cursor.actions).encode(),
        )
        for row in rows
    ]
    cursor.notifications = int(rows[-1].id)
    return events


def _new_activity(
    session: Session, caller: Caller, cursor: Cursor, *, limit: int
) -> list[StreamEvent]:
    statement = (
        select(IncidentAction, Incident)
        .join(Incident, Incident.id == IncidentAction.incident_id)
        .where(IncidentAction.id > cursor.actions)
        .order_by(IncidentAction.id)
        .limit(limit)
    )
    # The same predicate the console and `GET /incidents` use. An action on a camera this officer
    # is not granted is not a thing they may be told happened, even though the row is public in
    # the table.
    scope = camera_scope_condition(caller.principal, "incident.view", Incident)
    if scope is not None:
        statement = statement.where(scope)

    pairs = session.execute(statement).all()
    if not pairs:
        return []
    names = actor_names(session, {action.actor_id for action, _ in pairs if action.actor_id})
    events = [
        StreamEvent(
            name=EVENT_ACTIVITY,
            data={
                "id": int(action.id),
                "incident_id": int(incident.id),
                "incident_reference": incident.reference,
                "incident_status": incident.status,
                "incident_severity": incident.severity,
                "action": action.action,
                "note": action.note,
                "actor_id": action.actor_id,
                "actor_name": names.get(action.actor_id) if action.actor_id else None,
                "created_at": timestamp(action.created_at),
            },
            id=Cursor(cursor.notifications, int(action.id)).encode(),
        )
        for action, incident in pairs
    ]
    cursor.actions = int(pairs[-1][0].id)
    return events


def _cameras(session: Session, camera_ids: set) -> dict:
    if not camera_ids:
        return {}
    rows = session.execute(select(Camera).where(Camera.id.in_(list(camera_ids)))).scalars().all()
    return {camera.id: camera for camera in rows}


def _references(session: Session, incident_ids: set) -> dict[int, str]:
    if not incident_ids:
        return {}
    rows = session.execute(
        select(Incident.id, Incident.reference).where(Incident.id.in_(list(incident_ids)))
    ).all()
    return {int(incident_id): reference for incident_id, reference in rows}


async def stream_frames(
    session_factory: Callable[[], Session],
    caller: Caller,
    settings: CloudSettings,
    cursor: Cursor,
    *,
    heartbeat_seconds: float | None = None,
    poll_seconds: float | None = None,
    max_lifetime_seconds: float | None = None,
    is_disconnected: Callable[[], Any] = lambda: False,
) -> AsyncIterator[str]:
    """Yield SSE frames until the lifetime cap, a disconnect, or the database says no.

    `session_factory` is called fresh for every poll and closed again immediately. Reading the
    database in a worker thread keeps the event loop free to serve the rest of the process while
    this connection sleeps, which matters because this endpoint is the one thing in the service
    that is designed to stay open.
    """
    poll = poll_seconds if poll_seconds is not None else settings.stream_poll_seconds
    heartbeat = (
        heartbeat_seconds if heartbeat_seconds is not None else settings.stream_heartbeat_seconds
    )
    lifetime = (
        max_lifetime_seconds
        if max_lifetime_seconds is not None
        else float(settings.stream_max_lifetime_seconds)
    )

    position = Cursor(cursor.notifications, cursor.actions)
    loop = asyncio.get_running_loop()
    opened_at = loop.time()
    last_heartbeat = opened_at

    yield StreamEvent(
        name=EVENT_READY,
        data={
            "cursor": position.encode(),
            "poll_seconds": poll,
            "heartbeat_seconds": heartbeat,
            "server_time": _now(),
        },
        id=position.encode(),
    ).frame()

    try:
        while True:
            elapsed = loop.time() - opened_at
            if elapsed >= lifetime:
                yield _closing(position, "lifetime")
                return
            if await _disconnected(is_disconnected):
                return

            try:
                report = await asyncio.to_thread(_drain_now, session_factory, caller, settings, position)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a dropped read must end the stream, not the process
                LOGGER.warning("live stream could not read its feed: %s", exc)
                yield _closing(position, "database_unavailable")
                return

            for event in report.events:
                position = _merge(position, event.id)
                yield event.frame()

            now = loop.time()
            if now - last_heartbeat >= heartbeat:
                last_heartbeat = now
                yield StreamEvent(
                    name=EVENT_HEARTBEAT,
                    data={"cursor": position.encode(), "server_time": _now()},
                    id=position.encode(),
                ).frame()

            await asyncio.sleep(poll)
    finally:
        LOGGER.debug("live stream for user %s closed", caller.user_id)


def _drain_now(
    session_factory: Callable[[], Session],
    caller: Caller,
    settings: CloudSettings,
    position: Cursor,
) -> DrainReport:
    with session_factory() as session:
        return drain(session, caller, settings, position)


def _merge(position: Cursor, frame_id: str) -> Cursor:
    """Adopt a frame's cursor: whichever feed moved, the other keeps its own position."""
    incoming = Cursor.parse(frame_id)
    if incoming is None:
        return position
    return Cursor(incoming.notifications, incoming.actions)


async def _disconnected(is_disconnected: Callable[[], Any]) -> bool:
    return bool(await _maybe_await(is_disconnected()))


async def _maybe_await(value: Any) -> Any:
    if asyncio.iscoroutine(value):
        return await value
    return value


def _closing(position: Cursor, reason: str) -> str:
    return StreamEvent(
        name=EVENT_CLOSING,
        data={"reason": reason, "cursor": position.encode(), "server_time": _now()},
        id=position.encode(),
    ).frame()


def _now() -> str:
    return dt.datetime.now(dt.UTC).isoformat().replace("+00:00", "Z")


__all__ = [
    "BATCH_LIMIT",
    "EVENT_ACTIVITY",
    "EVENT_CLOSING",
    "EVENT_HEARTBEAT",
    "EVENT_NOTIFICATION",
    "EVENT_READY",
    "Cursor",
    "DrainReport",
    "StreamEvent",
    "StreamRoom",
    "drain",
    "latest_cursor",
    "stream_frames",
]
