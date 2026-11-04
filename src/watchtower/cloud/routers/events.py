"""The live alert channel (contract section 10.8).

`GET /api/v1/events/stream` is the reason an officer sees an alert without waiting for the next
poll: the app holds one authenticated HTTPS connection and the service tells it when something
arrived. It is server-sent events rather than a WebSocket because everything that crosses this
connection travels one way, and SSE needs no handshake, no subprotocol negotiation and no
re-open logic on a proxy that dropped it - which is what a phone on a mobile network does hourly.

Three things this route gets right that the endpoint it replaces did not:

  * it does not hold a database connection. FastAPI runs a dependency's teardown when the response
    finishes, and this response finishes ten minutes later, so the request session is explicitly
    released before the body starts and the stream opens its own short-lived session per read.
  * it authorises with the same dependency as every other alert surface, so a handset cannot
    subscribe to a feed the REST routes would refuse.
  * it ends. The connection lifetime is capped below the access-token TTL by configuration, so the
    permission check that opened it cannot go stale for longer than a token's own life.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..config import CloudSettings
from ..deps import Caller, get_container, get_db, get_settings, require_permission
from ..errors import CloudError
from ..streaming import Cursor, latest_cursor, stream_frames

LOGGER = logging.getLogger("watchtower.cloud.events")

router = APIRouter(prefix="/events", tags=["events"])

STREAM_HEADERS = {
    "cache-control": "no-store, no-transform",
    "pragma": "no-cache",
    # Without this, an nginx or Caddy front ends the connection by buffering the body it is meant
    # to be forwarding, and the officer sees a live-looking app that has not received a frame.
    "x-accel-buffering": "no",
    "x-content-type-options": "nosniff",
}


@router.get("/stream")
def live_stream(
    request: Request,
    since: str | None = Query(
        default=None,
        description="Cursor from a previous connection (`notifications:actions`), or Last-Event-ID.",
    ),
    session: Session = Depends(get_db),
    caller: Caller = Depends(require_permission("incident.view")),
    settings: CloudSettings = Depends(get_settings),
):
    """A long-lived text/event-stream of this caller's alerts and the activity on their incidents."""
    if not settings.stream_enabled:
        raise CloudError(
            "stream_disabled",
            "The live channel is switched off on this service; use the notification list.",
            status_code=503,
        )
    room = get_container(request).streams
    if not room.acquire():
        LOGGER.warning(
            "live stream refused for user %s: %d of %d connections are already open",
            caller.user_id,
            room.open,
            room.limit,
        )
        raise CloudError(
            "stream_unavailable",
            "This service is holding its full set of live connections.",
            status_code=503,
            headers={"retry-after": "30"},
        )

    resume = Cursor.parse(since) or Cursor.parse(request.headers.get("last-event-id"))
    if since and resume is None:
        # A cursor the service cannot read is not a reason to replay history from zero, which is
        # what an unparseable value would otherwise become. Start at the end and let the app's own
        # list refresh cover whatever it missed while the cursor was broken.
        LOGGER.info("live stream started with an unreadable cursor from user %s", caller.user_id)
    if resume is None:
        resume = latest_cursor(session, caller)

    # Release the request session now: see the module docstring. The stream re-reads through the
    # container's factory, one session per poll, and never borrows this one.
    session.close()

    factory = request.app.state.session_factory

    async def frames():
        try:
            async for frame in stream_frames(
                factory,
                caller,
                settings,
                resume,
                is_disconnected=request.is_disconnected,
            ):
                yield frame
        finally:
            room.release()

    return StreamingResponse(
        frames(),
        media_type="text/event-stream",
        headers=dict(STREAM_HEADERS),
    )


__all__ = ["router"]
