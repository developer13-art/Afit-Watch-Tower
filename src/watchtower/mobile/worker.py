"""The outbox drain: a daemon thread that hands queued alerts to the cloud service.

It is deliberately *not* part of `SupervisionLoop.cycle()`. A cycle runs every two seconds and
must not be delayed by a slow HTTPS call to another network, because the thing that notices a
camera has stopped streaming is the same loop. Draining is its own thread with its own cadence.

One worker per monitoring host. `claim_due` takes a `FOR UPDATE SKIP LOCKED` lock so a second
worker would be safe, but two hosts draining one queue would double the retries without
doubleing the delivery, so the deployment guide says one and this module assumes it.

When `mobile_forwarding_enabled` is false the thread still starts and does nothing; `status()`
then reports `disabled`, which is what the console displays.
"""

from __future__ import annotations

import logging
import threading
import time

from sqlalchemy.orm import sessionmaker

from ..config import Settings
from ..security.secrets import redact
from .outbox import OutboxForwarder, queue_summary

LOGGER = logging.getLogger("watchtower.mobile.worker")

DEFAULT_POLL_SECONDS = 5.0
DEFAULT_HEARTBEAT_SECONDS = 60.0


def build_evidence_reader(settings: Settings, session_factory):
    """Read the bytes for a storage key, or nothing at all if they cannot be had.

    A missing or corrupt file is reported as `None` so the forwarder leaves the asset pending
    and tries again later; raising here would stop unrelated alerts from being delivered.
    """
    from sqlalchemy import select

    from ..models import EvidenceAsset
    from ..services.evidence import EvidenceError, EvidenceStore

    def read(storage_key: str) -> bytes | None:
        with session_factory() as session:
            asset = session.scalar(
                select(EvidenceAsset).where(EvidenceAsset.storage_key == storage_key)
            )
            if asset is None:
                return None
            try:
                return EvidenceStore(settings, session).read(asset)
            except (EvidenceError, OSError):
                LOGGER.warning("evidence bytes unavailable for a relayed asset")
                return None

    return read


class OutboxWorker:
    def __init__(
        self,
        settings: Settings,
        session_factory: sessionmaker,
        *,
        forwarder: OutboxForwarder | None = None,
        poll_seconds: float = DEFAULT_POLL_SECONDS,
        heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
        monitoring_host: str | None = None,
        app_version: str = "unknown",
    ) -> None:
        self._settings = settings
        self._forwarder = forwarder or OutboxForwarder(settings, session_factory)
        self._poll = poll_seconds
        self._heartbeat = heartbeat_seconds
        self._host = monitoring_host or settings.cloud_key_id or "monitoring-host"
        self._app_version = app_version
        self._session_factory = session_factory
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_run_at: float | None = None
        self._last_heartbeat_at: float | None = None
        self._cycles = 0
        self._failures = 0

    @property
    def enabled(self) -> bool:
        return self._forwarder.enabled

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="outbox-drain", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=15)
            self._thread = None

    def _run(self) -> None:
        while not self._stop.wait(self._poll):
            self._safe_cycle()

    def _safe_cycle(self):
        """One cycle that never propagates: a drain fault must not stop the queue."""
        try:
            return self.run_once()
        except Exception as exc:  # noqa: BLE001 - the next cycle has to run regardless
            self._failures += 1
            LOGGER.error("outbox drain failed: %s", redact(str(exc)))
            return None

    def run_once(self):
        """One drain pass plus, on its own cadence, a heartbeat."""
        report = self._forwarder.run_once()
        self._cycles += 1
        self._last_run_at = time.time()
        if self.enabled and self._should_heartbeat():
            try:
                result = self._forwarder.send_heartbeat(
                    monitoring_host=self._host, app_version=self._app_version
                )
                if result is not None and not result.ok:
                    LOGGER.warning("heartbeat refused: %s", result.error or result.status)
                self._last_heartbeat_at = time.time()
            except Exception as exc:  # noqa: BLE001 - the queue matters more than the ping
                LOGGER.warning("heartbeat failed: %s", redact(str(exc)))
        return report

    def _should_heartbeat(self) -> bool:
        return self._last_heartbeat_at is None or (
            time.time() - self._last_heartbeat_at >= self._heartbeat
        )

    def status(self) -> dict:
        """What the console shows about the mobile link, from the queue itself."""
        summary: dict[str, int] = {}
        if self.enabled:
            try:
                with self._session_factory() as session:
                    summary = queue_summary(session)
            except Exception as exc:  # noqa: BLE001 - status must not break the page
                LOGGER.warning("outbox status unavailable: %s", redact(str(exc)))
        return {
            "enabled": self.enabled,
            "state": "connected" if self.enabled else "disabled",
            "cloud_api_configured": self.enabled,
            "poll_seconds": self._poll,
            "cycles": self._cycles,
            "failures": self._failures,
            "last_run_at": self._last_run_at,
            "last_success_at": self._forwarder.report.last_success_at,
            "last_error": redact(self._forwarder.report.last_error or "") or None,
            "pending": summary.get("queued", 0)
            + summary.get("processing", 0)
            + summary.get("failed", 0),
            "delivered": summary.get("delivered", 0),
            "dead": summary.get("dead", 0),
            "spooled": len(self._forwarder.spool.pending()),
        }
