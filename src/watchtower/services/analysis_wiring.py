"""Composition root for the AI analysis pass (sections 11 and 15).

`cli.main serve` asks for an analysis engine, but the engine is only useful once it is bound
to the live stream supervisor, the evidence directory and the notification service — none of
which exist yet when the CLI parses its arguments. This module is where those pieces meet, so
the CLI and the API stay free of analysis-layer knowledge.

Two properties are preserved here rather than assumed:

  * candidate events reach a human as notifications; a detection that nobody is told about is
    not a monitoring feature;
  * evidence snapshots are written under the configured evidence directory, not beside the
    code, and only for events that actually alert (see `events._attach_snapshot`).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from ..config import Settings

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from ..analysis.engine import AnalysisEngine
    from ..ingest.supervisor import StreamSupervisor
    from ..models import Camera, DetectionEvent

LOGGER = logging.getLogger("watchtower.analysis.wiring")


def build_analysis_engine(
    settings: Settings,
    supervisor: StreamSupervisor,
) -> AnalysisEngine | None:
    """Return an engine wired to this deployment, or None when it cannot run.

    Returning None is a deliberate degradation: proposal section 5 keeps analysis separate
    from ingestion, so a missing evidence path must leave live view and health monitoring
    fully working.
    """
    from ..analysis.engine import AnalysisEngine
    from ..analysis.events import LocalEvidenceWriter
    from ..services.notifications import NotificationService

    try:
        settings.evidence_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        LOGGER.error("analysis disabled: evidence directory %s is unusable (%s)",
                     settings.evidence_dir, exc)
        return None

    def dispatch_alert(session: Session, camera: Camera, event: DetectionEvent) -> None:
        """An alerting candidate becomes governed evidence, then routes to its reviewers."""
        from ..security.secrets import redact
        from ..services.evidence import EvidenceError, EvidenceStore

        snapshot = (event.event_metadata or {}).get("snapshot")
        if isinstance(snapshot, dict):
            try:
                EvidenceStore(settings, session).adopt(
                    camera_id=camera.id,
                    detection_event_id=event.id,
                    snapshot=snapshot,
                    captured_at=event.occurred_at,
                )
            except EvidenceError as exc:
                # A missing file must not swallow the alert; the reviewer still sees the event.
                LOGGER.warning(redact(f"{camera.code}: candidate snapshot not adopted: {exc}"))
        NotificationService(session, webhook_url=settings.webhook_url).candidate_event_alert(
            camera, event
        )

    return AnalysisEngine(
        settings,
        supervisor,
        evidence_writer=LocalEvidenceWriter(settings.evidence_dir),
        on_alert=dispatch_alert,
    )
