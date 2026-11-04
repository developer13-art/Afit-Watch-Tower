"""AI-assisted video analysis: candidate security events for human review (section 11)."""

from __future__ import annotations

from .detectors import (
    available_detector_codes,
    detector_codes,
    full_frame_zone,
    unavailable_reason,
    zones_from_policy,
)
from .engine import AnalysisEngine
from .events import (
    EvidenceRef,
    EvidenceWriter,
    LocalEvidenceWriter,
    submit_finding,
    submit_findings,
)

__all__ = [
    "AnalysisEngine",
    "EvidenceRef",
    "EvidenceWriter",
    "LocalEvidenceWriter",
    "available_detector_codes",
    "detector_codes",
    "full_frame_zone",
    "submit_finding",
    "submit_findings",
    "unavailable_reason",
    "zones_from_policy",
]
