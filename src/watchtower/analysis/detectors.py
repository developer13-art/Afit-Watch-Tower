"""Classical computer-vision candidate detectors for AI-assisted video analysis (section 11).

No trained model ships with this deployment, so every finding here comes from background
subtraction, blob geometry and short-lived temporal state. Findings are candidates for a
human reviewer, never conclusions: the two categories that genuinely need recognition are
registered as unavailable stubs that refuse to emit findings.

Detectors share one grayscale frame and one running background per camera; zone state is
per camera+zone and lives only in memory, so `AnalysisEngine.reset()` discards it when a
stream reconnects.
"""

from __future__ import annotations

import itertools
import math
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

import cv2
import numpy as np

# --------------------------------------------------------------------------- #
# Tunables. Deliberate thresholds, not deployment settings: the proposal's
# Settings has no keys for them.
# --------------------------------------------------------------------------- #

FULL_FRAME_ZONE_ID = "full_frame"

BACKGROUND_LEARNING_RATE = 0.02  # ~50 analysed frames to absorb a stopped object, so dwells stay well below that
MIN_DIFF_FLOOR = 18  # 8-bit absdiff floor for a lit indoor scene at JPEG quality 78
NOISE_THRESHOLD_MULTIPLIER = 3.0  # under 3x the frame's own median diff is sensor noise
SCENE_WIDE_CHANGE_MAX = 0.45  # motion on this much of the frame is an illumination step, not an intruder
BLUR_KSIZE = 3
MORPH_OPEN_KSIZE = 3
MORPH_CLOSE_KSIZE = 5

MIN_BLOB_AREA_FRACTION = 0.0012  # below this a leaf or sensor speck would qualify as person-sized
MAX_BLOB_AREA_FRACTION = 0.35  # a blob over a third of the frame is a lighting change, not an object
TARGET_BODY_AREA_FRACTION = 0.01  # a body at typical CCTV framing occupies around a percent of the frame
MIN_BLOB_EDGE_PIXELS = 12
MIN_BLOB_FILL_RATIO = 0.25  # foliage clutter scatters across its hull; a body fills it
MIN_BLOB_ASPECT_RATIO = 0.15
MAX_BLOB_ASPECT_RATIO = 6.0

ZONE_ENTRY_MIN_FRAMES = 3
CONFIDENCE_STREAK_SATURATION_FRAMES = 6
UNATTENDED_DWELL_SECONDS = 8.0
UNATTENDED_MIN_STATIONARY_FRAMES = 5
UNATTENDED_MAX_CENTER_SHIFT_FRACTION = 0.02  # of the frame diagonal per analysed frame
UNATTENDED_MAX_AREA_DRIFT = 0.5  # relative blob-area change per analysed frame
UNATTENDED_MIN_SCENE_MOTION_FRACTION = 0.003
UNATTENDED_MIN_OUTSIDE_MOTION_FRACTION = 0.002
LOITER_WINDOW_SECONDS = 12.0
LOITER_TRAIL_MAXLEN = 96
LOITER_MIN_DURATION_SECONDS = 3.0
LOITER_MIN_REVERSALS = 3
LOITER_MIN_PATH_DISPERSION_RATIO = 2.5
LOITER_MAX_SPAN_FRACTION = 0.8  # of the zone diagonal; beyond it the subject is passing through

STUB_REASONS: dict[str, str] = {
    "possible_physical_altercation": (
        "needs a trained altercation model validated on this site's cameras; motion "
        "heuristics cannot tell a scuffle from two people passing each other"
    ),
    "theft_like_activity": (
        "needs an object-interaction model validated on this site's cameras; motion "
        "heuristics cannot tell a theft from someone picking up their own bag"
    ),
}


class DetectorUnavailableError(RuntimeError):
    """Raised when a stubbed detector is asked to analyse a frame rather than report itself."""

    def __init__(self, code: str, reason: str) -> None:
        super().__init__(f"{code} is not available: {reason}")
        self.code = code
        self.reason = reason


# --------------------------------------------------------------------------- #
# Zone geometry
# --------------------------------------------------------------------------- #


def normalize_points(raw: Any) -> list[tuple[float, float]]:
    """Accept a zone polygon as a list of [x, y] pairs or mapping points."""
    if not isinstance(raw, (list, tuple)):
        return []
    points: list[tuple[float, float]] = []
    for item in raw:
        if isinstance(item, Mapping):
            xy = (item.get("x"), item.get("y"))
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            xy = (item[0], item[1])
        else:
            continue
        try:
            x = float(xy[0])
            y = float(xy[1])
        except (TypeError, ValueError):
            continue
        if math.isfinite(x) and math.isfinite(y):
            points.append((x, y))
    return points


@dataclass(slots=True)
class Zone:
    """A polygon the policy watches, with its rasterised mask cached per frame size."""

    id: str
    polygon: np.ndarray
    label: str = ""
    _masks: dict[tuple[int, int], np.ndarray] = field(default_factory=dict, repr=False)

    def scaled(self, height: int, width: int) -> np.ndarray:
        """Polygon as clipped int32 pixel coordinates; normalised geometry scales to the frame."""
        coords = np.asarray(self.polygon, dtype=np.float64).reshape(-1, 2)
        if float(np.max(coords)) <= 1.0:
            coords = coords * np.array([width, height], dtype=np.float64)
        return np.clip(coords, 0, None).astype(np.int32)

    def mask(self, height: int, width: int) -> np.ndarray:
        key = (height, width)
        cached = self._masks.get(key)
        if cached is not None:
            return cached
        mask = np.zeros((height, width), dtype=np.uint8)
        cv2.fillPoly(mask, [self.scaled(height, width).reshape(-1, 1, 2)], 255)
        self._masks[key] = mask
        return mask

    def diagonal(self, height: int, width: int) -> float:
        pts = self.scaled(height, width).astype(np.float64)
        return float(math.hypot(pts[:, 0].max() - pts[:, 0].min(), pts[:, 1].max() - pts[:, 1].min()))


def zones_from_policy(zones: Iterable[Mapping[str, Any]] | None) -> list[Zone]:
    """Build the analysable zone list from a monitoring policy's stored geometry."""
    built: list[Zone] = []
    for index, zone in enumerate(zones or ()):
        if not isinstance(zone, Mapping):
            continue
        zone_id = str(zone.get("id") or zone.get("code") or zone.get("name") or "").strip()
        label = str(zone.get("name") or zone.get("label") or "").strip()
        polygon = zone.get("polygon")
        if polygon is None:
            polygon = zone.get("points")
        if polygon is None:
            polygon = zone.get("coordinates")
        points = normalize_points(polygon)
        if len(points) < 3:
            continue
        built.append(
            Zone(
                id=zone_id or f"zone_{index + 1}",
                polygon=np.asarray(points, dtype=np.float64),
                label=label or zone_id or f"zone_{index + 1}",
            )
        )
    return built


def full_frame_zone() -> Zone:
    """Fallback covering the whole frame when a detector is enabled without geometry."""
    return Zone(
        id=FULL_FRAME_ZONE_ID,
        polygon=np.array([[0.0, 0.0], [1.0, 0.0], [1.0, 1.0], [0.0, 1.0]], dtype=np.float64),
        label="whole frame",
    )


# --------------------------------------------------------------------------- #
# Background model
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class MotionField:
    """The per-frame foreground mask shared by every detector on a camera."""

    timestamp: float
    height: int
    width: int
    mask: np.ndarray
    motion_fraction: float
    scene_wide_change: bool

    @property
    def usable(self) -> bool:
        return not self.scene_wide_change and self.mask.any()


class MotionModel:
    """Exponential-mean background subtraction with an adaptive per-frame noise floor."""

    def __init__(self, learning_rate: float = BACKGROUND_LEARNING_RATE) -> None:
        self._learning_rate = learning_rate
        self._background: np.ndarray | None = None

    def reset(self) -> None:
        """Discard the baseline; a reconnected stream may be a different scene."""
        self._background = None

    def analyze(self, gray: np.ndarray, timestamp: float) -> MotionField:
        frame = gray.astype(np.float32)
        height, width = gray.shape
        if self._background is None or self._background.shape != frame.shape:
            self._background = frame.copy()
            return MotionField(timestamp, height, width, np.zeros((height, width), np.uint8), 0.0, True)

        diff = np.abs(frame - self._background)
        smoothed = cv2.GaussianBlur(diff, (BLUR_KSIZE, BLUR_KSIZE), 0)
        threshold = float(max(MIN_DIFF_FLOOR, float(np.median(smoothed)) * NOISE_THRESHOLD_MULTIPLIER))
        mask = (smoothed > threshold).astype(np.uint8) * 255
        mask = cv2.morphologyEx(
            mask, cv2.MORPH_OPEN, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (MORPH_OPEN_KSIZE, MORPH_OPEN_KSIZE))
        )
        mask = cv2.morphologyEx(
            mask, cv2.MORPH_CLOSE, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (MORPH_CLOSE_KSIZE, MORPH_CLOSE_KSIZE))
        )
        fraction = float(np.count_nonzero(mask)) / float(height * width)
        scene_wide = fraction > SCENE_WIDE_CHANGE_MAX
        if scene_wide:
            mask = np.zeros((height, width), dtype=np.uint8)
            self._background = frame.copy()
        else:
            cv2.accumulateWeighted(frame, self._background, self._learning_rate)
        return MotionField(timestamp, height, width, mask, fraction, scene_wide)


# --------------------------------------------------------------------------- #
# Blob geometry
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class Blob:
    """A foreground region that passed the person-shaped geometry screen."""

    bbox: tuple[int, int, int, int]
    area: float
    fill_ratio: float
    aspect_ratio: float
    centroid: tuple[float, float]


def is_person_shaped(blob: Blob, height: int, width: int) -> bool:
    """Reject specks, foliage clutter and whole-frame lighting changes by geometry alone."""
    frame_area = float(height * width)
    if not MIN_BLOB_AREA_FRACTION * frame_area <= blob.area <= MAX_BLOB_AREA_FRACTION * frame_area:
        return False
    if min(blob.bbox[2], blob.bbox[3]) < MIN_BLOB_EDGE_PIXELS:
        return False
    if blob.fill_ratio < MIN_BLOB_FILL_RATIO:
        return False
    return MIN_BLOB_ASPECT_RATIO <= blob.aspect_ratio <= MAX_BLOB_ASPECT_RATIO


def blobs_in_zone(motion: MotionField, zone: Zone) -> list[Blob]:
    """Foreground blobs whose centre of mass lies inside the zone polygon."""
    if not motion.usable:
        return []
    zone_mask = zone.mask(motion.height, motion.width)
    combined = cv2.bitwise_and(motion.mask, zone_mask)
    contours, _ = cv2.findContours(combined, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    polygon = zone.scaled(motion.height, motion.width)
    blobs: list[Blob] = []
    for contour in contours:
        area = float(cv2.contourArea(contour))
        if area <= 0.0:
            continue
        moments = cv2.moments(contour)
        if moments["m00"] == 0.0:
            continue
        centroid = (float(moments["m10"] / moments["m00"]), float(moments["m01"] / moments["m00"]))
        if cv2.pointPolygonTest(polygon.reshape(-1, 2), centroid, False) < 0.0:
            continue
        hull_area = float(cv2.contourArea(cv2.convexHull(contour)))
        x, y, width, height = cv2.boundingRect(contour)
        blobs.append(
            Blob(
                bbox=(int(x), int(y), int(width), int(height)),
                area=area,
                fill_ratio=area / max(1.0, hull_area),
                aspect_ratio=float(width) / float(max(1, height)),
                centroid=centroid,
            )
        )
    return [blob for blob in blobs if is_person_shaped(blob, motion.height, motion.width)]


def outside_motion_fraction(motion: MotionField, zone: Zone) -> float:
    """Motion share beyond the zone, which separates a left object from a still room."""
    outside = cv2.bitwise_and(motion.mask, cv2.bitwise_not(zone.mask(motion.height, motion.width)))
    return float(np.count_nonzero(outside)) / float(motion.height * motion.width)


# --------------------------------------------------------------------------- #
# Per-camera state
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class ZoneMemory:
    """Consecutive-frame counters for one camera+zone pair."""

    entry_streak: int = 0
    stationary_centroid: tuple[float, float] | None = None
    stationary_area: float = 0.0
    stationary_streak: int = 0
    stationary_since: float = 0.0
    trail: deque[tuple[float, float, float]] = field(
        default_factory=lambda: deque(maxlen=LOITER_TRAIL_MAXLEN)
    )


@dataclass(slots=True)
class DetectorState:
    """In-memory detector memory for one camera, reused across analysed frames."""

    camera_id: str
    detector_code: str
    model: MotionModel
    timestamp: float = 0.0
    zones: dict[str, ZoneMemory] = field(default_factory=dict)

    def memory(self, zone_id: str) -> ZoneMemory:
        return self.zones.setdefault(zone_id, ZoneMemory())

    def retain(self, zone_ids: Iterable[str]) -> None:
        """Drop counters belonging to zones that policy editing removed."""
        keep = set(zone_ids)
        for stale in [zone_id for zone_id in self.zones if zone_id not in keep]:
            del self.zones[stale]

    def clear(self) -> None:
        self.zones.clear()


# --------------------------------------------------------------------------- #
# Detector contract
# --------------------------------------------------------------------------- #


@dataclass(frozen=True, slots=True)
class RawFinding:
    """One candidate observation, before confidence gating and deduplication."""

    category: str
    confidence: float
    detail: Mapping[str, Any]

    @property
    def zone_id(self) -> str:
        return str(self.detail.get("zone_id") or FULL_FRAME_ZONE_ID)


@runtime_checkable
class Detector(Protocol):
    """Turns one grayscale frame plus prior state into candidate findings."""

    code: str
    category: str
    available: bool
    unavailable_reason: str
    min_frames: int

    def detect(self, frame: np.ndarray, zones: Sequence[Zone], state: DetectorState) -> list[RawFinding]: ...


def _streak_score(streak: int, minimum: int, saturation: int) -> float:
    if streak <= minimum:
        return 0.0
    return max(0.0, min(1.0, (streak - minimum) / max(1, saturation - minimum)))


def _size_score(area: float, height: int, width: int) -> float:
    """Full credit once the blob reaches a believable body footprint."""
    return min(1.0, area / (TARGET_BODY_AREA_FRACTION * float(height * width)))


# --------------------------------------------------------------------------- #
# Implemented detectors
# --------------------------------------------------------------------------- #


class RestrictedZoneEntryDetector:
    """Fires only after person-sized motion persists inside a zone over consecutive frames."""

    code = "restricted_zone_entry"
    category = "restricted_zone_entry"
    available = True
    unavailable_reason = ""
    min_frames = ZONE_ENTRY_MIN_FRAMES

    def detect(self, frame: np.ndarray, zones: Sequence[Zone], state: DetectorState) -> list[RawFinding]:
        motion = state.model.analyze(frame, state.timestamp)
        state.retain([zone.id for zone in zones])

        findings: list[RawFinding] = []
        for zone in zones:
            memory = state.memory(zone.id)
            blobs = blobs_in_zone(motion, zone)
            if not blobs:
                memory.entry_streak = 0
                continue
            largest = max(blobs, key=lambda blob: blob.area)
            memory.entry_streak += 1
            if memory.entry_streak < self.min_frames:
                continue
            confidence = 0.45 + 0.3 * _streak_score(
                memory.entry_streak, self.min_frames, CONFIDENCE_STREAK_SATURATION_FRAMES
            ) + 0.2 * _size_score(largest.area, motion.height, motion.width)
            findings.append(
                RawFinding(
                    category=self.category,
                    confidence=min(0.95, round(confidence, 4)),
                    detail={
                        "zone_id": zone.id,
                        "zone_label": zone.label,
                        "bbox": list(largest.bbox),
                        "blob_area_px": round(largest.area, 2),
                        "blob_count": len(blobs),
                        "motion_frames": memory.entry_streak,
                        "motion_fraction": round(motion.motion_fraction, 6),
                        "detector": self.code,
                    },
                )
            )
        return findings


class UnattendedObjectDetector:
    """Fires on a blob that holds still in a zone while the rest of the scene keeps moving."""

    code = "unattended_object"
    category = "unattended_object"
    available = True
    unavailable_reason = ""
    min_frames = UNATTENDED_MIN_STATIONARY_FRAMES

    def __init__(self, dwell_seconds: float = UNATTENDED_DWELL_SECONDS) -> None:
        self.dwell_seconds = dwell_seconds

    def detect(self, frame: np.ndarray, zones: Sequence[Zone], state: DetectorState) -> list[RawFinding]:
        motion = state.model.analyze(frame, state.timestamp)
        state.retain([zone.id for zone in zones])
        if not motion.usable or motion.motion_fraction < UNATTENDED_MIN_SCENE_MOTION_FRACTION:
            for memory in state.zones.values():
                memory.stationary_streak = 0
                memory.stationary_centroid = None
            return []

        tolerance = UNATTENDED_MAX_CENTER_SHIFT_FRACTION * math.hypot(motion.width, motion.height)
        findings: list[RawFinding] = []
        for zone in zones:
            memory = state.memory(zone.id)
            blobs = blobs_in_zone(motion, zone)
            if not blobs:
                memory.stationary_streak = 0
                memory.stationary_centroid = None
                continue
            candidate = max(blobs, key=lambda blob: blob.area)
            still = (
                memory.stationary_centroid is not None
                and math.hypot(
                    candidate.centroid[0] - memory.stationary_centroid[0],
                    candidate.centroid[1] - memory.stationary_centroid[1],
                )
                <= tolerance
                and abs(candidate.area - memory.stationary_area)
                <= UNATTENDED_MAX_AREA_DRIFT * max(memory.stationary_area, 1.0)
            )
            if still:
                memory.stationary_streak += 1
            else:
                memory.stationary_streak = 1
                memory.stationary_since = motion.timestamp
                memory.stationary_area = candidate.area
            memory.stationary_centroid = candidate.centroid

            if memory.stationary_streak < self.min_frames:
                continue
            dwell = motion.timestamp - memory.stationary_since
            outside = outside_motion_fraction(motion, zone)
            if dwell < self.dwell_seconds or outside < UNATTENDED_MIN_OUTSIDE_MOTION_FRACTION:
                continue
            confidence = 0.4 + 0.3 * min(1.0, dwell / max(1.0, self.dwell_seconds * 2.0)) + 0.2 * min(
                1.0, memory.stationary_streak / float(self.min_frames * 2)
            )
            findings.append(
                RawFinding(
                    category=self.category,
                    confidence=min(0.9, round(confidence, 4)),
                    detail={
                        "zone_id": zone.id,
                        "zone_label": zone.label,
                        "bbox": list(candidate.bbox),
                        "dwell_seconds": round(dwell, 3),
                        "stationary_frames": memory.stationary_streak,
                        "outside_motion_fraction": round(outside, 6),
                        "motion_fraction": round(motion.motion_fraction, 6),
                        "detector": self.code,
                    },
                )
            )
        return findings


class UnusualMovementDetector:
    """Fires on sustained in-zone motion whose centroid path doubles back on itself."""

    code = "unusual_movement"
    category = "unusual_movement"
    available = True
    unavailable_reason = ""
    min_frames = ZONE_ENTRY_MIN_FRAMES

    @staticmethod
    def _reversals(samples: Sequence[tuple[float, float]], axis: int) -> int:
        direction = 0
        reversals = 0
        for previous, current in itertools.pairwise(samples):
            delta = current[axis] - previous[axis]
            if abs(delta) < 1.0:
                continue
            sign = 1 if delta > 0 else -1
            if direction != 0 and sign != direction:
                reversals += 1
            direction = sign
        return reversals

    @staticmethod
    def _path_length(samples: Sequence[tuple[float, float]]) -> float:
        return float(sum(math.hypot(b[0] - a[0], b[1] - a[1]) for a, b in itertools.pairwise(samples)))

    def detect(self, frame: np.ndarray, zones: Sequence[Zone], state: DetectorState) -> list[RawFinding]:
        motion = state.model.analyze(frame, state.timestamp)
        state.retain([zone.id for zone in zones])
        for memory in state.zones.values():
            self._age_trail(memory, motion.timestamp)
        if not motion.usable:
            return []

        findings: list[RawFinding] = []
        for zone in zones:
            memory = state.memory(zone.id)
            blobs = blobs_in_zone(motion, zone)
            if not blobs:
                memory.entry_streak = 0
                continue
            largest = max(blobs, key=lambda blob: blob.area)
            memory.entry_streak += 1
            memory.trail.append((motion.timestamp, largest.centroid[0], largest.centroid[1]))
            self._age_trail(memory, motion.timestamp)
            if memory.entry_streak < self.min_frames or len(memory.trail) < self.min_frames * 2:
                continue

            samples = [(x, y) for _, x, y in memory.trail]
            duration = memory.trail[-1][0] - memory.trail[0][0]
            if duration < LOITER_MIN_DURATION_SECONDS:
                continue
            xs = [x for x, _ in samples]
            ys = [y for _, y in samples]
            span = zone.diagonal(motion.height, motion.width)
            covered = math.hypot(max(xs) - min(xs), max(ys) - min(ys))
            if span > 0.0 and covered > LOITER_MAX_SPAN_FRACTION * span:
                continue
            displacement = math.hypot(samples[-1][0] - samples[0][0], samples[-1][1] - samples[0][1])
            path = self._path_length(samples)
            reversals = max(self._reversals(samples, 0), self._reversals(samples, 1))
            dispersion = path / max(displacement, 1.0)
            if reversals < LOITER_MIN_REVERSALS or dispersion < LOITER_MIN_PATH_DISPERSION_RATIO:
                continue

            confidence = 0.4 + 0.2 * min(1.0, (reversals - LOITER_MIN_REVERSALS + 1) / 4.0) + 0.25 * min(
                1.0, dispersion / 6.0
            )
            findings.append(
                RawFinding(
                    category=self.category,
                    confidence=min(0.88, round(confidence, 4)),
                    detail={
                        "zone_id": zone.id,
                        "zone_label": zone.label,
                        "bbox": list(largest.bbox),
                        "direction_reversals": reversals,
                        "path_dispersion": round(dispersion, 3),
                        "trajectory_seconds": round(duration, 3),
                        "motion_frames": memory.entry_streak,
                        "motion_fraction": round(motion.motion_fraction, 6),
                        "detector": self.code,
                    },
                )
            )
        return findings

    @staticmethod
    def _age_trail(memory: ZoneMemory, timestamp: float) -> None:
        """A gap in analysis or in-zone motion invalidates the trajectory window."""
        cutoff = timestamp - LOITER_WINDOW_SECONDS
        while memory.trail and memory.trail[0][0] < cutoff:
            memory.trail.popleft()
        if memory.trail and timestamp - memory.trail[-1][0] > LOITER_WINDOW_SECONDS:
            memory.trail.clear()


class PhysicalAltercationDetector:
    """Stub that refuses to emit findings: motion geometry cannot recognise an altercation."""

    code = "possible_physical_altercation"
    category = "possible_physical_altercation"
    available = False
    unavailable_reason = STUB_REASONS["possible_physical_altercation"]
    min_frames = 0

    def detect(self, frame: np.ndarray, zones: Sequence[Zone], state: DetectorState) -> list[RawFinding]:
        raise DetectorUnavailableError(self.code, self.unavailable_reason)


class TheftLikeActivityDetector:
    """Stub that refuses to emit findings: object-interaction recognition is not trained here."""

    code = "theft_like_activity"
    category = "theft_like_activity"
    available = False
    unavailable_reason = STUB_REASONS["theft_like_activity"]
    min_frames = 0

    def detect(self, frame: np.ndarray, zones: Sequence[Zone], state: DetectorState) -> list[RawFinding]:
        raise DetectorUnavailableError(self.code, self.unavailable_reason)


# --------------------------------------------------------------------------- #
# Registry
# --------------------------------------------------------------------------- #

DETECTOR_CLASSES: dict[str, type[Detector]] = {
    RestrictedZoneEntryDetector.code: RestrictedZoneEntryDetector,
    UnattendedObjectDetector.code: UnattendedObjectDetector,
    UnusualMovementDetector.code: UnusualMovementDetector,
    PhysicalAltercationDetector.code: PhysicalAltercationDetector,
    TheftLikeActivityDetector.code: TheftLikeActivityDetector,
}


def detector_codes() -> tuple[str, ...]:
    """Every category the analysis layer knows about, available or not."""
    return tuple(DETECTOR_CLASSES)


def available_detector_codes() -> tuple[str, ...]:
    """Categories that can produce findings on this deployment today."""
    return tuple(code for code, cls in DETECTOR_CLASSES.items() if cls.available)


def unavailable_reason(code: str) -> str:
    """Why a registered category cannot run, or an empty string when it can."""
    cls = DETECTOR_CLASSES.get(code)
    if cls is None:
        return "not a recognised detector code"
    if cls.available:
        return ""
    return STUB_REASONS.get(code, "no trained model is available for this category")


def build_detector(code: str) -> Detector:
    """Instantiate a registered detector by its stable code."""
    try:
        cls = DETECTOR_CLASSES[code]
    except KeyError as exc:
        raise KeyError(
            f"unknown detector code {code!r}; registered codes are {', '.join(detector_codes())}"
        ) from exc
    return cls()
