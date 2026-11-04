"""Candidate events, confidence gating and duplicate suppression (proposal section 11).

Every frame here is synthetic: the cameras are not present, so what is being proved is the
promise section 11 actually makes - a person-shaped, persistent change inside an approved zone
becomes one reviewable candidate, and a busy zone does not become an alert storm. Nothing in
this file asserts detection accuracy; see `docs/detection-limitations.md`.
"""

from __future__ import annotations

import datetime as dt
import math
from pathlib import Path

import cv2
import numpy as np
import pytest
from sqlalchemy import select

from watchtower.analysis import detectors as D
from watchtower.analysis.engine import AnalysisEngine
from watchtower.analysis.events import (
    LocalEvidenceWriter,
    build_dedupe_key,
    dedupe_base,
    effective_min_confidence,
    effective_window_seconds,
    recent_event,
    sanitize_metadata,
    submit_finding,
    submit_findings,
)
from watchtower.config import Settings
from watchtower.models import DetectionEvent, MonitoringPolicy

WIDTH, HEIGHT = 320, 240
BASE_GRAY = 40
OBJECT_GRAY = 215
# 20x40 px is 800 px of a 76800 px frame: above MIN_BLOB_AREA_FRACTION, below the body
# footprint, taller than it is wide, and edge-long enough to clear MIN_BLOB_EDGE_PIXELS.
OBJECT_BOX = (60, 100, 20, 40)
GATE_ZONE = {
    "id": "gate",
    "name": "Gate apron",
    "polygon": [[0.0, 0.0], [0.6, 0.0], [0.6, 1.0], [0.0, 1.0]],
}
ALERT_ZONE = {
    "id": "store",
    "name": "Store door",
    "polygon": [[0.7, 0.0], [1.0, 0.0], [1.0, 1.0], [0.7, 1.0]],
}
ENTRY = "restricted_zone_entry"
SNAPSHOT = b"\xff\xd8\xff\xe0fake-jpeg\xff\xd9"


# --------------------------------------------------------------------------- #
# Synthetic video
# --------------------------------------------------------------------------- #


def scene(*, moved: int = 0) -> np.ndarray:
    """A still frame, optionally with the object displaced `moved` pixels to the right."""
    gray = np.full((HEIGHT, WIDTH), BASE_GRAY, dtype=np.uint8)
    gray[12:28, 250:300] = BASE_GRAY + 12  # static structure, so the scene is not flat
    if moved:
        x, y, w, h = OBJECT_BOX
        gray[y : y + h, x + moved : x + moved + w] = OBJECT_GRAY
    else:
        x, y, w, h = OBJECT_BOX
        gray[y : y + h, x : x + w] = OBJECT_GRAY
    return gray


def empty_scene() -> np.ndarray:
    gray = np.full((HEIGHT, WIDTH), BASE_GRAY, dtype=np.uint8)
    gray[12:28, 250:300] = BASE_GRAY + 12
    return gray


def as_jpeg(gray: np.ndarray) -> bytes:
    ok, buffer = cv2.imencode(".jpg", cv2.cvtColor(gray, cv2.COLOR_GRAY2BGR))
    assert ok
    return buffer.tobytes()


class ScriptedFrames:
    """A `FrameSource` that hands out one prepared frame per poll, on the timestamps we choose."""

    def __init__(self, frames: list[tuple[float, bytes]], *, hold_last: bool = False) -> None:
        self._frames = [(stamp, jpeg, 12.0) for stamp, jpeg in frames]
        self._hold_last = hold_last
        self.polled = 0

    def latest_frame(self, camera_id: str):
        if self.polled < len(self._frames):
            frame = self._frames[self.polled]
            self.polled += 1
            return frame
        if not self._hold_last:
            # The stream simply stops, which is what the no-frame paths are written for.
            self.polled += 1
            return self._frames[-1]
        stamp, jpeg, fps = self._frames[-1]
        self.polled += 1
        return (stamp + (self.polled - len(self._frames)) * 0.5, jpeg, fps)


def frame_times(count: int, *, start: float = 1_700_000_000.0, step: float = 0.5) -> list[float]:
    return [start + index * step for index in range(count)]


def walk_in(engine_frames: int = 7) -> list[tuple[float, bytes]]:
    """An empty scene, then an object that appears and holds still in the gate zone."""
    stamps = frame_times(engine_frames)
    frames = [(stamps[0], as_jpeg(empty_scene()))]
    for stamp in stamps[1:]:
        frames.append((stamp, as_jpeg(scene())))
    return frames


def analysed_camera(factory, settings: Settings, *, zones=None, detectors=(ENTRY,), **policy_kw):
    camera = factory.camera()
    policy = factory.policy(detectors=detectors, **policy_kw)
    policy.zones = [GATE_ZONE] if zones is None else zones
    policy.analysis_fps = 4.0
    factory.session.flush()
    camera.monitoring_policy_id = policy.id
    factory.session.flush()
    return camera, policy


def build_engine(
    settings, frames: list[tuple[float, bytes]], *, evidence_root: Path | None = None, hold_last=False
):
    return AnalysisEngine(
        settings,
        ScriptedFrames(frames, hold_last=hold_last),
        evidence_writer=LocalEvidenceWriter(evidence_root) if evidence_root else None,
    )


def poll(engine, db, camera, policy, times: int):
    """Run the analysis pass `times`, one frame per pass, as the background poller would."""
    created = []
    for _ in range(times):
        created.extend(engine.run(db, camera, policy))
    db.commit()
    return created


def events_in(db) -> list[DetectionEvent]:
    db.expire_all()
    return db.scalars(select(DetectionEvent).order_by(DetectionEvent.occurred_at)).all()


# --------------------------------------------------------------------------- #
# Detector level: geometry and persistence, not guesses
# --------------------------------------------------------------------------- #


def run_detector(detector, frames: list[np.ndarray], zones: list[D.Zone]) -> list[D.RawFinding]:
    """Feed one grayscale frame at a time through a detector with its own motion model."""
    state = D.DetectorState(
        camera_id="cam-1", detector_code=detector.code, model=D.MotionModel(), timestamp=0.0
    )
    findings: list[D.RawFinding] = []
    for index, gray in enumerate(frames, start=1):
        state.timestamp = float(index)
        findings.extend(detector.detect(gray, zones, state))
    return findings


def test_an_unchanging_scene_produces_no_candidate():
    zones = D.zones_from_policy([GATE_ZONE])
    assert zones, "the policy geometry must build an analysable zone"
    findings = run_detector(D.build_detector(ENTRY), [empty_scene()] * 8, zones)
    assert findings == []


def test_a_single_frame_of_motion_is_not_reported():
    """One loud frame is a leaf, a bird or a compression artefact; section 11 requires persistence."""
    zones = D.zones_from_policy([GATE_ZONE])
    frames = [empty_scene(), scene(), empty_scene(), empty_scene(), empty_scene()]
    assert run_detector(D.build_detector(ENTRY), frames, zones) == []


def test_sustained_motion_inside_the_approved_zone_is_a_candidate():
    zones = D.zones_from_policy([GATE_ZONE])
    findings = run_detector(D.build_detector(ENTRY), [empty_scene(), *[scene()] * 6], zones)
    assert len(findings) >= 1
    finding = findings[0]
    assert finding.category == ENTRY
    assert finding.zone_id == "gate"
    assert finding.confidence >= 0.55, "must clear the platform floor to be reviewable"
    assert math.isfinite(finding.confidence)
    bbox = finding.detail["bbox"]
    assert len(bbox) == 4 and bbox[2] > 0 and bbox[3] > 0


def test_the_same_motion_outside_every_approved_zone_is_not_reported():
    zones = D.zones_from_policy([ALERT_ZONE])
    findings = run_detector(D.build_detector(ENTRY), [empty_scene(), *[scene()] * 6], zones)
    assert findings == [], "geometry is the scope of the detector, not a label on the finding"


def test_a_walking_subject_advances_through_the_zone_over_successive_frames():
    """The blob follows the object, which is what makes the bbox worth showing a reviewer."""
    zones = D.zones_from_policy([GATE_ZONE])
    frames = [empty_scene()] + [scene(moved=step) for step in range(0, 80, 8)]
    findings = run_detector(D.build_detector(ENTRY), frames, zones)
    assert findings, "sustained movement across the zone still qualifies as entry"
    last_x = findings[-1].detail["bbox"][0]
    assert last_x > findings[0].detail["bbox"][0]


def test_a_scene_wide_illumination_step_is_not_reported_as_intruder():
    zones = D.zones_from_policy([GATE_ZONE])
    dark = np.full((HEIGHT, WIDTH), 30, dtype=np.uint8)
    bright = np.full((HEIGHT, WIDTH), 200, dtype=np.uint8)
    frames = [dark, dark, bright, bright, bright, bright]
    assert run_detector(D.build_detector(ENTRY), frames, zones) == []


# --------------------------------------------------------------------------- #
# Availability: the two recognition categories are registered, not run
# --------------------------------------------------------------------------- #


def test_the_recognition_stubs_refuse_to_emit_findings():
    zones = D.zones_from_policy([GATE_ZONE])
    for code in ("possible_physical_altercation", "theft_like_activity"):
        detector = D.build_detector(code)
        assert detector.available is False
        with pytest.raises(D.DetectorUnavailableError) as excinfo:
            run_detector(detector, [empty_scene(), scene(), scene(), scene()], zones)
        assert excinfo.value.code == code
        assert excinfo.value.reason


def test_only_runnable_detectors_are_listed_as_available():
    assert set(D.available_detector_codes()) == {
        "restricted_zone_entry",
        "unattended_object",
        "unusual_movement",
    }
    assert set(D.detector_codes()) - set(D.available_detector_codes()) == {
        "possible_physical_altercation",
        "theft_like_activity",
    }
    assert D.unavailable_reason(ENTRY) == ""
    assert D.unavailable_reason("possible_physical_altercation")


def test_an_unregistered_code_is_rejected_rather_than_silently_ignored():
    with pytest.raises(KeyError):
        D.build_detector("loitering")


# --------------------------------------------------------------------------- #
# Engine level: frames in, database rows out
# --------------------------------------------------------------------------- #


def test_the_engine_turns_a_frame_into_a_persisted_candidate(db, factory, settings, tmp_path):
    camera, policy = analysed_camera(factory, settings)
    engine = build_engine(settings, walk_in(7), evidence_root=tmp_path / "evidence")

    poll(engine, db, camera, policy, 7)

    rows = events_in(db)
    assert len(rows) == 1, "sustained motion is one situation, not one row per frame"
    event = rows[0]
    assert event.camera_id == camera.id
    assert event.policy_id == policy.id
    assert event.category == ENTRY
    assert event.confidence >= settings.detection_min_confidence
    assert event.status == "new"
    assert event.suppressed is False
    assert event.dedupe_key.startswith(f"{camera.id}|{ENTRY}|gate|w")

    metadata = event.event_metadata
    assert metadata["zone_id"] == "gate"
    assert metadata["zone_source"] == "policy"
    assert metadata["camera_code"] == camera.code
    assert metadata["bbox"][2] > 0
    assert metadata["detector"] == ENTRY
    assert metadata["measured_fps"] == 12.0
    assert metadata["seen_count"] > 1, "the later frames were folded into this row"
    assert metadata["snapshot"]["storage_key"].endswith(".jpg")


def test_the_engine_delivers_one_snapshot_per_event_not_one_per_frame(
    db, factory, settings, tmp_path
):
    camera, policy = analysed_camera(factory, settings)
    root = tmp_path / "evidence"
    engine = build_engine(settings, walk_in(9), evidence_root=root)

    poll(engine, db, camera, policy, 6)

    files = sorted(root.glob("*/*/*/*.jpg"))
    assert len(files) == 1, "the alert wrote evidence; its suppressed repeats wrote nothing"
    assert len(events_in(db)) == 1


def test_a_policy_without_approved_geometry_reports_the_full_frame_fallback(
    db, factory, settings
):
    camera, policy = analysed_camera(factory, settings, zones=[])
    engine = build_engine(settings, walk_in(7))

    assert poll(engine, db, camera, policy, 7), "a detector with no geometry watches the whole frame"
    metadata = events_in(db)[0].event_metadata
    assert metadata["zone_source"] == "full_frame_fallback"
    assert metadata["zone_id"] == D.FULL_FRAME_ZONE_ID


def test_a_disabled_policy_is_never_analysed(db, factory, settings):
    camera, policy = analysed_camera(factory, settings, enabled=False)
    engine = build_engine(settings, walk_in(7))

    assert engine.run(db, camera, policy) == []
    assert engine.run_enabled_cameras(db, [camera]) == []
    db.commit()
    assert events_in(db) == []


def test_a_camera_with_no_video_is_skipped_without_failing_the_poll(db, factory, settings):
    camera, policy = analysed_camera(factory, settings)
    engine = AnalysisEngine(settings, ScriptedFrames([(1_700_000_000.0, b"not-a-jpeg")]))

    assert engine.run(db, camera, policy) == []
    db.commit()
    assert events_in(db) == []


def test_the_engine_names_the_detectors_that_did_not_run(db, factory, settings):
    """An operator must be able to see that altercation detection is not watching, not assume it."""
    camera, policy = analysed_camera(
        factory, settings, detectors=(ENTRY, "possible_physical_altercation", "made_up_code")
    )
    engine = build_engine(settings, walk_in(7))

    created = poll(engine, db, camera, policy, 7)
    assert {event.category for event in created} == {ENTRY}

    status = engine.detector_status(str(camera.id))
    assert status[ENTRY] == "active"
    assert status["possible_physical_altercation"].startswith("not analysed:")
    assert "made_up_code" in status


def test_a_reset_makes_the_engine_relearn_the_scene_before_it_reports_again(
    db, factory, settings
):
    """Section 11: a reconnected stream may be a different scene, so its counters start over."""
    camera, policy = analysed_camera(factory, settings)
    stamps = frame_times(14)
    frames = [(stamps[0], as_jpeg(empty_scene()))]
    frames += [(stamp, as_jpeg(scene())) for stamp in stamps[1:8]]
    # After the reset the object walks on to a new position, which is motion only if the
    # baseline was rebuilt from the frame it arrived with.
    frames.append((stamps[8], as_jpeg(scene())))
    frames += [(stamp, as_jpeg(scene(moved=40))) for stamp in stamps[9:]]
    engine = build_engine(settings, frames)

    poll(engine, db, camera, policy, 8)
    assert events_in(db), "the intrusion was reported before the reset"

    engine.reset(str(camera.id))
    assert engine.run(db, camera, policy) == [], "the first analysed frame is a baseline, not a finding"

    reported = poll(engine, db, camera, policy, 5)
    db.commit()
    assert reported, "motion against the rebuilt baseline is reported again"
    rows = events_in(db)
    assert len(rows) == 1, "the same situation in the same window is still one candidate"
    assert rows[0].event_metadata["seen_count"] > 1


# --------------------------------------------------------------------------- #
# Confidence gating
# --------------------------------------------------------------------------- #


def submit(db, factory, settings, *, confidence, category=ENTRY, zone="gate", occurred_at=None, **kw):
    camera = kw.pop("camera", None) or factory.camera()
    policy = factory.policy(detectors=(category,))
    policy.min_confidence = kw.pop("policy_min_confidence", 0.55)
    factory.session.flush()
    finding = D.RawFinding(category=category, confidence=confidence, detail={"zone_id": zone})
    outcomes = submit_findings(
        db,
        camera=camera,
        policy=policy,
        settings=settings,
        findings=[finding],
        occurred_at=occurred_at or dt.datetime.now(dt.UTC),
        **kw,
    )
    db.commit()
    return camera, policy, outcomes


def test_a_finding_below_the_floor_is_not_persisted(db, factory, settings):
    _, _, outcomes = submit(db, factory, settings, confidence=0.4)
    assert outcomes == []
    assert events_in(db) == []


def test_a_finding_at_the_floor_is_persisted(db, factory, settings):
    _, _, outcomes = submit(db, factory, settings, confidence=0.55)
    assert len(outcomes) == 1 and outcomes[0].alert is True


@pytest.mark.parametrize(
    ("policy_min", "floor", "expected"),
    [(0.20, 0.55, 0.55), (0.70, 0.55, 0.70), (0.10, 0.30, 0.30)],
)
def test_the_stricter_of_policy_and_platform_floor_governs(
    db, factory, settings, policy_min, floor, expected
):
    settings.detection_min_confidence = floor
    policy = MonitoringPolicy(code="GATE-1", name="Gate", min_confidence=policy_min)
    assert effective_min_confidence(settings, policy) == expected


@pytest.mark.parametrize("confidence", [float("nan"), math.inf, -1.0])
def test_an_impossible_confidence_is_reflected_rather_than_recorded(db, factory, settings, confidence):
    _, _, outcomes = submit(db, factory, settings, confidence=confidence)
    assert outcomes == []
    assert events_in(db) == []


def test_a_just_below_the_policy_target_never_reaches_the_queue(db, factory, settings):
    _, _, outcomes = submit(
        db, factory, settings, confidence=0.64, policy_min_confidence=0.65
    )
    assert outcomes == []


# --------------------------------------------------------------------------- #
# Duplicate suppression
# --------------------------------------------------------------------------- #


def stamp_at(seconds: float, *, window: int = 90) -> dt.datetime:
    """Seconds after the start of its own window bucket, so a close repeat is a same-bucket repeat.

    Buckets are absolute (`epoch // window`), not relative to the first event, and a test that
    ignored that would silently be testing the next bucket instead of the duplicate window.
    """
    base = (1_700_000_000.0 // window) * window
    return dt.datetime.fromtimestamp(base + seconds, dt.UTC)


def submit_at(
    db, factory, settings, *, at_seconds, confidence=0.8, category=ENTRY, zone="gate",
    camera=None, window=90, snapshot=None, evidence_writer=None,
):
    camera = camera or factory.camera()
    policy = factory.policy(detectors=(category,))
    policy.duplicate_window_seconds = window
    factory.session.flush()
    outcome = submit_finding(
        db,
        camera=camera,
        policy=policy,
        settings=settings,
        finding=D.RawFinding(category=category, confidence=confidence, detail={"zone_id": zone}),
        occurred_at=stamp_at(at_seconds, window=window),
        snapshot=snapshot,
        evidence_writer=evidence_writer,
    )
    db.commit()
    return camera, policy, outcome


def test_a_repeat_inside_the_window_updates_the_event_instead_of_alerting_again(
    db, factory, settings
):
    camera, _, first = submit_at(db, factory, settings, at_seconds=0)
    assert first.alert and first.event.event_metadata["seen_count"] == 1

    _, _, repeat = submit_at(db, factory, settings, at_seconds=40, camera=camera)
    assert repeat is not None
    assert repeat.duplicate and repeat.suppressed and repeat.alert is False
    assert repeat.reason in {"same_window", "overlapping_window"}
    db.expire_all()
    rows = events_in(db)
    assert len(rows) == 1, "a busy zone must not become an alert storm"
    assert rows[0].event_metadata["seen_count"] == 2


def test_the_suppressed_repeat_raises_the_peak_confidence_it_saw(db, factory, settings):
    camera, _, _first = submit_at(db, factory, settings, at_seconds=0, confidence=0.6)
    _, _, stronger = submit_at(db, factory, settings, at_seconds=30, camera=camera, confidence=0.9)
    assert not stronger.alert
    db.expire_all()
    event = events_in(db)[0]
    assert event.event_metadata["peak_confidence"] == pytest.approx(0.9)
    assert event.event_metadata["seen_count"] == 2
    assert event.confidence == pytest.approx(0.6), "the alerting row keeps its own confidence"


def test_a_later_window_alerts_again(db, factory, settings):
    camera, _, first = submit_at(db, factory, settings, at_seconds=0, window=60)
    _, _, later = submit_at(db, factory, settings, at_seconds=180, camera=camera, window=60)
    assert later is not None and later.alert is True
    assert first.event.dedupe_key != later.event.dedupe_key
    db.expire_all()
    assert len(events_in(db)) == 2


def test_a_different_zone_is_a_different_situation(db, factory, settings):
    camera, _, first = submit_at(db, factory, settings, at_seconds=0, zone="gate")
    _, _, other = submit_at(db, factory, settings, at_seconds=5, camera=camera, zone="store")
    assert other is not None and other.alert is True
    assert first.event.dedupe_key != other.event.dedupe_key
    db.expire_all()
    assert len(events_in(db)) == 2


def test_a_different_camera_is_a_different_situation(db, factory, settings):
    submit_at(db, factory, settings, at_seconds=0)
    _, _, elsewhere = submit_at(db, factory, settings, at_seconds=5)
    assert elsewhere is not None and elsewhere.alert is True
    db.expire_all()
    assert len(events_in(db)) == 2


def test_a_keyed_repeat_in_the_next_bucket_is_still_suppressed(db, factory, settings):
    """Time-bucketed keys can straddle a boundary; the window lookback is what catches it."""
    camera, _, first = submit_at(db, factory, settings, at_seconds=10, window=60)
    # 59 and 61 fall in adjacent 60-second buckets while being two seconds apart.
    _, _, overlap = submit_at(db, factory, settings, at_seconds=61, camera=camera, window=60)
    assert overlap is not None
    assert overlap.suppressed and overlap.alert is False
    assert first.event.dedupe_key != overlap.event.dedupe_key
    assert overlap.event.event_metadata["duplicate_of_event_id"] == first.event.id


def test_the_base_key_is_the_situation_and_the_bucket_is_the_window(db, factory, settings):
    key_a = build_dedupe_key(
        camera_id="cam", category=ENTRY, zone_id="gate",
        occurred_at=stamp_at(0, window=90), window_seconds=90,
    )
    key_b = build_dedupe_key(
        camera_id="cam", category=ENTRY, zone_id="gate",
        occurred_at=stamp_at(89, window=90), window_seconds=90,
    )
    key_c = build_dedupe_key(
        camera_id="cam", category=ENTRY, zone_id="gate",
        occurred_at=stamp_at(91, window=90), window_seconds=90,
    )
    assert key_a == key_b
    assert key_a != key_c
    assert key_a.rsplit("|w", 1)[0] == dedupe_base(camera_id="cam", category=ENTRY, zone_id="gate")


def test_the_platform_window_is_a_floor_not_a_suggestion(db, factory, settings):
    policy = MonitoringPolicy(code="W-1", name="W", duplicate_window_seconds=1)
    assert effective_window_seconds(settings, policy) >= 5


def test_recent_event_finds_the_matching_base_only_within_the_window(db, factory, settings):
    camera, _, outcome = submit_at(db, factory, settings, at_seconds=0, window=60)
    base = dedupe_base(camera_id=camera.id, category=ENTRY, zone_id="gate")

    found = recent_event(db, camera_id=camera.id, base_key=base, since=stamp_at(-30, window=60))
    assert found is not None and found.id == outcome.event.id

    too_old = recent_event(db, camera_id=camera.id, base_key=base, since=stamp_at(30, window=60))
    assert too_old is None


def test_a_matching_base_key_from_another_zone_is_not_a_duplicate(db, factory, settings):
    camera, _, _outcome = submit_at(db, factory, settings, at_seconds=0, window=60)
    other_zone = dedupe_base(camera_id=camera.id, category=ENTRY, zone_id="store")
    assert recent_event(
        db, camera_id=camera.id, base_key=other_zone, since=stamp_at(-30, window=60)
    ) is None


def test_a_new_event_does_not_link_to_itself(db, factory, settings):
    _, _, outcome = submit_at(db, factory, settings, at_seconds=0)
    assert "duplicate_of_event_id" not in outcome.event.event_metadata


# --------------------------------------------------------------------------- #
# What the metadata is allowed to contain
# --------------------------------------------------------------------------- #


def test_metadata_carries_scalars_and_no_pixel_payload(db, factory, settings):
    camera = factory.camera()
    finding = D.RawFinding(
        category=ENTRY,
        confidence=0.8,
        detail={
            "zone_id": "gate",
            "bbox": [1, 2, 20, 40],
            "mask": np.zeros((8, 8), dtype=np.uint8),
            "rtsp_url": "rtsp://admin:sup3r-secret-pw@10.20.0.5:554/cam/realmonitor",
            "nested": {"password": "sup3r-secret-pw"},
        },
    )
    metadata = sanitize_metadata(finding, camera=camera, zone_source="policy")
    flat = str(metadata)
    assert "sup3r-secret-pw" not in flat
    assert "rtsp://" not in flat or "***" in flat
    assert metadata["mask"] is None, "a pixel array is not a reviewable fact"
    assert metadata["bbox"] == [1, 2, 20, 40]


def test_persisted_metadata_holds_no_credential_for_the_camera_that_produced_it(
    db, factory, settings
):
    camera = factory.camera(password="sup3r-secret-pw")
    finding = D.RawFinding(
        category=ENTRY,
        confidence=0.9,
        detail={
            "zone_id": "gate",
            "url": "rtsp://admin:sup3r-secret-pw@10.20.0.5/x",
            "rtsp_password": "sup3r-secret-pw",
        },
    )
    outcome = submit_finding(
        db,
        camera=camera,
        policy=factory.policy(detectors=(ENTRY,)),
        settings=settings,
        finding=finding,
        occurred_at=dt.datetime.now(dt.UTC),
    )
    db.commit()
    db.expire_all()
    row = db.get(DetectionEvent, outcome.event.id)
    assert "sup3r-secret-pw" not in str(row.event_metadata)
    assert row.event_metadata["rtsp_password"] == "***"
