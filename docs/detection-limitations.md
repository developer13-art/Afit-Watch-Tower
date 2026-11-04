# Detection Capability and Limitations

Covers proposal section 11 and the pilot requirement to document detection limitations and
false-positive rates. Read this before enabling AI monitoring on any camera, and before
writing a claim about what the system can detect.

## The single most important fact

**No trained model ships with this deployment.** Everything in
`src/watchtower/analysis/detectors.py` is classical computer vision: background
subtraction, blob geometry and short-lived temporal state. The detectors answer "there is
sustained, person-shaped motion inside this polygon", not "a person is committing an
offence".

That distinction is not a hedge. It determines who may act on an output and what weight the
output carries in any later review.

## What can produce findings today

| Detector code | What it actually fires on | Honest description |
|---|---|---|
| `restricted_zone_entry` | person-shaped motion persisting inside a configured zone across `ZONE_ENTRY_MIN_FRAMES` (3) consecutive analysed frames | motion geometry, not identity or intent |
| `unattended_object` | a blob that stays stationary in a zone for `UNATTENDED_DWELL_SECONDS` (8 s) while the rest of the scene keeps moving | needs ongoing scene motion; an empty, still scene never triggers it |
| `unusual_movement` | sustained in-zone motion whose centroid path reverses on itself `LOITER_MIN_REVERSALS` (3) times within `LOITER_WINDOW_SECONDS` (12 s), with path dispersion above 2.5 and span under 80% of the zone diagonal | an approximation of "pacing/loitering"; someone walking slowly across the frame does not qualify |

Confidence is a weighted combination of how long the pattern persisted and how
person-shaped the blob is, capped at 0.95. It is a **ranking signal for the reviewer's
queue**, not a probability, not calibrated, and not comparable across cameras. Never quote
it as an accuracy figure.

## What deliberately cannot produce findings

| Detector code | Status |
|---|---|
| `possible_physical_altercation` | registered, `available = False` |
| `theft_like_activity` | registered, `available = False` |

These are the two proposal categories that require recognition rather than motion geometry.
They are implemented as stubs that **raise `DetectorUnavailableError` instead of emitting a
finding**. That design choice is the point: a heuristic "altercation detector" built on
blob velocity would fire on two people walking past each other, and an institution that
receives that alert cannot tell it apart from a real one. Motion heuristics cannot tell a
scuffle from a greeting, or a theft from someone picking up their own bag.

Enabling these categories on a policy is rejected with the recorded reason, and
`available_detector_codes()` reports what the deployment can actually do. **A category the
system cannot compute must not be listed as a capability in any proposal update, status
report or dashboard label.**

## Known failure modes

Each of these produces false positives or false negatives in a real AFIT deployment. All of
them are unmeasured here — the pilot measures them.

**False positives**
- Lighting steps: sunlight across a driveway as clouds move, a headlight sweep, a lamp
  switching on. Mitigated by `SCENE_WIDE_CHANGE_MAX` (motion over 45% of the frame is read
  as an illumination change, not an intruder), not eliminated.
- Vegetation in wind — trees, shrubs, tall grass. Partially mitigated by the fill-ratio and
  area bounds; a swaying palm at a gate is still a plausible trigger.
- Water, reflections, steam, heat shimmer, rain and dust.
- Insects and birds crossing very close to the lens.
- Vehicles: a car is person-shaped enough at CCTV framing to satisfy the geometry filters
  when it enters a restricted zone. If a zone includes a roadway, expect it to fire.
- Camera motion: a knocked or vibrating camera makes the whole frame change at once.
- Compression artefacts on a low-bitrate stream, especially around JPEG quality 78 where
  `MIN_DIFF_FLOOR` was chosen for lit indoor scenes — a dark, noisy outdoor scene at night
  sits closer to the floor.

**False negatives**
- A person standing still. The detectors need motion; motion after a long dwell takes
  several frames to re-accumulate confidence.
- A person who is small in frame, partially occluded, or whose silhouette does not meet the
  aspect and fill bounds.
- Slow approach: motion below the per-frame diff floor is read as noise.
- Night-time infrared scenes, where contrast and texture differ from the tuning assumptions.
- A background that has absorbed a stopped object. The learning rate is deliberately ~50
  analysed frames so unattended-object dwells stay meaningful; a very long dwell becomes
  background.

**Structural limits**
- No person detection, no face recognition, no object classification, no re-identification.
  The system cannot say who, or what an object is.
- Single background model per camera. A scene change (truck parked in view) degrades
  everything until it is re-learned or the camera is toggled.
- Zone state lives in memory only and is discarded on reconnect (`AnalysisEngine.reset()`),
  so a streak never survives an interruption — which is correct behaviour and also means a
  flapping camera cannot build dwell evidence.
- Sampling is bounded by `WATCHTOWER_ANALYSIS_FPS` as a platform ceiling across all enabled
  cameras, so adding cameras reduces per-camera analysis rate. Detection latency is a
  function of the total enabled fleet, not of one camera's frame rate.
- Detection depends on a polygon drawn by a human. A mis-drawn zone is a silent
  misconfiguration; the dashboard must show the zone over the live frame so this is
  reviewable.

## Configuration reality

Thresholds are module constants with deliberate values (`ZONE_ENTRY_MIN_FRAMES`,
`UNATTENDED_DWELL_SECONDS`, `LOITER_*`) and a documented reason for each — not deployment
settings. Only these are configurable:

- which detectors a policy enables;
- per-policy `analysis_fps`, bounded by the platform ceiling;
- per-policy detection zones;
- `WATCHTOWER_DETECTION_MIN_CONFIDENCE` as the floor for creating an event;
- `WATCHTOWER_DUPLICATE_EVENT_WINDOW` for suppression.

If the pilot shows that these are not enough, the answer is a validated model and
site-specific evaluation — not a fifth tunable knob adjusted until the demo looks good. A
threshold changed to make one demonstration pass is a threshold that hides the next
incident.

## Governance of an output

Three rules, enforced in code and restated here because they are what makes this component
usable in a security context:

1. **A detection is a candidate event, never a conclusion.** It enters the incident queue
   for a human. Nothing in the system escalates on detector output alone, and no automated
   action is taken from it.
2. **Camera-health events are separate from security detections.** A disconnected camera is
   an operational problem and must not be filed as an incident about a person.
3. **Duplicate suppression must not hide sustained activity.** A suppressed repeat updates
   the existing event's timestamps rather than creating noise; the reviewer sees the span.

## Before any accuracy claim is made

Required measurements, from the pilot in `docs/pilot-evaluation.md`:

- true positives, false positives and missed events counted against independently reviewed
  ground truth, per camera and per category;
- precision/recall with confidence intervals, not a single decimal;
- time-to-detection distribution;
- alerts per operator per shift, and the resulting acknowledgement rate — a system that
  trains its users to ignore alerts has failed regardless of its recall.

Until those exist, the correct statement about detection performance is: **not measured in
the AFIT environment**. No precision, recall or false-positive figure appears anywhere in
this codebase, and none should be added from a vendor datasheet.

## Interim recommendation

Phase 1 should run with **`--no-analysis`**, or with analysis enabled on one camera and no
detection categories enabled, while the ingestion, health and incident paths are validated
against the real environment. Section 19 Phase 5 asks for "one validated detection
workflow"; validation requires the site data above, which is a pilot output rather than an
assumption that can be made now.
