# Controlled Pilot Evaluation Plan

Covers proposal sections 21 and 19 Phase 7. The proposal's own rule applies here:
**targets are established during baseline testing rather than assumed before measurement.**
This plan therefore defines what to measure, how, and from where — it deliberately does not
state acceptable values. Filling in a target before the baseline exists is how a pilot
becomes a demonstration.

## Gate before the pilot starts

All of these must be true, in writing, before any operational camera is registered:

- [ ] AFIT authorization for the pilot scope: which cameras, which locations, which
      personnel have accounts, what is recorded, and for how long.
- [ ] Section 19 Phase 1 complete — camera models verified individually, with the RTSP
      configuration recorded per the runbook. No model is assumed compatible because a
      similar one worked.
- [ ] Each pilot camera has passed a connection test **from the deployment host**, not from
      a technician's laptop (section 22, "Network restrictions").
- [ ] Real-camera verification items 1-6 in `docs/testing.md` performed and documented.
- [ ] HTTPS enforced, `WATCHTOWER_ENVIRONMENT=pilot`, key ring backed up separately.
- [ ] Roles issued per person; no shared administrator account.
- [ ] Retention rules agreed and the purge schedule installed.
- [ ] `docs/detection-limitations.md` read by the reviewers who will act on alerts.
- [ ] Data protection / privacy sign-off for storing images of identifiable people, with the
      lawful basis named by the institution rather than by this project.

## Metrics (section 21)

| # | Metric | How to measure | Source |
|---|---|---|---|
| 1 | Percentage of supported cameras successfully registered | (cameras reaching `online`) / (cameras attempted), per model | `cameras.status`, registration audit rows |
| 2 | Successful connection-test rate | count `ProbeResult` outcomes by result, per camera model | probe results recorded at registration, `audit_logs` |
| 3 | Live-feed startup time | time from `POST /api/live/sessions` to first JPEG delivered in the relay | client-side mark in the dashboard, plus session `opened_at` vs first frame |
| 4 | Stream uptime and interruption frequency | uptime = frames-delivering wall time / total; count health transitions per camera per day | `camera_health_events`, `camera_stream_sessions` |
| 5 | Average reconnection time | mean interval from `reconnecting` to `online` | `camera_health_events` timestamp deltas |
| 6 | Camera-health alert accuracy | compare alerts against an independently kept log of real outages; record missed outages and spurious alerts separately | `camera_health_events` vs manual log |
| 7 | Detection precision and false-positive rate | review **every** candidate event in the period; classify true / false / unresolvable. Report as counts with intervals, per category and per camera | `detection_events`, `incidents.outcome`, false-positive markings |
| 8 | Time between candidate event and notification | `notifications.created_at - detection_events.created_at` | database query |
| 9 | Time required for operators to acknowledge events | `first acknowledgement action - event creation`, reported as median and 95th percentile, not mean | `incident_actions` |
| 10 | Unauthorized-access test results | pass/fail against the security test list in `docs/testing.md`, including cross-group camera access and evidence retrieval by an out-of-scope user | test run + `audit_logs` |
| 11 | Evidence retrieval success rate | successful authorized retrievals / retrieval attempts, and every failure classified (permission, retention-expired, integrity mismatch) | audit rows + SHA-256 verification on read |
| 12 | System resource consumption at increasing camera counts | CPU, RSS, per-worker memory, bytes/sec egress and dropped/late frames measured at 1, then +1 up to the configured ceiling | host metrics + `camera_stream_sessions` telemetry |

## Baseline procedure for metric 12

Section 22 names video-processing load as a risk and prescribes "benchmark one stream,
increase gradually". Follow it literally:

1. One camera, `--no-analysis`. Record CPU, memory, egress, measured fps.
2. Add one camera at a time up to `WATCHTOWER_MAX_CONCURRENT_STREAMS`. Do not jump.
3. At each step, note when `degraded` transitions begin appearing — that is the practical
   ceiling, and it is usually earlier than the CPU number suggests.
4. Then enable analysis on one camera and repeat the measurement at the same camera count.
   Analysis cost is bounded by `WATCHTOWER_ANALYSIS_FPS` as a **platform-wide ceiling**, so
   per-camera analysis rate falls as cameras are added. Record that curve.
5. Only then propose a capacity number, and only for that hardware.

Keep `WATCHTOWER_MAX_CONNECTION_TESTS` low during the baseline. Concurrent probes against a
half-configured camera can saturate the camera's own RTSP server and produce failures that
look like incompatibility but are self-inflicted load.

## Qualitative evaluation

Numbers above do not tell you whether the system is used. Add:

- **Alert workload per operator per shift** (an explicit pilot requirement). If this is
  high enough that reviewers begin dismissing without opening evidence, the pilot has
  produced an unreliable system regardless of its measured precision.
- **Time-to-awareness comparison.** For incidents that occurred during the pilot, compare
  when the event happened against when security first knew — recorded discovery versus
  AFIT's existing process. This is the project's actual hypothesis: that awareness improves,
  not that detection is accurate.
- **Workflow fit.** Can operators find the camera, view the frame, and file the incident
  without assistance? Record every step where a reviewer had to ask for help.
- **False-positive tolerance.** Ask the reviewers directly what rate they would accept,
  before the numbers arrive, so the target is an operational judgement rather than a
  technical one.

## Reporting and the expansion gate

Produce one report per pilot phase containing: the twelve metrics with their measured
values, the per-model compatibility record, every security test result, the incident
register with outcomes, and an explicit **"not measured"** list.

Expansion beyond the pilot requires, per sections 19 and 22:

- documented measured results;
- AFIT approval obtained *before* expanding, not after;
- per-model configuration recorded for any new camera;
- a decision on each unmeasured item, rather than an assumption.

## Known gaps this pilot will not close

State these in the report rather than letting them be inferred as successes:

- **No trained detection model exists.** Altercation and theft-like categories cannot
  produce findings at all (`available = False`), so their precision is undefined, not zero —
  and must not be reported as though a capability was tested.
- **WebRTC/HLS is not implemented.** Live view is the JPEG relay, so startup and egress
  figures describe the relay, and neither audio nor adaptive-bitrate behaviour is measured.
- **External notification channels are not configured.** Email/SMS/mobile are recorded as
  failed deliveries, so metric 8 covers dashboard notifications only.
- **No redundancy or failover.** One application process owns the stream registry; host
  failure stops ingestion. Section 23 lists redundancy as future work, and this pilot does
  not evaluate it.
- **Integration with other institutional security systems** is out of scope until both
  feasibility and authorization are established (section 23).
