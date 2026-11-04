# How the pieces fit together

What runs, in which direction data moves, and why each hop exists in that form rather than
the obvious one. Endpoints and payloads are specified in `docs/mobile-api-contract.md`;
tables are in `docs/database-schema.md`; this document is the map between them.

## 1. The two halves and one database

```
AFIT site                                                   hosted / reachable by phones
┌────────────────────────────────────────┐                  ┌──────────────────────────────┐
│ monitoring host (the PC by the cameras)│                  │ cloud API  +  cloud worker   │
│                                        │                  │                              │
│ RTSP cameras ──► stream workers        │   one shared     │  /api/v1/ingest/*  ◄─────────┼── signed POSTs
│      │              │                  │   PostgreSQL     │  notifications, outbox       │   from the forwarder
│      ▼              ▼                  │   database       │  /auth /incidents /evidence  │
│ health evaluator  detectors            │  (29 tables)     │        ▲                     │
│      │              │                  │                  │        │ bearer tokens       │
│      ▼              ▼                  │                  │        ▼                     │
│ dashboard console  incident workflow   │                  │   personnel app (Android/web)│
│      │              │                  │                  │                              │
│      └──► notification_outbox ─────────┼──────────────────►  FCM HTTP v1 ──► handsets    │
│           (spool file if the DB dies)  │                  └──────────────────────────────┘
└────────────────────────────────────────┘
```

The split is not two systems with a sync job. The monitoring half and the cloud half are two
sets of tables and two sets of processes over **one** PostgreSQL database, so an incident an
officer opens on a phone is the same row the console shows - not a copy, not an eventual
convergence.

The rule that shapes everything else is direction: **the monitoring host initiates every
connection**. Nothing in the AFIT network listens for the phones, and the phone never talks
to the camera or to the PC. That is what keeps the deployment inside "do not expose the
local FastAPI server, camera RTSP streams or the private monitoring computer to the public
internet" - the monitoring host makes one outbound HTTPS call to a known API host.

## 2. Inside the monitoring half

**Cameras → registry.** A camera is registered by pasting an address already proven in VLC
(`docs/camera-preparation-runbook.md`). Registration opens a real socket, probes frames, and
only then writes a registry row: `is_registered` and `last_successful_frame_at` are separate
columns precisely so "we added it" cannot be confused with "it is delivering pictures".
The address is decomposed into `camera_connection_profiles` (host, port, path, stream
username) and the password goes to `camera_secrets` as sealed ciphertext with a `key_id`.
The plaintext never exists in the database and never crosses the API boundary.

**Stream workers.** Each watched camera gets a supervised worker process. The parent supervises
and restarts with backoff (`WATCHTOWER_STREAM_BACKOFF`, `WATCHTOWER_MAX_STREAM_RESTARTS`);
each lifetime is a `camera_stream_sessions` row carrying frame counts, decode failures,
retries and measured fps. Live delivery to the dashboard is JPEG served from the worker,
throttled by `WATCHTOWER_LIVE_MAX_MBPS` and `WATCHTOWER_LIVE_JPEG_QUALITY` - the browser is
never handed an RTSP URL.

**Health.** The evaluator moves a camera through nine states and writes a
`camera_health_events` row only when the state *changes*, with a `reason_code`. Change-only
events are what make 30 days of history readable, and `notified` is what stops one outage
alerting repeatedly.

**Detection.** Frames are sampled at `WATCHTOWER_ANALYSIS_FPS`; detectors produce
`detection_events` with a `confidence` and a unique `(camera_id, dedupe_key)`, which is how
a 4 fps sampler yields one candidate per real event instead of hundreds. A detection is a
**proposal awaiting human review** (`status`, `reviewed_by`, `review_note`) and the product
never presents it as a confirmed finding.

**Incidents.** `IncidentService` owns the status vocabulary and appends `incident_actions`
rows as the response narrative. Evidence bytes are written by `EvidenceStore` under
`WATCHTOWER_EVIDENCE_DIR` with the sha256 recorded in `evidence_assets`.

## 3. The hop that must not lose an alert

An incident happening at the gate must reach a phone even if the cloud is having a bad
afternoon. The naive version - call the cloud from the request handler - fails twice: it
holds a database transaction open across a network round trip, or it commits the incident and
then discovers the internet is down, which is the exact failure the proposal forbids.

So the alert is **queued in the same transaction as the incident**:

1. `IncidentService` calls the hook in `mobile/alerts.py` *before* its own commit. The
   incident row and the `notification_outbox` row either both exist or neither does.
2. `mobile/worker.py` - its own daemon thread, deliberately **not** part of the two-second
   supervision cycle, because the loop that notices a dead camera must never be delayed by a
   slow HTTPS call - drains due rows: `claim_due` uses `FOR UPDATE SKIP LOCKED`, so a
   restart or an accidental second worker cannot double-send.
3. Each drained row becomes a signed POST to the cloud (key id, secret, nonce, timestamp,
   body digest). The cloud checks the signature, refuses a replayed nonce
   (`ingest_nonces`) and answers a repeated idempotency key from `ingest_records` instead of
   executing it twice.
4. Evidence bytes travel the same way, into `CLOUD_EVIDENCE_DIR` on the cloud side.
   `evidence_relay_states` records whether they have actually arrived, so the app can say
   "evidence still arriving" instead of showing a broken image.

Two outages are handled differently, and this distinction is the reason the design is not
simpler:

- **Cloud unreachable, database reachable** - the normal case. Rows stay queued with a
  `next_retry_at` and the worker comes back. Nothing local is needed.
- **Database unreachable** - a queue row cannot exist, so the intent is appended to a JSONL
  spool under the spool directory and replayed into the outbox on a later cycle. The spool
  is small and dumb on purpose: it exists so an intent is not silently discarded.

If forwarding is switched off (`mobile_forwarding_enabled` false), the thread still starts
and reports `disabled` to the console. No alert is claimed to have been sent.

## 4. The cloud half

**API process** (`cloud/app.py`) answers the app: authentication, device registration, the
dashboard summary, notifications, incidents, evidence, profile. It writes rows; it never
talks to FCM.

It also holds the **live channel** (`cloud/streaming.py`, `routers/events.py`): one
authenticated Server-Sent-Events response per open app, carrying that recipient's new
notifications and the timeline rows of incidents its camera grant covers. It reads the
database on a short timer instead of accepting an in-process push from the worker, because a
state transition can happen in another process or on another host - an in-memory event bus
would be a private copy of the truth and would drop exactly the alerts this channel exists to
deliver. Each poll opens a session and closes it, the route caps how many connections the
process will hold, and every connection ends by itself before the access token that authorised
it expires, so the reconnect is also a fresh permission check (§10.8).

**Cloud worker** (`cloud/worker.py`) is the only thing that talks to Google, plus it
escalates: a critical incident still open and unacknowledged past
`CLOUD_ESCALATE_AFTER_SECONDS` queues a re-page to a wider role. Both jobs are idempotent -
the unique dedupe key on `notifications` is the enforcement - so a second worker or a
mid-batch restart widens the audience at most once per stage instead of multiplying it.

**Targeting** (`cloud/targeting.py`) decides who receives what: role and camera-group scope,
`personnel_preferences` (minimum severity, kinds, quiet hours evaluated on the worker's UTC
clock, sound), and `forced_alerts`, which overrides a quieting preference for critical and
escalated alerts. `cloud/delivery.py` then writes one `notifications` row per person, fans
out to that person's live devices, and records one `notification_attempts` row per handset:
requested, accepted, failed with a redacted reason, or opened.

**Push payload** is shaped for the handset, not for a generic transport: the Android
notification block carries the title, the severity's channel id (a channel the app really
created - Android discards a notification naming a channel that does not exist), the sound
decision, and the `deep_link` in `data`. No body text, no `click_action`
(`docs/mobile-api-contract.md` §10.6).

## 5. The phone

`personnel-app/` is one codebase with two targets. It holds **no** database credential, no
Firebase server credential, no storage secret and no camera address - the public Firebase
client configuration is the only Firebase material in the bundle, and it is not what
authorises a send.

- Login gives a short access token plus a rotated refresh token; the app stores session
  material in the secure storage plugin, and a refresh-token reuse revokes the whole family.
- Device registration uploads the FCM token; the cloud seals it into
  `mobile_devices.push_token_ciphertext` and only ever shows a fingerprint.
- Tapping a notification opens `watchtower://incidents/<id>` (or the verified HTTPS form)
  and the app fetches that incident - it never trusts the payload to describe the incident.
- Evidence is fetched through a brokered, single-purpose request per asset. The app is never
  given a permanent public link, so a leaked URL cannot become a standing window onto AFIT
  footage.
- Acknowledge, investigate, note and resolve are the response actions. Logging out
  deactivates the handset rather than deleting the audit trail.

## 6. Where each kind of request terminates

| From | To | Purpose | Travels |
| --- | --- | --- | --- |
| Browser (console) | monitoring host | dashboard, live JPEG, review | operator network only |
| VLC / operator | camera | verification before registration | camera VLAN only |
| Stream worker | camera | RTSP | camera VLAN only, never proxied to the app |
| Monitoring forwarder | cloud API `/api/v1/ingest/*` | signed alert + evidence | outbound HTTPS |
| Cloud worker | Google FCM | delivery | outbound HTTPS |
| Phone | cloud API | everything the officer does | HTTPS + bearer token |
| Phone | cloud API `/api/v1/events/stream` | live alerts and timeline changes while the app is open | HTTPS + bearer token, one long-lived response |
| Phone | camera / monitoring PC | nothing | not reachable by design |

## 7. What is not here

- **No Redis, no message broker.** The outbox table plus `SKIP LOCKED` is the queue; adding
  a broker would add a service to deploy and a second place for an alert to be lost.
- **No media gateway in the mobile path.** WebRTC/HLS are discussed in
  `docs/media-gateway.md` as a separate decision; the app reads stored evidence, not a live
  stream.
- **No email or SMS delivery.** The channel names exist in the enum; no code sends through
  them and no rows are created for them.
- **No WebSocket, and no in-process event bus.** The live channel is SSE and is read from the database, for the two reasons stated in §4.
- **No public exposure of the monitoring host.** Deployment must not change this. The
  hosting options in `docs/deployment.md` all keep the AFIT side outbound-only.
