# AFIT WATCH TOWER — Personnel Mobile API Contract

**Status:** normative. The `cloud-api` service and the `personnel-app` frontend are both
generated from this document. If code and this file disagree, that is a defect in one of them.

Everything below is served over **HTTPS only** by the cloud service. The local monitoring
application is never contacted by a phone, and no phone ever sees a database credential,
an RTSP URL or a camera password.

---

## 0. Participants and trust boundaries

| Actor | Speaks to | Authenticates with |
|---|---|---|
| Personnel phone / web app | Cloud API `/api/v1/*` | Bearer access token (15 min) + rotating refresh token |
| Local monitoring app | Cloud API `/api/v1/ingest/*` | HMAC-SHA256 service signature + timestamp + nonce + idempotency key |
| Cloud API | Firebase Cloud Messaging | Google service-account OAuth2 assertion (HTTP v1) |
| Cloud API | Neon PostgreSQL | `CLOUD_DATABASE_URL` — never leaves the server |

The local app **only makes outbound calls**. Nothing listens on the monitoring PC.

---

## 1. Conventions

- Base URL: `https://<cloud-host>/api/v1`
- The host is supplied by the deployment, never by the client. `personnel-app` has no default
  endpoint: with none configured the build boots into an explicit "No server configured" state and
  sign-in is disabled. A loopback address, a private LAN address or plain HTTP in a **release** build
  is likewise refused, because a phone cannot resolve the developer's machine and a personnel
  password is not sent in clear text. Development builds may point at a local server and do so
  loudly; that configuration is kept in files the release build never reads (see
  `docs/android-build.md` §3a).
- All bodies `application/json; charset=utf-8` unless stated.
- All timestamps RFC 3339 UTC with offset, e.g. `2026-11-01T09:41:07Z`.
- IDs: incidents are integers with a human `reference` (`WT-2026-0007`); cameras are UUID
  strings; devices are integer rows plus an opaque `installation_id` UUID the app owns.
- Severity vocabulary is the existing one: `low | medium | high | critical`. The UI labels
  `medium` as **Warning** and `low` as **Informational**; the API never sends UI labels.
- Unknown JSON members are ignored. Unknown enum values are rejected with `422`.
- Errors are always:

```json
{ "error": { "code": "incident_already_closed", "message": "Human readable.", "request_id": "req_9f2c…" } }
```

`request_id` is echoed in the `x-request-id` response header and is what a support ticket quotes.

| HTTP | Meaning |
|---|---|
| 401 | No/invalid/expired token, or a refresh token that failed reuse detection |
| 403 | Authenticated but the permission or camera-group check failed |
| 404 | Row does not exist **or** the caller is not authorised to know it exists |
| 409 | Conflict: an idempotency key reused for **different** content (`idempotency_conflict`), status already advanced, device already registered |
| 410 | Evidence expired or deleted |
| 422 | Validation |
| 429 | Rate limited; includes `retry-after` |

404 rather than 403 on a single record is deliberate: enumerating other people's incidents
through a 403 oracle is an information leak.

---

## 2. Authentication

Personnel accounts are created by an administrator in the monitoring console
(Administration → Users and grants) or by `POST /api/v1/admin/personnel`. **There is no
public registration endpoint and none will be added.**

### 2.1 `POST /auth/login`

```json
{ "username": "a.ahiya", "password": "••••••••••••", "device": { "installation_id": "3f9c…", "platform": "android", "push_token": "fcm…", "model": "Pixel 7", "os_version": "14", "app_version": "1.0.0" } }
```

`username` also accepts an email address. `device` is optional at login and may be sent
later to `/devices`.

```json
{ "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 900,
  "refresh_token": "b9d2…", "refresh_expires_in": 2592000,
  "user": { "id": 12, "username": "a.ahiya", "display_name": "Ahmad Ahiya",
            "roles": ["security_operator"], "permissions": ["incident.view", "evidence.view", "…"],
            "must_change_password": false } }
```

- Passwords are verified against `users.password_hash`. New hashes use **Argon2id**;
  existing PBKDF2-SHA256 hashes still verify and are transparently re-hashed on the next
  successful login. Minimum length stays 12 characters.
- Failed logins use the existing lockout: 8 failures → 5 minutes locked.
- The response sets no cookie. The app stores `refresh_token` in the Android Keystore-backed
  secure store, never in `localStorage`.

### 2.2 `POST /auth/refresh`

```json
{ "refresh_token": "b9d2…" }
```

Returns the same shape as login minus `user`. Refresh tokens are **single use**: the presented
token is invalidated and a new one issued in the same transaction. Each token is bound to
`installation_id`.

**Reuse detection:** presenting a token that was already rotated revokes the entire token
family for that device and writes `audit_logs.action = "auth.refresh_reuse"`. The legitimate
user is logged out on their next refresh; a stolen token cannot survive its own replay.

### 2.3 `POST /auth/logout`

Revokes the current refresh-token family, deactivates the device row's push capability when
`{ "forget_device": true }`, and revokes the access token's `jti` for its remaining lifetime.

### 2.4 `POST /auth/password`

```json
{ "current_password": "…", "new_password": "…" }
```

Changes the caller's own password, rotates every refresh token for every device (other
sessions survive only if `keep_other_sessions: true`, default false), and clears
`must_change_password`.

### 2.5 `GET /auth/me`

The caller's profile, roles, effective permissions and camera-group scopes. The app calls
this on cold start to restore a session; it is the only place the permission set is read from.

Access token claims: `sub`, `sid` (session id), `jti`, `iat`, `exp`, `scope: "watchtower.personnel"`.
Permissions are **never** in the token — they are resolved from the database on every request,
so revoking a grant takes effect immediately.

---

## 3. Devices

### 3.1 `POST /devices`

Registers or refreshes the caller's device. Idempotent on `installation_id`.

```json
{ "installation_id": "3f9c…", "platform": "android", "push_provider": "fcm",
  "push_token": "fcm-registration-token", "model": "Pixel 7", "os_version": "14", "app_version": "1.0.0" }
```

Response: `{ "id": 41, "installed_at": "…", "last_seen_at": "…", "push_state": "active" }`

A token that changes on the same installation overwrites the previous token — FCM tokens
rotate and the app must re-POST on every `token` event. One account may register many
devices. A device row belongs to exactly one user.

### 3.2 `DELETE /devices/{installation_id}`

Deactivates the caller's own device. `GET /devices` lists them for the profile screen.
An administrator may revoke any device through `/api/v1/admin/devices/{id}/revoke`.

Deactivated devices are excluded from targeting and are never retried.

---

## 4. Dashboard

### 4.1 `GET /dashboard/summary`

Every number here is a real aggregate filtered by the caller's camera-group scope. Nothing
is hardcoded in the client.

```json
{ "generated_at": "…",
  "incidents": { "active": 4, "awaiting_acknowledgement": 2, "critical_open": 1,
                 "high_open": 3, "acknowledged_last_24h": 5, "resolved_last_24h": 2 },
  "notifications": { "unread": 6, "failed_delivery": 0 },
  "delivery": { "outbox_pending": 0, "outbox_failed": 0, "last_successful_push_at": "…" },
  "personnel": { "display_name": "…", "roles": ["security_operator"], "permissions": ["…"] } }
```

`delivery` is what the app shows as "notification service reachable / degraded". It is
computed from `notification_outbox`, not from a guess.

---

## 5. Notifications

A notification is one row per recipient per channel — the existing `notifications` table.
`channel = "mobile_push"` for phone alerts, `"dashboard"` for console alerts.

### 5.1 `GET /notifications`

Query: `unread_only`, `severity` (repeatable), `from`, `to`, `kind`, `cursor`, `limit` (≤100, default 25).

```json
{ "items": [ { "id": 812, "kind": "incident.created", "title": "Restricted-zone entry at Main Gate",
  "body": "…", "severity": "high", "state": "delivered", "read_at": null,
  "acknowledged_at": null, "incident_id": 77, "incident_reference": "WT-2026-0007",
  "camera_name": "Main Gate", "camera_location": "North entrance", "created_at": "…",
  "deep_link": "watchtower://incidents/77" } ],
  "next_cursor": "eyJvIjo4MTJ9", "total_unread": 6 }
```

Cursor pagination, newest first. `total_unread` powers the badge.

### 5.2 `POST /notifications/{id}/read` · `POST /notifications/read-all`

Sets `state = read`, for the recipient who owns the row only, and only from `pending`, `delivered`
or `suppressed` - a silenced alert is still an alert somebody has not looked at yet. A `failed` row
stays failed: the send is finished, and the read button does not undo a fact about it. Reading is
**not** acknowledging. The API keeps those two facts separate and so must the UI.

### 5.3 `POST /notifications/{id}/open`

Called when a push is tapped and the incident actually renders. Records
`notification_attempts[].opened_at`. This is the only "seen" signal the platform can honestly
claim, and only when the app is installed and the user taps.

---

## 6. Incidents

### 6.1 `GET /incidents`

Query: `status` (repeatable), `severity`, `category`, `camera_id`, `location`, `from`, `to`,
`q` (matches reference, title, summary), `cursor`, `limit`.

Returns only incidents in the caller's scope. A caller with a group-scoped grant sees cameras
inside that group and ungrouped cameras never.

```json
{ "items": [ { "id": 77, "reference": "WT-2026-0007", "title": "…", "category": "restricted_zone_entry",
  "severity": "high", "status": "open", "camera_id": "uuid", "camera_name": "Main Gate",
  "campus_location": "North entrance", "occurred_at": "…", "created_at": "…",
  "detection_source": "ai_candidate", "confidence": 0.72, "evidence": [ { "id": 5, "kind": "snapshot", "content_type": "image/jpeg" } ],
  "acknowledged_by": null, "assigned_to": null } ], "next_cursor": "…" }
```

`detection_source` is `ai_candidate | manual | health` and is always shown. An AI candidate is
never rendered as confirmed wrongdoing.

### 6.2 `GET /incidents/{id}`

Full record plus `summary`, `resolution`, `outcome`, `resolved_at`, `escalated_to`, and
`activity` (chronological `incident_actions` with actor display name and timestamp).

### 6.3 Response actions

Every action writes an `incident_actions` row, an `audit_logs` row, and returns the updated
incident. All accept `{ "note": "optional text" }` unless stated.

| Endpoint | Permission | Effect |
|---|---|---|
| `POST /incidents/{id}/acknowledge` | `incident.acknowledge` | `open → investigating`, records actor + timestamp, marks the caller's notification acknowledged |
| `POST /incidents/{id}/investigating` | `incident.view` + own scope | `open → investigating` without an acknowledgement claim |
| `POST /incidents/{id}/notes` | `incident.view` | activity note only |
| `POST /incidents/{id}/escalate` | `incident.escalate` | `{ "reason": "…", "to_role": "security_supervisor" }`, notifies the target group |
| `POST /incidents/{id}/assign` | `incident.assign` | `{ "user_id": 12 }` |
| `POST /incidents/{id}/resolve` | `incident.resolve` | `{ "outcome": "confirmed_threat", "resolution": "…" }` → `resolved` |
| `POST /incidents/{id}/reopen` | `incident.resolve` | `{ "reason": "…" }` → `open` |

**Conflict rules** (server-side, not UI-side): acknowledging an incident already `resolved`
or `closed` returns `409 incident_not_actionable`. A second acknowledgement by the same user
is idempotent and returns the existing record with `already_acknowledged: true`. Status
transitions are validated against the existing `IncidentStatus` machine — the client cannot
set an arbitrary status.

### 6.4 `GET /incidents/{id}/activity`

Paginated history for the details screen. Same rows the console shows.

---

## 7. Evidence

Evidence bytes live in cloud object storage or the cloud host's evidence directory — never in
Neon, never on the phone permanently.

### 7.1 `GET /incidents/{id}/evidence`

```json
{ "items": [ { "id": 5, "kind": "snapshot", "content_type": "image/jpeg", "byte_size": 184320,
  "captured_at": "…", "state": "available", "url": "https://cloud/api/v1/evidence/5/content?token=…",
  "expires_at": "2026-11-01T10:11:07Z", "sha256": "…" } ] }
```

`state` is `available | processing | expired | deleted | unavailable`. A `processing` asset is
one the local app has not finished uploading; the UI must show that rather than a broken image.

`url` is a **short-lived single-asset token** (10 minutes default), bound to the asset id and
the requesting user, valid for that one asset for the length of the window. It is reusable
inside the window rather than single-use: a video element makes a sequence of range requests
to seek, and a token that died on first use would break playback after the first byte range.
There is no permanent public link, no bucket name, and no storage credential in any response.

### 7.2 `GET /evidence/{id}/content`

Streams the bytes with `content-type`, `content-length`, `accept-ranges`. Authorised by the
asset token or the caller's session, and audited as `evidence.view` on every successful read.
Requires `evidence.view`; export requires `evidence.export`.

Video: `kind = "clip"`, `content_type = "video/mp4"`, range requests supported so the Android
`<video>` element can seek.

---

## 8. Profile and notification preferences

### 8.1 `GET /profile`

Name, username, roles with scope descriptions, account status, personnel identifier
(`users.username` plus optional `email`/`phone`), registered devices, effective permissions,
last sign-in.

### 8.2 `GET|PUT /profile/preferences`

```json
{ "min_severity": "medium", "kinds": { "incident.created": true, "incident.escalated": true,
  "incident.resolved": true, "camera.health": true, "event.new": false },
  "quiet_hours": { "enabled": false, "start": "22:00", "end": "06:00" },
  "sound": "default" }
```

`PUT` replaces the caller's preferences. **Mandatory alerts cannot be switched off by the
individual**: `notification_policy_overrides` in the cloud configuration can force
`incident.escalated` and `critical` severity to always deliver, and the response reports
`"forced": ["critical", "incident.escalated"]` so the UI greys those toggles out with an
explanation instead of letting a user believe they silenced a duty alert.

`sound` accepts `default`, `alarm` or `silent`; an unknown value is a `422`. What each does at
delivery is in §10.6. `quiet_hours` is evaluated on the **delivery worker's UTC clock**, not the
handset's: an AFIT officer on WAT (UTC+1) who wants 22:00–06:00 local must enter 23:00–07:00, and
the app says so next to the two inputs rather than leaving the discrepancy to be discovered on a
quiet night.

`kinds` is a sparse override map, and `GET` returns only the entries the account has stored —
an account that has never touched the screen gets `{}`. That is not "no kinds are configurable".
Delivery suppresses a kind only when it is present and `false` (`cloud/targeting.py`), so **an
absent kind is an enabled one**, and the client renders its own mirror of `KNOWN_KINDS` with every
switch on. A client that renders the stored map alone shows an officer with default preferences an
empty list and implies the service offered nothing, which is how this was first misbuilt.

The same reasoning is why the client sends `min_severity` exactly as chosen and re-asserts nothing
on the server's behalf: `apply_preferences` exempts a forced severity or kind from the floor, the
toggles and quiet hours before it reads any of them, so a forced alert arrives whatever the
account has set and a client-side "protection" can only ever damage the preference it is sent to
guard.

---

## 9. Service-to-service ingest (local monitoring app → cloud)

### 9.1 `POST /api/v1/ingest/incident`

Called by the local forwarder for every outbox row. Body:

```json
{ "idempotency_key": "outbox:7c1f…", "occurred_at": "…",
  "incident": { "reference": "WT-2026-0007", "title": "…", "summary": "…",
    "category": "restricted_zone_entry", "severity": "high", "status": "open",
    "camera_id": "uuid", "camera_name": "Main Gate", "campus_location": "North entrance",
    "detection_source": "ai_candidate", "confidence": 0.72, "origin_event_id": 512 },
  "evidence": [ { "asset_id": 5, "kind": "snapshot", "content_type": "image/jpeg",
                  "byte_size": 184320, "sha256": "…", "captured_at": "…", "relay": "multipart" } ],
  "recipients_hint": { "min_severity": "high", "escalate_to_role": "security_supervisor" } }
```

Response `201 { "incident_id": 77, "notifications_created": 3, "devices_targeted": 3 }`. A
retry that carries the **same body** again is answered `201` with the original response fields
plus `"duplicate": true` - the status code does not change, so the forwarder settles the local
row either way.

A call reusing a spent key with a **different body** is refused `409
idempotency_conflict`. That is not a retry, it is a second alert given a used key, and answering
it from the stored response would report success while discarding the new content - the one
silent-alert-loss path the idempotency mechanism could have hidden. `ingest_records.request_digest`
is what the comparison is made against.

Evidence bytes ride the same call as a `multipart/form-data` second part named `evidence`
when the local app is configured to relay them; otherwise the JSON-only variant is used and
the cloud marks the asset `processing` until a separate `POST /ingest/evidence/{asset_id}`
upload lands.

### 9.2 Signature scheme

Headers on every ingest request:

```
x-watchtower-key-id:      wt-monitor-2026
x-watchtower-timestamp:   1762000000        (unix seconds, ±300 s accepted)
x-watchtower-nonce:       8f2c19ab…         (16 random hex, single use)
x-watchtower-content-sha256: <hex of raw body bytes>
authorization:            WATCHTOWER-HMAC-SHA256 <key_id>:<signature>
```

Canonical string, `\n`-joined, signed with the shared secret:

```
POST\n/api/v1/ingest/incident\n<timestamp>\n<nonce>\n<content-sha256>
```

Verification order — cheap and fail-closed: timestamp window → nonce replay cache (in-memory
TTL plus a `ingest_nonces` unique index so a restart cannot re-accept a captured request) →
constant-time signature compare → idempotency lookup, which also compares the request's
`content-sha256` against the digest stored with the first call. The raw body is read as bytes and hashed
before parsing; JSON re-serialisation is never used for verification.

`key_id` maps to a secret held only in cloud configuration. Rotation is additive: both key ids
verify during an overlap window.

### 9.3 `POST /api/v1/ingest/heartbeat`

`{ "monitoring_host": "…", "app_version": "…", "outbox_pending": 0, "outbox_failed": 0 }`
Every 60 s. Lets the console answer "is the forwarder alive?" with evidence.

### 9.4 `POST /api/v1/ingest/outbox-ack`

`{ "idempotency_key": "outbox:7c1f…" }` — the cloud confirms processing so the local row
settles to `delivered`. Retried safely; acking an already-acked key is a no-op.

---

## 10. Notification targeting (cloud-side, after ingest)

Recipients are computed, never assumed:

1. Users holding `incident.view` (or `event.review` for candidate alerts) **and**
   `incident.acknowledge` where the alert asks for action.
2. Narrowed by camera group exactly as the console does — a group-scoped grant receives
   nothing for a camera outside its group.
3. `is_active` users only, with at least one registered handset that has not been forgotten or
   revoked. This is the *display* test, not the paging test: a phone that signed in but holds no FCM
   token - every phone on a build with no Firebase project - is recorded an alert it can show
   (§10.7). Only devices in `push_state = active` with a token are ever sent to.
4. Filtered by each user's preferences and the mandatory-alert overrides.
5. Ranked by severity: `critical` → duty officers, supervisors and command; `high` → duty
   officers and supervisors; `medium`/`low` → the responsible role only. Camera-health events
   go to `health.view` holders, never to the whole estate.

One `notifications` row per recipient per channel, one `notification_attempts` row per send.
Unacknowledged `critical` incidents escalate automatically after `CLOUD_ESCALATE_AFTER_SECONDS`
(default 180) to the next role, recorded as an `incident.escalated` activity.

Delivery vocabulary, kept distinct in the schema and in the UI:

`queued → submitted → accepted_by_fcm → opened → acknowledged` plus `failed(reason)`.
**FCM acceptance is not delivery to a human.** Android power management can defer a wake;
the platform claims only what it can observe.

An alert for a recipient whose handsets cannot be paged at all is recorded `suppressed` with
`failure_reason = in_app_only` and produces no attempt row: nothing was sent, and nothing failed. It
counts as unread and can be marked read like any other alert, because reading it in the app is the
delivery.

### 10.6 What the handset is told to display

The Android block of the FCM message is part of this contract, because a mismatch there produces
an alert nobody sees:

| Field | Value | Why |
|---|---|---|
| `notification.channel_id` | `watchtower-critical` / `watchtower-high` / `watchtower-warning` / `watchtower-informational`, and `watchtower-camera-health` for `camera.health` | Android discards a notification whose channel the app never created. The app creates these five at launch (`personnel-app/src/lib/severity.ts`, `ALL_CHANNELS`), and `tests/test_cloud_delivery.py` reads that file so the two lists cannot drift apart again. |
| `notification.title` | the alert title, e.g. `Incident WT-2611-0042 escalated` | Android displays the notification block, not `data`; without a title the handset posts an empty banner. |
| `notification.body` | **absent** | The stored body is the operator's own sentence (escalation reason, resolution note). A lock screen shows it to whoever stands next to the phone. It stays in the database and is read inside the app. |
| `notification.click_action` | **absent** | A custom action with no matching intent filter resolves to nothing, so the tap would open no screen. With no action, Android launches the app with the payload, the Capacitor plugin fires `pushNotificationActionPerformed`, and the app follows `data.deep_link` itself. |
| `notification.sound` | the recipient's `sound` preference, except for a forced alert | `silent` arrives as an empty sound field. `default` (and a legacy `alarm`) means the channel's own tone, which the officer sets in Android's notification settings — a push cannot rewrite a channel's sound. A severity or kind in `CLOUD_FORCED_ALERTS` is sent with sound regardless of the preference, the same way it ignores quiet hours. |

### 10.7 Foreground refresh when push is not configured

Push (§10) is the delivery path, and it is the only one that reaches a handset whose app is
closed. Until a Firebase project exists (§2 of `docs/firebase-setup.md`), the app instead re-reads
its own queue while a screen is open: the dashboard, the alert centre and the incident history each
poll their listed endpoint every `VITE_ALERT_POLL_SECONDS` (default 20; 0 disables it).

The rules the client keeps so this is not mistaken for push:

- A hidden webview sends nothing. A phone in a pocket does not poll, and an alert that arrives while
  the app is closed waits for the next open screen — it is still stored and listed, only not shown.
- Returning to the foreground re-reads immediately rather than waiting out the cadence.
- A poll never overtakes a request already in flight, so a slow network does not stack retries.
- A `401` stops the polling. The session is refused; asking again is how a locked-out device turns
  one error into a hundred.
- There has to be a row to find. An alert is recorded for a recipient who has signed in on a
  handset at least once (§10 step 3); when that handset cannot be paged the row is recorded
  `suppressed` with `in_app_only`, still counted unread, and cleared by opening it. An account that
  has never signed in anywhere receives nothing, which is the difference between "nobody pushed
  them" and "there is no screen this alert could appear on".

The polls are ordinary authenticated reads — one or two per open screen every
`VITE_ALERT_POLL_SECONDS`, which §11 places no limit on (no read route is rate-limited).
`total_unread` in the list response is what refreshes the badge.
`notification_attempts.error_code = not_configured` remains the honest record that no push was sent.

### 10.8 `GET /events/stream` — the live channel

§10.7 is the floor. This is the accelerator: while the app is open it holds one authenticated
Server-Sent-Events connection, so an alert that lands is on the officer's screen in about
`CLOUD_STREAM_POLL_SECONDS` (default 2) instead of up to `VITE_ALERT_POLL_SECONDS`. It changes
latency, not reach: **a closed app runs nothing**, and push (§10) remains the only path that wakes a
phone. The foreground poll keeps running with the stream open; it is what delivers an alert the
moment the stream drops and the reconnect has not yet landed.

Transport: `text/event-stream`, one long-lived response.

| | |
|---|---|
| Auth | `Authorization: Bearer <access token>` and `x-installation-id`, exactly like every other read. |
| Permission | `incident.view`. A caller without it is refused with `403 incident_permission_required` before any frame is written. |
| Query | `since=<cursor>`, optionally `Last-Event-ID: <cursor>` (the header SSE clients resend on reconnect; the query parameter is the explicit form). |
| Cursor | `"<notifications id>:<actions id>"` — the two autoincrement primary keys the feeds are read from. Not opaque, not guessable-safe: it carries no data the caller cannot already list. |
| No cursor | The connection starts at the **end** of both feeds. A fresh stream is not a history lesson; replaying last week's queue as a stack of banners would be worse than useless. |
| Unparseable cursor | Treated as no cursor — start at the end. Never from zero, which would re-deliver everything. |
| Frames | `id:` line first, then `event:`, then one `data:` JSON line, then a blank line. |

Event names:

| Name | Body | Meaning |
|---|---|---|
| `ready` | `{cursor, poll_seconds, heartbeat_seconds, server_time}` | The connection is open and authorised, and this is where a reconnect resumes. The client takes its idle-watchdog length from `heartbeat_seconds`. |
| `notification` | the same object `GET /notifications` returns for that row | A new alert addressed to **this** recipient. Nothing about anyone else's queue is ever framed. |
| `incident_activity` | one `GET /incidents/{id}/activity` entry plus `incident_id`, `incident_reference`, `incident_status`, `incident_severity` | A timeline row — acknowledged, escalated, resolved, reopened, closed, or a note — including the automatic service writes. Filtered by the same camera-group grant as the incident list, so an action on a camera outside the caller's grant is not framed at all. |
| `heartbeat` | `{cursor, server_time}` | Proof of life, so a silent proxy or a dead radio is visible as a missed heartbeat instead of a screen that merely looks quiet. |
| `closing` | `{reason, cursor, server_time}` | The service ended the stream. `reason` is `lifetime` (scheduled — see below) or `database_unavailable`. The client resumes from `cursor` for both. |

Rules the route keeps:

- **Lifetime is capped below the access token's TTL** (`CLOUD_STREAM_MAX_LIFETIME_SECONDS`, default
  600 against a 900 s token; the loader refuses a configuration where it is not). A connection that
  outlived the check that opened it would be an authorisation nobody re-examined. The client
  reconnects immediately on `lifetime`, and the reconnect runs the full permission check again.
- **One database read per poll, in a short-lived session.** The stream never holds a pool connection
  while it sleeps; `db.build_engine` opens 10 with 20 overflow, and an unbounded stream route would
  take those from logins. `CLOUD_STREAM_MAX_CONNECTIONS` (default 24) caps the process, and past the
  cap the answer is `503 stream_unavailable` with `Retry-After: 30` — a refusal the app can read, not
  a queue that would look like a live channel producing nothing.
- `CLOUD_STREAM_ENABLED=0` answers `503 stream_disabled` on every attempt, so an operator can switch
  the channel off without redeploying. `GET /healthz` reports the state as
  `"live_channel": "enabled" | "disabled"`.
- A read failure ends the stream with `database_unavailable` and closes it. The driver's message
  never leaves the process — it is logged, not framed.

The client (`personnel-app/src/api/stream.ts`) is `fetch` plus `ReadableStream`, not `EventSource`:
`EventSource` cannot set an `Authorization` header, and the alternative — a bearer token in a query
string — writes that token into every proxy and hosting access log between the phone and the
service. It reads the current access token per attempt and **never** calls `/auth/refresh`; the API
client is the only place a family rotates, and a second refresher would rotate it twice. So a `401`
or `403` ends the feed, and the fresh pair the client installs is what reopens it. Reconnect backoff
is 1/2/5/10/30 s, reset by a successful `ready`, skipped for `lifetime`; `stream_disabled`, `404`
and `405` stop asking for good. Frames are deduplicated by row id, and what the app does with them is
documented under *Live updates* in `personnel-app/README.md`.

---

## 11. Rate limits and CORS

Per-identity sliding windows, in-memory per process (documented as a scale-out caveat):

| Route group | Limit |
|---|---|
| `POST /auth/login` | 10 / 5 min per username + 30 / min per IP |
| `POST /auth/refresh` | 60 / 5 min per session |
| `POST /auth/password` | 5 / 15 min |
| Incident response actions | 60 / min |
| Evidence content | 200 / min |
| `POST /ingest/*` | exempt from user limits; bounded by outbox batch size |

CORS: exact origin allow-list from `CLOUD_ALLOWED_ORIGINS`. Credentialed requests are
rejected — the app uses bearer tokens, so `allow-credentials` stays `false` and a rogue
origin cannot ride a user's session.

---

## 12. Deep links

`watchtower://incidents/{id}` from the push payload, plus the HTTPS form
`https://<cloud-host>/open/incidents/{id}` for link-based entry.

Tap → app opens → session check → `GET /incidents/{id}` → render. Unauthenticated: the
destination is held in memory, login, then the destination is restored and re-authorised.
The push payload itself carries only `incident_id`, `notification_id`, `severity`, `title`,
`camera_name` and `deep_link` — never a body, evidence URL, credential or location of tactical
value.

---

## 13. What this contract deliberately does not offer

- No live camera video to phones. Live view stays on the console inside the AFIT network.
- No endpoint returns an RTSP URL, camera credential, or the `camera_secrets` table.
- No direct database access from the app, and no Neon credential in any client bundle.
- No Redis, no Celery, no queue service: PostgreSQL rows and workers only.
- No WebSocket. The live channel (§10.8) is one-way by design: a phone tells the service nothing
  over it, and every write the app performs is an ordinary authenticated request that a rate limit,
  a permission check and an audit row already exist for. A bidirectional socket would be a second
  place those rules have to be re-implemented, and a rule that lives in two places is a rule that
  drifts.
- No self-registration, no password-reset-by-email (that needs a mail gateway AFIT has not
  approved); administrators reset credentials in the console.
