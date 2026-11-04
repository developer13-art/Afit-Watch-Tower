# Troubleshooting

Symptom-first. Every message quoted here is a string that exists in this codebase, so you can
grep for it. The order of the sections is the order to work through when an alert "did not
arrive": queue → forwarder → cloud acceptance → targeting → delivery → handset.

## 0. The three questions to ask of any failure

1. **Was it recorded at all?** This system's rule is that a thing that did not happen leaves a
   row saying why, rather than quietly producing nothing. `notifications.failure_reason`,
   `notification_attempts.error_code`, `evidence_relay_states.state`, `system_jobs.last_error`
   and `camera_stream_sessions.termination_reason` exist for exactly this.
2. **Which layer stopped it?** The console can show an incident while the outbox shows it
   undrained, and the cloud can show a delivered attempt while the handset shows nothing. Each
   layer reports for itself.
3. **Is it a missing credential or a broken one?** "Not configured" is a supported state - the
   system is meant to run without push and say so. "Configured and failing" is different, and
   the fix is never to remove the guard.

Do not work around a guard by editing product code. If a check is blocking a legitimate local
test, build a labelled demo path around it instead of weakening it.

## 1. The service will not start

| Message | Meaning | Fix |
| --- | --- | --- |
| `WATCHTOWER_DATABASE_URL is required…there is no implicit local fallback` | no DSN in the process environment | set it; note that a `.env` line containing `&` is split by Windows `set`/`source` |
| `…PostgreSQL…` refusal from `load_settings()` | a SQLite URL was supplied | this is intentional; the demo script is the only SQLite path |
| `CLOUD_JWT_SECRET` must be at least 32 characters (got N) | short secret | generate one; boot is refused rather than allowed |
| `…may only use plain http against loopback in the development environment` | non-development environment with a non-HTTPS or non-loopback base URL | terminate TLS in front, fix `CLOUD_PUBLIC_BASE_URL` |
| `CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE is set but CLOUD_FIREBASE_PROJECT_ID is not` | half-configured push | both or neither (`cloud/config.py`) |
| `CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE points at '…', which does not exist` | configured-but-missing file | fix the path, or comment the two `CLOUD_FIREBASE_*` lines in `.env`. `set CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE=` in cmd does **not** help: it deletes the process variable, the loader then reads the value out of the file again, and the same error returns. An unreadable configured file is a startup error, not a silent fallback |
| `the Firebase service-account file is missing 'client_email'` / `'private_key'` | wrong artefact uploaded (usually `google-services.json` instead of a service-account JSON) | see `docs/firebase-setup.md` §1 |
| `WATCHTOWER_CLOUD_API_URL must be https://` | plain HTTP forward target | the forwarder refuses to send signed credentials in the clear |
| `WATCHTOWER_CLOUD_API_URL is set, so the machine credential is mandatory` | URL without key id/secret | `python -m watchtower.cloud service-key` and set all three |
| `WATCHTOWER_CLOUD_KEY_SECRET must be at least 32 characters` | short ingest secret | generate a fresh pair; it HMAC-signs every request |
| `connected; alembic revision = X, but the code in this checkout needs Y` | database behind the code | `python -m watchtower.cli migrate`, then re-run `check-schema` |
| `404 not_found` from a hosting health check | the check URL names `/readyz`. The cloud API answers `/healthz` only; `/readyz` is the monitoring console's route | point the check at `/healthz` (`cloud/app.py:273`). It returns 503 with `"database": "unavailable"` when the pool is down, and 200 otherwise - see `docs/deployment.md` §5.5 |
| `PORT is not a port number: '…'` | the platform's published port is not a number | fix the variable. `serve` reads `PORT` when `--port` is absent and refuses to guess (2026-11-03). `--port` still wins; a `PORT` of 0 or 70000 is refused the same way |
| `the secret for '<id>' is N characters; ingest signatures need at least 32` while the file clearly holds a longer one below | the key is **duplicated** in the env file and the loader takes the first occurrence, so the working pair lower down is invisible | keep one `CLOUD_SERVICE_KEYS_JSON=` line with every machine id inside that one object. See `docs/deployment.md` §2 - this exact fault stopped every cloud command on the control-room PC |
| `/healthz` never answers instead of returning 503 | the database host is black-holing the connection: no `connect_timeout` was configured, and neither `/healthz` nor `db.build_engine` sets one. Measured: a connect to a dead port did not return within 60s; the same DSN with `connect_timeout=2` raised in 2.00s | add `&connect_timeout=5` to `CLOUD_DATABASE_URL` (`docs/deployment.md` §5.5) |

`python -m watchtower.cloud verify` is the non-destructive way to see all of this at once: it
prints a line per capability, separates blocking failures from warnings, and tells you that
without a service key "the monitoring host's forwarder is refused; alerts stay local".

## 2. Login, tokens, sessions

| Response `code` | What actually happened | What to do |
| --- | --- | --- |
| `invalid_credentials` | wrong username or password, or the account is inactive. Deliberately one message for all three. | check `users.is_active`; check `locked_until` |
| `invalid_credentials` **only on the deployed service**, while the same pair signs in locally | almost always `argon2-cffi` missing from the cloud environment. `verify_password` returns False for an Argon2id hash it cannot check, rather than pretending (`security/passwords.py:63-67`), and the live hashes were written by the monitoring host | run `python -c "from watchtower.security.passwords import argon2_available; print(argon2_available())"` in the service's own environment - `False` there is the answer. Install `requirements-cloud.txt` as written; do not hand-pick a shorter list |
| `invalid_refresh` | the token is unknown, or it was already rotated | expected after a password change or a family revocation; the app re-authenticates |
| `refresh_expired` | past `CLOUD_REFRESH_TOKEN_TTL_SECONDS` (30 days default) | normal for a phone left unused |
| `session_revoked` | the family was revoked because a rotated token was presented again | a real signal: either two copies of the app on one account, or a stolen token. Check `audit_logs` for the actor |
| `invalid_scope` | the token's scope does not cover this route | not a bug in the client; check which credential is being sent |
| `forbidden` | authenticated, but the role or camera-group scope does not allow it | see §4 |
| `note_required`, `validation_failed`, `severity_invalid`, `status_invalid`, `payload_too_large` | request body problems | the message names the field |

The app is supposed to refresh transparently. If a phone has to log in repeatedly, look for
`session_revoked` first: it usually means two processes are rotating the same token.

## 3. "No notification arrived"

Work through it in this order. Each step answers for itself; do not skip to FCM.

**a. Is the alert in the outbox?**
```sql
select state, attempts, next_retry_at, left(last_error, 120)
from notification_outbox order by id desc limit 20;
```
- No row at all → the incident and the alert are written in one transaction, so a missing row
  means the incident commit did not happen, or forwarding is disabled and the console reports
  `disabled`.
- Rows stuck `queued` with growing `attempts` → step b.

**b. Is the forwarder running and reaching the cloud?**
The drain is its own daemon thread, never part of the two-second supervision cycle. Look for
`watchtower.mobile.worker` log lines. `last_error` naming a DNS or TLS failure means the cloud
host is wrong or unreachable - the fix is network, not code. A growing JSONL spool under
`WATCHTOWER_SPOOL_DIR` means the database itself was unavailable when the incident happened;
it is replayed automatically on a later cycle.

**c. Did the cloud accept it?**
`ingest_records` should have one row per forwarded request. If it does not, the forwarder's
requests were refused - see §5 for the refusal codes. `ingest_unconfigured` (503) means the
cloud has no service key at all.

**d. Was anyone targeted?**
```sql
select id, recipient_id, state, left(failure_reason,120)
from notifications where incident_id = :id;
```
- **No rows** → targeting excluded everyone. Check role and camera-group scope, then
  `personnel_preferences` (`min_severity`, `kinds`, `quiet_hours`). Quiet hours are evaluated
  on the worker's **UTC** clock: an officer in WAT (UTC+1) who wants 22:00–06:00 local must
  save 23:00–07:00. Also check that the person has signed in on the app at least once: an alert is
  only recorded where there is a handset to display it, so an account nobody has logged into is not
  a delivery failure, it is an unused account.
- `state='suppressed'` with a `failure_reason` → deliberately filtered. The preference reasons name
  which rule silenced it; `in_app_only` means the recipient's handsets have no push token, so the
  alert waits in the app's queue instead of buzzing (§10.7 of the contract).
- `push_not_configured` is **not** a value this system writes. When the host has no Firebase
  project the attempt row carries `error_code='not_configured'` and the notification carries the
  sentence "This cloud host has no Firebase project configured, so no push was sent." Expected
  until a project exists.
- `failure_reason='no_active_device'` → every handset for that person has been forgotten or revoked,
  so there is no screen left to show the alert on. They need to sign in again. A handset that is
  present but has no push token produces `in_app_only`, not this.

**e. What did the attempt say?**
```sql
select device_id, state, error_code, left(failure_reason,120)
from notification_attempts where notification_id = :n;
```
- `state='requested'` and never `accepted` → the sender could not reach Google.
- A `UNREGISTERED`-style error → the token is dead (app reinstalled, token rotated). The
  device row should be moving to an invalid state with `invalid_reason`; if it keeps being
  retried, that is a bug worth reporting rather than retrying harder.
- `failure_reason='The stored push token could not be decrypted.'` → the token was sealed by a
  different ring. Either `CLOUD_SECRET_KEY_PATH` changed, or the row came from another
  environment. There is no recovery for the token: the handset must re-register.
- `no_token` → the device registered before a push token was ever obtained (a browser build,
  or a handset that refused `POST_NOTIFICATIONS`).

**f. Payload and channel.** A send can be *accepted* and still show nothing. Check that the
Android notification block names a channel the app creates (`docs/android-build.md` §6) -
Android discards a notification whose `channel_id` does not exist. `tests/test_cloud_delivery.py`
guards this against drift; if you have changed severity names or channel ids, run it.

**g. The handset.** Permission denied in Android settings, the channel set to silent/minimised
in the system UI, Do Not Disturb, or a battery-optimisation policy killing the app. Every one of
those is a property of the phone, and none of them appear in `notification_attempts`.

**h. Is the app open?** If it is, the live channel is the difference between "two seconds" and
"up to `VITE_ALERT_POLL_SECONDS`", and the banner strip in the shell says which one you are
looking at (§10.8). Three readings:

- A line that says **Live** - the connection is open and authorised. An alert for this recipient
  reaches the screen without a refresh tap.
- **Live updates paused - reconnecting**, or a line naming the poll - the channel dropped, and
  the app is carrying on through the poll. Nothing is lost: the poll is still running, and the
  reconnect resumes from the last cursor, so rows from the gap arrive once each.
- **This service does not offer live updates** - `CLOUD_STREAM_ENABLED=0`, or the deployed build
  predates the route, or a proxy answered `404`. The client stops asking for good, which is the
  correct behaviour and not a fault to chase. To confirm the service's own answer, ask it
  directly:
  ```bash
  curl -N -H "Authorization: Bearer $TOKEN" "<api>/api/v1/events/stream?since=0:0"
  ```
  A `ready` frame then a `heartbeat` every `CLOUD_STREAM_HEARTBEAT_SECONDS` is the whole expected
  conversation. `GET /healthz` reports `"live_channel"`, and the startup line prints
  `live_channel=on (cap N)`.
- `503 stream_unavailable` with `Retry-After: 30` is the per-process connection cap
  (`CLOUD_STREAM_MAX_CONNECTIONS`, default 24). It is not a fault in the handset: that many
  officers hold a stream and the pool behind them is `pool_size=10, max_overflow=20`. Raise the
  cap and the pool together, or leave it - refused clients poll instead, which is the designed
  fallback and not a outage.

A stream that stays up while nothing is framed is not proof of a working delivery path: the
channel only carries rows that exist. An empty database produces a quiet stream, and the queue
endpoint answers `empty`. That is the state this project is in until a camera and the forwarder
have run for real.

## 4. "The app says I'm not allowed"

`forbidden` is a correct answer, not a fault. Check, in order: the role codes on
`user_roles`; whether that role holds the permission (`incident.view`, `incident.acknowledge`,
`health.view`, `evidence.view`); and whether a `camera_group_id` on the grant scopes it to
cameras that do not include this incident. A camera-scoped officer sees an empty incident list
rather than an error, so an empty-but-200 response is also a scope signal.

Health alerts (`kind` starting with `camera.`) are targeted against `HEALTH_ROLES` rather than
the severity-role table, and need `health.view`. The full filter chain in
`cloud/targeting.py:216`, in order - a person must clear every one:

1. `users.is_active` is true;
2. not excluded by the caller (an action taken by the person themselves does not page them);
3. holds the permission for the alert's family: `event.view`, `incident.view` or `health.view`;
4. if the alert `requires_action`, also holds `incident.acknowledge` - an alert that asks to be
   acted on is not sent to somebody who cannot act on it;
5. the camera, if any, is inside their scope;
6. they hold one of the wanted roles.

Anything that reaches the end of that chain and is then filtered by preferences produces a
`suppressed` row with a reason. Anything stopped earlier produces **no row at all**, which is
why an empty `notifications` result is normal and is not the same finding as a suppression.

## 5. Ingest refusals (monitoring host → cloud)

All of these answer **401** with the code as the message and never a hint about the secret.

| `code` | Meaning |
| --- | --- |
| `ingest_unconfigured` | the cloud accepts no service traffic yet |
| `missing_key_id` | `x-watchtower-key-id` header absent |
| `unknown_key_id` | the id is not in `CLOUD_SERVICE_KEYS_JSON` - rotation mid-flight, or the wrong pair on the host |
| `malformed_signature`, `unsupported_scheme` | the `Authorization` header is not `<key_id>:<signature>` for this algorithm |
| `key_id_mismatch` | the id in the header and in the signature differ |
| `bad_signature` | the secret differs, or the method/path/body differ from what was signed |
| `content_mismatch` | `x-watchtower-content-sha256` does not match the body actually sent |
| `invalid_timestamp`, `invalid_nonce`, `invalid_content_sha256` | malformed headers |
| (clock skew) | the timestamp is outside `CLOUD_INGEST_MAX_SKEW_SECONDS` (300 default) - **fix the NTP on the monitoring host**, this is the most common invisible one |
| `replay_detected` | the nonce was already used; the forwarder must issue a fresh nonce per attempt |
| `idempotency_conflict` | **409.** The idempotency key was already spent on a different body. A retry sends the same content; a different alert needs its own key. If the forwarder is hitting this, it is reusing a key it should not - check how `idempotency_key` is built in `mobile/outbox.py` |

`payload_too_large` (413) means an evidence asset exceeded the ingest body limit; the asset
stays pending and retries, and the alert is not lost.

## 6. Evidence problems

| Symptom | Cause | Action |
| --- | --- | --- |
| App shows "evidence still arriving" | `evidence_relay_states.state = pending_upload` - the cloud has the metadata but not the bytes | check the forwarder is draining assets, and that `CLOUD_EVIDENCE_DIR` has not been wiped by a redeploy on ephemeral disk |
| `evidence_token_required` / `evidence_token_invalid` | the short-lived retrieval token is missing, expired, or used for a different asset | expected: the app re-requests. A phone that loops here has a clock far off the server's |
| `evidence_key_invalid` | a storage key outside the allowed shape, or attempting traversal | the confinement is doing its job; never widen it to make an error go away |
| A sha256 mismatch on read | the stored byte is not what was recorded | treat as corruption. `evidence_assets.sha256` is authoritative; restore from backup or re-capture |
| Empty evidence where the console has some | the assets are scoped to cameras this officer cannot see | scope, not loss |

## 7. Camera and monitoring-side problems

| Status / result | Meaning | Usual cause |
| --- | --- | --- |
| `pending_setup` | registered, never proven | the connection test has not run or has not passed |
| `testing` → `host_unreachable` | nothing answered the socket | wrong IP, VLAN routing, camera asleep |
| `authentication_failed` | the camera refused the login | wrong stream credentials; re-seal via the registry rather than editing the DB |
| `stream_path_invalid_or_unsupported` | connected, but that path is not a stream | compare against the VLC-verified URL, character by character |
| `video_decode_failed`, "no decodable video frames arrived" | bytes arrived, no frames | codec the build cannot decode, or a substream the probe cannot open |
| `timed_out` | the camera stopped mid-handshake | raise `WATCHTOWER_PROBE_TIMEOUT_SECONDS` only after checking the network |
| `degraded` | frames are late (`WATCHTOWER_DEGRADED_AFTER_SECONDS`) | bandwidth, or the camera serving more streams than expected |
| `reconnecting` | the worker died and is coming back within the grace window | check `termination_reason` and `retry_count` in `camera_stream_sessions`; backoff is `WATCHTOWER_STREAM_BACKOFF` |
| `authentication_failed` appearing after a working period | credentials changed on the camera | re-run the connection test; do not hand-edit `camera_secrets` |
| Live view shows nothing but health is `online` | the browser is not getting JPEG | viewer count and measured fps are in the session row; `WATCHTOWER_LIVE_MAX_MBPS` throttles by design |

A camera only reaches `online` after frames are confirmed. If a row says `online` with
`last_successful_frame_at` null, that is a bug - report it, do not adjust the threshold.

## 8. The app itself

- **The screens show obviously canned data.** A fixture build. `npm run verify` fails if a
  fixture marker reaches a production bundle, so rebuild without `VITE_USE_FIXTURES`.
- **Tapping a notification opens a browser instead of the app.** Either the payload carries
  the `watchtower://` scheme and Android has no handler (an old install), or you are using the
  HTTPS form and the host in `AndroidManifest.xml` is still the placeholder, or
  `/.well-known/assetlinks.json` does not match the signing certificate
  (`docs/android-build.md` §5).
- **The app is silent for some severities.** The channel for that severity is minimised or
  silenced in Android settings, or the profile's `sound` preference is `silent`. Critical and
  escalated alerts ignore the preference - if a critical one arrives silently, that is a defect.
- **Cold start shows a login screen after a working week.** Expected at a 30-day refresh TTL,
  or after a password change revoked the family.
- **An alert appears twice in the banner stack.** It should not: the live banner is keyed by the
  notification id, so the poll and the stream produce one banner for one row. If you see two, the
  ids differ, which means the alert really was written twice - look at `notifications` for that
  incident rather than at the app.
- **The badge count and the list disagree.** The badge is bumped by the stream and reset by the
  list's own `total_unread` on the next read, so a disagreement lasts one cadence. A disagreement
  that persists is a server defect in `total_unread`, not a client bug.

## 9. When to stop

Stop and escalate rather than improvising if the fix would be: exposing the monitoring host or
a camera port; putting an RTSP URL or a camera credential in an API response; replacing
PostgreSQL with SQLite for a real deployment; adding Redis to "fix" the queue; deleting an
audit or attempt row to make a symptom disappear; or marking an acceptance test passed because
the code looks right. Those are not troubleshooting steps - they are the constraints the system
exists to hold.
