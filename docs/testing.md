# Testing and Quality Assurance

Covers proposal section 18. Every test group named there is listed below with the check that
corresponds to it and how it is verified. The **Status** column is deliberately honest:
"automated" means a pytest case exists, "manual" means a person must perform it, and
"**blocked**" means it cannot be performed without the physical camera or AFIT
authorization. No blocked item is presented anywhere in this project as passed.

Run the automated suite with:

```bash
cd watchtower
python -m pytest -q
python -m ruff check src tests migrations
```

Tests build their own `Settings` object and use SQLite dialect variants where a unit test
needs a database, which is a testing convenience only — deployment refuses anything but
PostgreSQL (`config.py::load_settings`), so a green suite is not evidence that the
production migration path works. That is checked separately with
`alembic upgrade head --sql` and against a real PostgreSQL instance. Because the harness
bypasses `load_settings()`, the refusals themselves are pinned directly by
`tests/test_config_guards.py`: a missing or non-PostgreSQL database URL, a session secret
shorter than 32 characters, a webhook that is not http(s), and the HTTPS default for each
environment. The convenience cannot mask a broken guard.

## Where each area is tested

| Module | Covers |
|---|---|
| `tests/test_rtsp_parser.py`, `tests/test_rtsp_probe.py` | URL parsing, and probe outcomes against a stub socket (never a live camera) |
| `tests/test_supervisor.py`, `tests/test_live_view.py` | Stream capacity, restart/park, viewer counts, MJPEG delivery and session tokens |
| `tests/test_health_evaluator.py` | Blip tolerance, degraded and offline transitions, recovery, auth-fault distinction |
| `tests/test_rbac.py`, `tests/test_rbac_seeding.py`, `tests/test_registration_workflow.py` | Roles, camera-group scoping, the registration-to-activation guard |
| `tests/test_secret_handling.py` | Sealing at rest, redaction (patterns and key names), and a scan of every response body |
| `tests/test_detection_events.py` | Synthetic-frame candidate generation, confidence floor, dedupe and suppression |
| `tests/test_incident_workflow.py` | Review decisions, assignment, escalation, resolution and reopening |
| `tests/test_evidence_capture.py` | Snapshot adoption, integrity, retention, path safety and download authorization |
| `tests/test_session_and_transport.py` | Tokens, logout revocation, lockout, self-service password change (the replaced hash, the revoked token, the surviving refusal record), CSRF, HTTPS enforcement and hardening headers |
| `tests/test_operations_report.py` | The Reports screen's numbers: both window ends honoured, zero-filled severity buckets that still sum to the incident count, a gap-free daily trend, the 90-day chart cap and its `truncated`/`excluded_days` flags, camera ranking, and the inverted-window and permission refusals |
| `tests/test_harness.py` | Smoke: the application boots against the fake supervisor, login reaches `/api/auth/me`, `/healthz` and `/readyz` answer, and every API path hard-coded in the dashboard resolves to a declared route |
| `tests/test_config_guards.py` | `load_settings()` itself: the PostgreSQL-only rule, the minimum session secret, the HTTPS defaults per environment, the webhook scheme check and the numeric limits |

## Camera registration tests (section 18)

| Required test | Check | Status |
|---|---|---|
| Valid RTSP connection | `rtsp/parser.py::parse_connection_string` accepts a well-formed URL and produces a validated `ConnectionSpec`; `probe.run_probe` returns `connection_successful` | parse: automated. Probe success: **blocked** — needs a real camera |
| Incorrect credentials | raw `DESCRIBE` returns 401/407 → `ProbeResult.AUTH_FAILED`, message redacted | automated against a stub socket; live confirmation blocked |
| Incorrect stream path | 404/501 on `DESCRIBE` → `PATH_INVALID` | automated against a stub socket; live confirmation blocked |
| Unreachable host | connect failure → `HOST_UNREACHABLE`; connect hang → `TIMED_OUT` | automated (TEST-NET address, verified to reach the terminal state with the configured backoff) |
| Invalid input | non-RTSP scheme, missing stream path, out-of-range port, blank fields → `RTSPSpecError(field, message)` | automated |
| Duplicate camera code | unique constraint on `cameras.code`; service surfaces a field-level error rather than a database traceback | automated |
| Camera configuration editing | `services/cameras.py::update` forces a re-test and stops the running session on a connection-relevant change — an edited camera cannot stay `online` on the strength of the previous test | automated |
| Safe secret handling | password sealed into `camera_secrets`; camera row stores `secret_reference`; responses expose only host, port, path, username and `has_secret`; `redact()` masks `rtsp://user:***@host`, `?password=` and JSON `"password"` | automated, including a scan of recorded audit rows and log lines for the plaintext secret |

The activation guard is tested explicitly: `activate()` raises `test_required` when no test
has run and `test_not_passed` when the latest test failed, and the state it writes is
`testing`, never `online`.

## Live-stream tests (section 18)

| Required test | Check | Status |
|---|---|---|
| Continuous playback | managed stream keeps publishing latest-frame updates; measured fps recorded on the session | automated with a synthetic frame source |
| Browser playback compatibility | MJPEG `multipart/x-mixed-replace` renders in the supported browsers | **manual** — needs a browser and a camera |
| Reconnection after interruption | worker reconnect loop with the configured backoff sequence | automated (unreachable-host restart path) |
| Worker restart and recovery | supervisor restarts a dead worker up to `max_stream_restarts`, then parks it and emits a health event | automated |
| Multiple simultaneous viewers | viewers attach to one managed source stream; attach happens on MJPEG connect, not on session open, so counts are not inflated | automated |
| Stream resource cleanup | `shutdown()` leaves zero active sessions and zero worker processes; duplicate `ensure()` for the same camera id returns the same managed stream | automated |

Session-token authorization is also tested: a token presented by a user other than its
owner is rejected, and a released token yields `410`.

## Health tests (section 18)

| Required test | Check | Status |
|---|---|---|
| Temporary disconnection | blips shorter than `degraded_after_seconds` do not change state — this is the anti-alert-storm property | automated |
| Sustained offline state | no frames beyond `offline_after_seconds` → `OFFLINE` plus a health event | automated |
| Authentication failure | worker surfaces an auth error → `AUTHENTICATION_FAILED`, distinct from `OFFLINE` | automated |
| Degraded frame delivery | frame rate below threshold → `DEGRADED` | automated |
| Camera restoration | recovery promotes to `ONLINE` on confirmed delivery and records the transition | automated |
| Notification deduplication | health events are recorded on change only; the same sustained condition does not repeat an alert | automated |

The regression that this table is really guarding against: `refresh_health` once compared
its `changed` flag against state that had already been mutated, so it was always false and
transitions never fired. The test captures `previous_status` before
`sync_stream_state()` runs.

## AI and incident tests (section 18)

| Required test | Check | Status |
|---|---|---|
| Candidate-event generation | detectors emit `RawFinding` → `DetectionEvent` with confidence, zone and bbox metadata. Only `available` detectors run; the altercation and theft stubs raise rather than emit | automated with synthetic frames |
| Duplicate-event suppression | dedupe key on camera + category + zone within `duplicate_event_window_seconds`; a suppressed event updates the existing record instead of creating a second | automated |
| Alert delivery | notifications created for candidate events and health changes | automated |
| Human acknowledgement | incident workflow: acknowledge, dismiss, escalate, assign, resolve, mark false-positive, reopen — each recorded as an `incident_actions` row | automated |
| Incident assignment and resolution | assignment records the target user; resolution requires an outcome and is auditable | automated |
| Evidence-access authorization | retrieval checks the caller's permission **and** the camera group of the asset's own camera before returning bytes; an ungrouped camera is invisible to a scoped reviewer | automated |
| Evidence integrity | SHA-256 recorded at write time and verified on read; a mismatch is surfaced as a failure and audited, never silently served | automated |
| Evidence path safety | a crafted asset key cannot escape the evidence directory (relative and absolute forms both refused) | automated |
| Evidence capture | a candidate snapshot written by the analysis pass is registered as an `evidence_assets` row (digest, expiry, audited download) and follows the candidate into the incident it is escalated to | automated |
| Evidence retention | `purge_expired` removes only past-expiry assets, retires the record, and a deleted asset returns `404`; reachable only through an authenticated admin POST | automated |

Detection accuracy is **not** asserted anywhere. See `docs/detection-limitations.md`.

## Security tests (section 18)

| Required test | Check | Status |
|---|---|---|
| Unauthorized camera access | `can_view_camera` with camera-group scoping; out-of-scope camera → `403`, and `404` for a malformed id so the response is not an id-probing oracle | automated |
| Credential leakage | grep-equivalent assertions over API responses, error text, audit rows and captured log lines for the known plaintext secret | automated |
| Role-permission enforcement | administrative rights and viewing rights are separate codes; each router declares its own permission | automated |
| Audit-log completeness | sign-in, failed sign-in, camera create/edit/activate/disable, incident actions, admin purge all recorded | automated |
| Evidence-access restrictions | as above, plus retention purge only through an authenticated admin POST | automated |
| Session handling | JWT HS256 signed with an HKDF-derived purpose key (a token forged with the master secret is refused), logout revocation that covers the cookie and the bearer transport, expiry refused, a deactivated account's live session ended | automated |
| Login lockout | `failed_login_count` and `locked_until` persist through the rollback of the refused request that set them; a locked account is refused even with the correct password, and recovers when the lock expires | automated |
| Transport security | with `require_https`, a plain-HTTP read gets `307` to the HTTPS URL, a plain-HTTP write is refused `https_required` rather than redirected, and a TLS-terminating proxy's `X-Forwarded-Proto` is honoured; the session cookie is `Secure` only when HTTPS is enforced; CSP forbids inline scripts and `frame-ancestors 'none'` | automated for the middleware; deployment TLS is **manual** |
| CSRF | custom-header requirement on cookie-authenticated writes (bearer clients exempt), `SameSite=strict` plus `HttpOnly` and a TTL-bounded `Max-Age`, and reads unaffected | automated |
| Audit purge is not a GET | the route is `POST`; a crawler or prefetch cannot delete the trail. This was a real defect found and fixed during development and is now covered by a test | automated |
| An unhandled fault leaks nothing | the `Exception` handler returns `internal_error` without echoing the exception text, which is where an FFmpeg or driver fault would otherwise carry a credential-bearing RTSP URL | automated |

## Defects these tests found in the implementation

Each of these was real, was fixed in `src/`, and is pinned by a named test so it cannot come
back (the last row is a contract trap rather than a product defect, and is listed because it
cost the suite a false conclusion). They are listed here rather than only in a commit message
because the next reader of this table deserves to know what the table was bought with.

| Defect | Consequence if left alone | Pinning test |
|---|---|---|
| Candidate snapshots were never registered as `evidence_assets` | The alert's own image had no digest, no expiry, no audited download path, and an escalated incident listed no evidence at all | `test_evidence_capture.py::test_adopting_a_candidate_snapshot_gives_it_a_digest_and_an_expiry` |
| Snapshot keys collided inside one second | Two alerts overwrote one file, so the first event's recorded SHA-256 pointed at bytes it never wrote | `test_evidence_capture.py::test_two_snapshots_in_the_same_second_keep_their_own_bytes` |
| Evidence download scoped the incident only | A reviewer scoped to one camera group could fetch bytes belonging to a camera outside it whenever no incident was attached | `test_evidence_capture.py::TestEvidenceHttpAccess::test_an_asset_whose_camera_is_outside_the_scope_is_refused` |
| A mapping key naming a credential hid its value from redaction | `{"rtsp_password": "…"}` reached an audit row or event metadata unmasked, because redaction only pattern-matched strings | `test_secret_handling.py::test_a_key_naming_a_credential_masks_its_value_even_without_a_pattern` |
| A failure audit row was rolled back with the refused request | `SENSITIVE_ACTIONS` promised failed attempts in the trail, but the route raises after recording, so `get_db` rolled the row away — no record of a brute-force attempt | `test_session_and_transport.py::TestAuditCompleteness::test_a_refused_login_is_recorded_before_the_401_leaves_the_process` |
| The login failure counter relied on that rollback | Lockout never accumulated, so the account-lock control was inert | `test_session_and_transport.py::TestLoginLockout::test_a_failure_count_survives_the_rollback_of_the_refused_request` |
| The rollback guard is an allow-list, and a new endpoint can miss it | `POST /api/auth/password` recorded its refusal and then raised, exactly like the login route did — but `auth.password_change` was not yet in `SENSITIVE_ACTIONS`, so a wrong current password left no trace. Adding a refusal-auditing route means adding its action here | `test_session_and_transport.py::TestPasswordChange::test_a_wrong_current_password_leaves_the_account_untouched` |
| `AnalysisEngine.run()` analyses one frame per call, throttled by that frame's own timestamp | Not a product defect, but a trap: a first draft of the detection tests called it once and "proved" nothing was detected. The suite polls per frame instead | `test_detection_events.py` (the `poll` helper is the contract) |

## Frontend verification is done in a browser, not by the suite

There is no JavaScript test runner for the **monitoring console** (`src/watchtower/api/web/static`,
hand-written ES modules), so nothing in the pytest suite proves the dashboard renders. The
personnel application is a separate case and does have one - see
"Personnel-mobile and cloud coverage" below. `tests/test_harness.py` only checks that every `/api/...` string the
frontend uses names a real route. Everything else about the console is a manual check, and
that check has already paid for itself more than once:

| Defect | Consequence if left alone | How it was found |
|---|---|---|
| `ui.js::h()` treated its second argument as attributes only, so `h('div.shell', [a, b])` - the form 194 call sites use - set `0="[object HTMLElement]"` and appended nothing | The whole console rendered as an empty page: no rail, no sections, no panels, and no error in the log. The API calls all returned 200, which is why a backend-only test suite could never have noticed | Loading `/dashboard` in a browser against the demo process and reading `#app` |
| `admin.js` used `durationText()` without importing it | Every valid ES module link check passes until the line runs, so the Reports screen rendered its filters and then threw a `ReferenceError` that `describe()` turned into "The request could not be completed." - the seven pytest cases for that endpoint all passed because they never touch the frontend | Driving `renderReports()` in the browser against a fixture payload, and reading the error the temporary `console.error` printed |
| The password form set its button busy *before* calling the helper, outside the promise chain | If the helper was missing (one stale module in the unhashed import graph is enough) the throw was synchronous, so `.finally` never ran: the operator saw a permanently disabled "Changing..." button and no explanation | Reproduced in the browser against a server process older than the screen, where the stale cache served exactly that half-updated module graph |

Performed on 2026-10-30 against `scripts/dev_serve.py` (SQLite demo process, loopback):
sign-in, the shell and all five rail sections, the permission gate that hides Live
monitoring from a role without `camera.view_live`, and the Add Camera dialog's connection
test against an RFC 5737 TEST-NET address, which returned `timed_out` after 12.0 s with
zero frames decoded and no registry row written. What that run does **not** cover is any
camera-backed path: MJPEG playback, activation, health transitions under a real stream and
detection on real video all remain open until the address from the VLC test is registered.

A second walk on 2026-11-03 covered the rebuilt Reports and Settings screens against the
running loopback console. Settings was exercised end to end on a real session: the account
tiles, the three password fields and each of their client-side refusals (empty current,
under 12 characters, mismatched repeat), and the Devices panel listing the one registered
camera with its health-loop status. Reports could only be exercised as far as its permission
gate, because the signed-in role holds no `report.operational`, and the rail keeps the
section locked rather than rendering an empty page for it. The charts themselves were then
driven in the browser through `renderReports()` with a fixture payload, which is what found
the missing import above; that proves the drawing code, not that the live server returns
those figures. Both halves therefore remain open until one run on an account that holds
`report.operational`, against a process restarted with the aggregate endpoint.

## What must be performed with the real camera

The following cannot be substituted with a stub, and until they are done the prototype
should not be described as verified:

1. `probe.run_probe` against the user's VLC-verified address returns
   `connection_successful` with a measured frame rate and decoded-frame count.
2. Activation → managed session → frame delivery → automatic promotion to `online`.
3. Live view in the target browsers at the camera's real resolution.
4. Sustained soak: hours, not minutes, watching for memory growth in the worker and for
   `degraded` transitions that never recover.
5. Physical interruption drill from the runbook (cable pull, lens cover) and the resulting
   health events and notifications.
6. Detection observation with no tuning — record what the detectors fire on in the real
   scene before anyone adjusts a threshold.

## Pilot-era evaluation

False-positive rate, detection limitations and alert workload are measured during the
pilot, not claimed before it. `docs/pilot-evaluation.md` defines the metrics and the
approval gate.

## Personnel-mobile and cloud coverage

Run both halves separately - they are separate deliverables and separate failure domains.

```bash
cd watchtower
python -m pytest -q                                             # backend, all suites
python -m ruff check src tests migrations scripts

cd personnel-app
npm run verify                                                  # typecheck + build + fixture scan + endpoint scan + unit tests
```

`npm run verify` is `tsc --noEmit && vite build`, then `verify:fixtures` over the emitted
bundle, then `verify:api-config`, then `vitest run`. The fixture scan is not decoration: a
development fixture that reaches a release bundle produces normal-looking screens talking to a fake
API, and no type error would ever report it. The endpoint scan is in the same category and earned
its place the same way - see the defect row below.

| File | Cases | What it pins down |
|---|---|---|
| `tests/test_cloud_auth.py` | 31 | login, refresh rotation, reuse revoking the family, logout, password change, session-scoped `/auth/me`, lockout |
| `tests/test_cloud_ingest.py` | 42 | the signature scheme, every refusal code, nonce replay, idempotency answered from `ingest_records`, body and digest limits |
| `tests/test_cloud_delivery.py` | 63 | targeting order, preferences and quiet hours (UTC), forced alerts, per-device attempts, the payload the handset is told to display, and - over HTTP - a handset with no push token receiving, counting and clearing its alert. Includes the worker tick with one job selected: a delivery-only pass pages and leaves the sweep untouched, an escalation-only pass queues a re-page and never calls the provider |
| `tests/test_cloud_cli.py` | 19 | the two promises a hosting platform depends on: `PORT` is bound unless `--port` says otherwise, and a `PORT` that is not a number or is out of range refuses to start rather than binding something the proxy cannot see; and `worker --jobs` selecting exactly the loops named, with `--host` still defaulting to loopback |
| `tests/test_cloud_evidence.py` | 23 | short-lived retrieval tokens, asset scoping, sha256 verification, traversal refusal, `pending_upload` reported as still arriving |
| `tests/test_cloud_incidents.py` | 34 | list/filter/cursor, detail shape, activity, the response actions and their permission checks |
| `tests/test_cloud_stream.py` | 53 | the live channel: cursor round-trip and refusal, the drain's scoping (own notifications only, camera-granted activity only) and its no-repeat position, frame wire form, heartbeat, the two closing reasons, a driver error never reaching the wire, disconnect ending the reads, every `CLOUD_STREAM_*` guard the loader refuses, and the route's 401/403/503 answers and its slot accounting |
| `tests/test_cloud_app.py` | 23 | app wiring: CORS, HTTPS enforcement, error envelope, liveness endpoints, route inventory against the contract, and that every path exempted from the TLS rule is one the app actually serves |
| `tests/test_mobile_outbox.py` | 27 | enqueue inside the caller transaction, claim with `SKIP LOCKED`, retry/backoff, settlement, the JSONL spool and its replay |
| `tests/test_mobile_worker.py` | 13 | the drain thread: cadence, disabled state, evidence bytes read-or-nothing, no exception escaping into the loop |
| `tests/test_mobile_signing.py` | 21 | canonical request construction, skew, nonce shape, key-id agreement, and that a wrong secret produces `bad_signature` rather than a leak |
| `tests/test_mobile_alert_hook.py` | 15 | which incident state change enqueues which kind, and that the hook never raises |
| `tests/test_mobile_schema.py` | 17 | mobile tables on the shared `Base`, the unique constraints, a push token never stored in the clear, and a single-headed migration history so `check-schema` can compare |

The application suite is 125 cases in twelve files:

| File | What it pins down |
|---|---|
| `src/api/client.test.ts` | bearer headers, timeout, retry queue, single-flight refresh on a 401, error normalisation |
| `src/api/errors.test.ts` | every contract error code mapped to a message a person can act on |
| `src/config/apiUrl.test.ts` | the endpoint resolver: both configuration keys and which wins, the `/api/v1` prefix and not doubling it, and the four states - a public HTTPS host is ready, nothing configured is unconfigured and blocks sign-in, a loopback or RFC 1918 address is local and blocks a packaged build but not a labelled dev one, plain HTTP is insecure and blocks the same way. Includes that `10example.org` is not a private address. |
| `src/auth/permissions.test.ts` | the client-side mirror of role and permission checks - and that it never replaces a server decision |
| `src/devfixtures/transport.test.ts` | the fixture transport validates the way the real API does, including rejecting a `sound` the server would answer 422 for, so a fixture cannot teach a screen wrong behaviour |
| `src/hooks/useAsync.test.ts` | the four properties foreground polling must keep: it runs on the cadence, a slow request is not stacked behind the next tick, a hidden webview asks for nothing and catches up on `visibilitychange`, and a 401 ends the polling rather than turning one refusal into a hundred requests |
| `src/hooks/useCursorList.test.ts` | the same cadence on a paginated list: a poll re-reads page one without blanking the rows on screen, never overtakes a page append in flight, and falls silent on a refused session |
| `src/lib/severity.test.ts` | severity/status vocabulary, channel ids, and the alert-sound options offered versus what the server accepts |
| `src/api/stream.test.ts` | the SSE reader: bearer in a header and never in the URL, the cursor carried into the reconnect so a row is not delivered twice, backoff that resets on a successful `ready`, an immediate reconnect after the service's scheduled `lifetime` close, and the answers that stop asking (`stream_disabled`, `404`, `401`/`403`) |
| `src/hooks/useLiveReload.test.ts` | a live revision re-reads quietly: no second load behind the initial one, one re-read per change, none for a repeated number, and the callback from this render rather than the one that mounted |
| `src/push/deeplink.test.ts` | `watchtower://` and HTTPS forms parsed to an incident id, internal `#/` routes, and that a bare click action never becomes a destination |
| `src/screens/NotificationSettingsScreen.test.ts` | the preferences screen offers only what `PUT /profile/preferences` accepts |

### The redesigned screens, checked in a browser

The suite never renders a screen, so the visual redesign of the personnel app (the 10-panel
mockup) was walked in a browser on 2026-11-03 against `VITE_USE_FIXTURES=1 npm run dev`
(port 5174, loopback). What was observed, screen by screen, through the page's accessibility
tree rather than a pixel screenshot — the browser surface in this environment would not produce
one, so colour, spacing and image rendering are **not** covered by this record:

| Screen | Observed |
|---|---|
| Login | emblem, banners, both fields, disabled-until-filled submit, footer `endpoint · environment · v1.0.0` (version injected from `package.json` at build time) |
| Dashboard | three severity tiles with counts, active incident rows, system status block (pending/failed/unread and the failed-delivery line), latest alerts, 24-hour tally, access summary |
| Notification centre | five rows newest-first, filter chips, advanced filters, per-row and mark-all read actions, end-of-history line |
| Incident history | four rows, severity chips, search field, cursor footer |
| Incident detail | severity banner with reference and status, information rows, response region, evidence region including the past-retention wording, activity history with the notes link |
| Acknowledge | confirm sheet (`§6.3` wording) → receipt sheet naming `WT-2026-0005`, the new status "Under investigation", and next actions |
| Investigation notes | composer with the 2000-character counter, save → "Saved. The note is in the activity history below…", and the note re-read in Activity as "Note added" with actor and timestamp |
| Profile hub, Account information | identity card with derived account status, role chips, camera scope rendered as `all camera groups`, and the eight effective permissions resolved by the server |
| Device status | "Not registered for push" plus the honest "no Firebase project is configured in this build", device rows with `ACTIVE`/`REVOKED` push state and last-seen, revoke and forget-this-handset actions |
| Notification preferences | mandatory-alerts panel (`critical, incident.escalated`), minimum severity held by a then-present policy lock, per-kind switches with the forced one disabled, quiet hours with the UTC warning, sound select; save → confirmation and the value still off after leaving and returning. Both the lock and the switch list changed afterwards — see the next section. |
| About this build | version, endpoint, timeouts, installation id, live/push/refresh/transport lines and "Service health: not probed" under fixtures |
| Forced password gate | current/new/confirm fields, the 12-character rule as live feedback |

Two claims were corrected by that walk, both of them the app asserting something it had not
checked: the About screen's transport line said "TLS endpoint" while `isInsecureApiHost()`
suppresses the plain-HTTP warning under fixtures (it now reads the URL scheme directly), and the
Device status screen said "the live channel is the fast path on this device" in a build where
`VITE_LIVE_FEED`/fixtures close it. A third line — "No asset stored for this incident" on the
notes screen — now distinguishes an incident with no asset from one whose asset is past retention.

Not covered by this run, and still open: the same screens at a phone viewport on a handset, and any
pixel-level confirmation of the mockup's colours and spacing. The screens themselves were then
walked again against the real cloud API — see the next section, which is where two defects this
fixture pass could not see were found.

### The same screens against the real cloud API

On 2026-11-03 the walkthrough was repeated with `VITE_USE_FIXTURES=0`, pointing at the cloud API
on `127.0.0.1:8080` and the Neon database, signed in as a real personnel account (`iliyasu`,
Security Operator, id 3). The account's password did not match the hash on file, so it was set to
the value the account's owner supplied, through the application's own `hash_password` and with an
`admin.user.password_set` audit row; the mismatch was checked offline against the stored hash
first, so the login rate limiter was never walked up to the lock-out threshold.

| Screen | Observed against the live service |
|---|---|
| Login | emblem served from `/brand/afit-emblem.png`, both banners, sign-in issued a real token pair into `sessionStorage` |
| Dashboard | tiles all zero, "No incident is open or under investigation in your scope right now", status block reading the real outbox (`PENDING 0 · FAILED 0 · UNREAD 0`), live channel shown as connected, access panel showing the server's eight permissions |
| Notification centre | "0 loaded · newest first", the no-match empty state, mark-all-read present |
| Incident history | filters rendered, "No incidents match" with the §1 not-visible-equals-not-exact wording |
| Profile hub | `abba / iliyasu / Security Operator`, installation id from this session, sign-out and forget-device copy |
| Account information | identity fields, `all camera groups` scope for incidents and evidence, the eight effective permissions |
| Device status | "Not registered for push", the honest no-Firebase line, live-channel and 20s refresh copy derived from the real endpoint |
| About this build | `v1.0.0`, endpoint, `12s for data calls, 15s for sign-in`, transport line correctly reporting plain HTTP, service health from the real `/healthz` (`database ok · push disabled · live channel enabled`) |
| Notification preferences | six kind switches, `incident.escalated` disabled as forced, save → server confirmed and the value persisted |

Two defects were found by this pass and both were in the preferences screen. The first was a
false statement: `GET /profile/preferences` returns only the kinds an account has overridden, and
`cloud/targeting.py` suppresses a kind only when it is present and `false`, so an empty map means
*everything is on* — but the screen read the stored map as its whole vocabulary and reported "The
server reported no configurable kinds" to an officer who had never touched the switches. The six
kinds are now rendered from the client's mirror of `KNOWN_KINDS`, with an absent kind shown as
enabled and an unrecognised key still getting a row. Three tests in
`src/screens/NotificationSettingsScreen.test.ts` pin that rule.

The second was worse than a wrong word. The save path "re-asserted" the forced values before
sending, and for a forced *severity* that meant writing `min_severity = "critical"` — so pressing
Save on an account whose floor was `low` quietly muted every high, medium and informational alert
for that account, while the screen still displayed "Held at Informational by policy". The
re-assertion is gone: `apply_preferences` delivers a forced severity or kind before it reads the
floor, the toggles or quiet hours, so there was never anything for the form to protect, and the
screen now says what the server actually does. The walkthrough account was restored to
`min_severity: low` through the fixed screen, and its stored `kinds` are
`{camera.health: true, incident.escalated: true}` — explicit trues where the account previously
stored nothing, which the delivery rule reads identically.

### The three endpoint states, checked in a browser

The endpoint correction changed what the login screen is allowed to do, so all three states were
loaded in a browser on 2026-11-03 rather than only asserted by the resolver's unit tests. The
production bundle was built with no endpoint configured, which is the state a release build is in
until AFIT hosts the cloud service.

| State | How it was produced | Observed |
|---|---|---|
| unconfigured | `npm run build` with `.env.production` as checked in, served on loopback | banner "NO SERVER CONFIGURED"; the reason sentence names both keys; submit disabled and relabelled "No secure server"; footer `no cloud endpoint · production · v1.0.0`. Username and password were filled and the form submitted anyway — the page stayed on `#/login` and the network log showed **only** the five static asset requests (bundle, stylesheet, two brand images, the Capacitor web shim), so no credential left the device |
| local, in a dev build | `npm run dev` reading `.env.development.local` | banner "INSECURE ENDPOINT" naming `127.0.0.1` as a loopback and saying it is never a production mobile API; no `endpoint-blocked` paragraph; submit enabled; signing in as the account's owner reached `#/dashboard` with the real outbox counts, the live channel reported connected, and the access panel showing the server's eight permissions. The labelled development path still works, loudly |
| ready | a temporary `.env.production.local` with an `https://` host, rebuilt | `verify:api-config -- --release` reported the endpoint as HTTPS on a public host and found the configured value inside the emitted JavaScript |

The temporary file was removed and the bundle rebuilt afterwards, so what is on disk is the
unconfigured release build. Two negative runs of the same script were recorded because a check that
has only ever passed is not evidence: with the production key set to `http://127.0.0.1:8080` it failed
as a loopback endpoint, and with `http://watchtower.example` it failed as plain HTTP. Injecting
`http://127.0.0.1:8080` into the emitted directory made the leak scan fire as well. The scan started
life as a generic "every `http://` URL in the bundle" search and was replaced: react-router embeds the
literal `http://localhost` as an origin placeholder and the SVG namespace is plain HTTP, so the
generic version reported library internals as endpoints. Checking against this machine's development
values is both narrower and the actual rule.

One thing this did not clear: no APK rebuilt with a real endpoint has been installed on a handset,
because there is no HTTPS cloud host to point it at. The phone that reported the original failure is
still running the bundle that carries it.

One timing observation, not a defect: the first dashboard read after sign-in exceeded the 12s
client timeout and the screen correctly showed `network_timeout` with a Try again control; the
retry succeeded, and the same `/dashboard/summary` call measured 5.5s cold and under 2s warm. That
is Neon round-trip latency from this machine, and it says something about a handset on a mobile
network that has not been measured yet.

Still not covered, and this pass does not change any of it: the incident detail, acknowledge,
escalate, resolve and investigation-notes screens, evidence retrieval, and the notification path
end to end, because **the database contains no incidents, no cameras and no notifications** —
those screens have only ever been exercised against fixture data. The same is true of everything
that needs a handset: no phone has run this build, and no push has reached one. A phone viewport
and any pixel-level confirmation of the mockup's colours and spacing remain open too; the browser
surface used here reports the accessibility tree, not an image.

### The payload tests

`TestAndroidPresentation` in `tests/test_cloud_delivery.py` exists because the delivery
format had no coverage at all: five defects in the server push payload each produced a send
this service reported as accepted and a phone that stayed silent. One of the six cases is a
cross-language check - it reads `personnel-app/src/lib/severity.ts` and asserts that every
`channel_id` the server can name is a channel the app actually creates, because Android
discards a notification naming a channel that does not exist on the handset.

## Defects the mobile work found in the implementation

Recorded because "the tests pass" is only interesting if it says what they caught.

| Found by | Defect | Consequence had it shipped |
|---|---|---|
| Found on the handset by the owner | a development endpoint compiled into the APK. `env.ts` defaulted `VITE_API_BASE_URL` to `http://localhost:8080`, and the machine's `.env.local` set `http://127.0.0.1:8080` - and Vite reads `.env.local` in **every** mode, including the one that produces a release bundle | the first real login attempt on a real phone failed with "Cannot reach the service", because the app's server was somebody's laptop. Nothing in the suite could have caught it: the tests never read the environment, and the bundle type-checked. Now `src/config/apiUrl.ts` has no default host and classifies what it is given, a packaged build refuses to send a password to a loopback, private or plain-HTTP endpoint, the endpoint files are split by mode so `.env.local` is not used at all, and `verify:api-config` searches the emitted JavaScript for this machine's development address |
| Payload tests | `channel_id` values the Android app never creates | every alert silently discarded by the handset |
| Payload tests | `click_action` referencing an action the app cannot resolve | tapping a notification opened nothing |
| Payload tests | no `title` in the Android notification block | a notification with no visible text |
| Payload tests | a `silent` preference ignored, and forced alerts not exempt from it | an officer quiet setting applied to critical alerts, or the reverse |
| `src/lib/severity.test.ts` | the settings screen offered `vibrate`, which the API answers 422 for | a preference a user could select and never save |
| `check-schema` against the live database | the Neon database sat at `0002` while the code required `0003`, and the command printed the revision without comparing it to head | every mobile login returning a 500 on a deployment that looked healthy |
| `.env.example` audit | the template held a real database password and a real JWT signing secret | live credentials in a file that invites committing; both values need rotating |
| Schema audit against the code | `ingest_records.request_digest` was stored and never compared, so a spent idempotency key reused with different content was answered with the first stored response | the second alert would be discarded while the forwarder was told it succeeded - a silent alert-loss path. Now refused with `409 idempotency_conflict` |
| Booting the cloud API against the live database | the HTTPS exemption list named `/readyz`, a route only the monitoring console defines; the cloud API answered it with `404 not_found` | a hosting health check copy-pasted from the console's path fails on a service that is in fact healthy. The exemption is removed, `/healthz` is documented as the only probe, and a test now fails if the exempt list names an unserved path |
| The first test that put a row in the queue | `GET /api/v1/notifications` called `notification_view(session, note, settings, …)` while the view declares `settings` keyword-only: a `TypeError` on every request that had at least one item | **the officer's alert list was a 500 whenever there was something to read.** Route-inventory tests asked only for the empty list, which returns 200 without ever entering the loop - the same blind spot as a queue with no alerts in it. Every list route now needs a non-empty case |
| Foreground polling work | an alert was recorded only for recipients with a *push-capable* device, so a handset that had signed in but held no FCM token - every phone on a build with no Firebase project - was skipped entirely | the app would poll a queue that was never written to, and the alert centre would stay empty forever while the incident sat in the database. A phone that can display an alert now gets the row; a phone that can be paged is still only `targetable` |

## Mobile acceptance tests (proposal section 17)

Ten acceptance items. "automated" below means a test in this repository exercises the logic;
it does not mean the end-to-end behaviour has been observed on hardware, which is what the
Status column says.

| # | Acceptance test | What is automated | Status |
|---|---|---|---|
| 1 | A personnel account logs in on the app | `test_cloud_auth.py` (31 cases) plus `client.test.ts` refresh queue | **automated**; the real-host run needs a deployed API and a provisioned account. One attempt has been made on a real handset and it failed - the bundle carried a development endpoint. That is corrected and checked on the build machine; a rebuilt APK has still never signed in anywhere, because there is no HTTPS cloud host to sign in to |
| 2 | A handset registers and a push token is stored sealed | device registration API, sealing and fingerprint tests (`test_mobile_schema.py`) | **blocked** - no Firebase project, no handset. A token from a real FCM SDK has never been stored here |
| 3 | An incident created by the monitoring app lands in Neon | alert hook, outbox drain and signed ingest (84 cases) | **blocked** - needs the forwarder pointed at a real cloud host and a camera producing an event |
| 4 | The right officer is notified automatically | targeting, preferences, attempts and payload tests (63 cases), plus one HTTP run in which a handset with no push token receives the alert in its queue, the badge counts it, and opening it clears it | **partly automated** - the in-app half now passes end to end against the service; the push half is **blocked** on FCM, which Google has never been called for |
| 5 | Tapping the notification opens that incident | `deeplink.test.ts` (9 cases) plus `deep_link` presence in the payload | **partly automated** - parsing is covered, Android delivery and launch are not |
| 6 | Evidence is viewable: image and video | retrieval token, scope, sha256, `pending_upload` tests (23 cases) | **blocked** for real assets: there is no camera, so no captured snapshot or clip exists. The app renders both kinds; nothing has been rendered from AFIT footage |
| 7 | An acknowledgement is saved and visible to the console | `test_cloud_incidents.py` plus the unique `(incident_id, user_id)` constraint | **automated** |
| 8 | A notification arrives outside the AFIT network | none - it is a property of hosting plus push | **blocked** - no cloud host exists |
| 9 | Alerts queued while offline are delivered when connectivity returns | outbox retry/backoff, `SKIP LOCKED` claim, JSONL spool and replay (40 cases) | **automated** for the queue; the handset-side reconnection story is covered by the fetch-retry tests, not by a phone in a tunnel |
| 10 | An officer cannot see what their scope excludes | camera-group scoping across four route groups plus `permissions.test.ts` | **automated** |
| 11 | A change reaches the screens that are open, without a refresh tap | `test_cloud_stream.py` (53 cases) for the server half - scoping, cursor, no repeats, both closing reasons; `stream.test.ts` (14) plus `useLiveReload.test.ts` (2) for the client half - resume-from-cursor, backoff, dedupe-by-id, quiet re-read | **automated**; the on-device run is **blocked** until the local services are restarted onto this build and there is an incident in the database to deliver. It is not claimed as observed on a phone |

Seven of the eleven are automated as far as this machine can automate them. Items 2, 3, 6 and 8
need a Firebase project, a cloud host and a real camera, and none of them is presented here as
passed. The single most valuable thing AFIT can do next is **host the cloud API on a public HTTPS
origin** (`docs/deployment.md`): with that, an officer who has the app open on a phone at home
receives every alert through the live channel in about two seconds (§10.8), or through the
polling path (§10.7) if the channel is switched off, and nothing further is required to see an
alert. Provisioning a Firebase project and one handset is the step after it - it unblocks items 2,
4, 5 and 8 together, turns "the app shows it when opened" into "the phone buzzes in a pocket", and
is roughly an hour of console work following `docs/firebase-setup.md`.

One caveat the suite cannot remove: an alert is written for a recipient only if that person has
signed in on a handset at least once, because the device row is what says there is a screen to read
it on. An account nobody has ever logged into receives nothing, in-app or pushed.
