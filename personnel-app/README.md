# AFIT WATCH TOWER — personnel app

The officer-facing half of the system: a React + TypeScript + Vite + Tailwind application
that runs as a responsive web app and, through Capacitor, as a native Android app. It talks
to the cloud API only (`docs/mobile-api-contract.md`). It does not know a camera address, a
database credential, or a Firebase server secret, and it must never be taught to.

A debug APK has been assembled from this project and installed on one handset (2026-11-03). That
install is how the endpoint misconfiguration was found: the bundle carried this machine's development
address, so the phone had no server to reach. It is fixed and checked on the build machine
(`verify:api-config`); no rebuilt APK has been installed, because there is no HTTPS cloud host for it
to point at yet, and **no push has ever reached a phone from here**. See `docs/android-build.md` §8
and the acceptance matrix in `docs/testing.md` for exactly what is and is not proven.

## Commands

From this directory:

| Command | What it does |
| --- | --- |
| `npm install` | dependencies |
| `npm run dev` | Vite dev server on loopback |
| `npm run build` | `tsc --noEmit` then `vite build` — a type error stops the bundle |
| `npm run verify` | build, then `verify:fixtures`, then `verify:api-config` over `dist/`, then `vitest run`. **This is the gate** |
| `npm run test` / `test:run` | vitest watch / single run |
| `npm run typecheck` | `tsc --noEmit` alone |
| `npm run preview` | serve `dist/` locally |
| `npm run cap:add:android` | create/refresh the `android/` project from `capacitor.config.ts` |
| `npm run cap:sync` | copy `dist/` and plugin state into `android/` — run after every build |
| `npm run android:open` | open the native project in Android Studio |
| `npm run android:apk` | `cd android && gradlew.bat assembleDebug` |

`verify:fixtures` exists because a development fixture that reaches a release bundle produces
normal-looking screens talking to a fake API. No type error would report it, so the emitted
files are scanned instead.

`verify:api-config` exists for the same reason one size bigger: in November 2026 a handset was
installed with the developer's laptop as its API server, because Vite reads `.env.local` in *every*
mode including `vite build`. The script classifies what the production configuration resolves to and
then searches the emitted JavaScript for this machine's development address. Pass `-- --release` to
make an unconfigured endpoint a failure too — that is the flag for cutting an APK.

## Configuration

Vite picks the file by mode, and this app deliberately does not use a plain `.env` or `.env.local` —
those are read in every mode, so a development value written there is compiled into the release
bundle. The mode-qualified files keep development and production apart:

| File | Tracked | Read by | Holds |
| --- | --- | --- | --- |
| `.env.development` | yes | `npm run dev` | fixtures on, no API host |
| `.env.production` | yes | `npm run build` | fixtures off, **no API host** |
| `.env.development.local` | no | `npm run dev` | this machine's cloud API (a loopback address is fine here) |
| `.env.production.local` | no | `npm run build` | the deployed HTTPS endpoint |
| `.env.example` | yes | nothing | the reference for every key |

Every key is `VITE_`-prefixed because that is the only prefix Vite exposes to a bundle — which is
precisely why the template's HARD RULES matter: **anything in any of these files is published in the
JavaScript asset**. The database, the Firebase service account and the camera passwords live on
servers, in the places `docs/deployment.md` says.

- `VITE_API_URL` (full base, including `/api/v1`) **or** `VITE_API_BASE_URL` (origin alone; the app
  appends the prefix). There is **no default host.** With neither set, a build boots into "No server
  configured" and cannot sign anybody in — which is the honest state for a backend that has not been
  deployed, and is what stopped a guessed IP address being shipped. `src/config/apiUrl.ts` also marks
  a loopback, private-LAN or plain-HTTP endpoint as unsafe, and a release build so marked refuses to
  send a password.
- `VITE_APP_ENV` — `development` permits the fixture transport; anything else refuses it.
- `VITE_USE_FIXTURES` — local UI work without a backend. Never in a shipped build.
- `VITE_ALERT_POLL_SECONDS` — how often an open screen re-reads the alert queue (default 20, 0
  turns it off). This is the only delivery on a build with no Firebase project, and it stops when
  the app is hidden — see §10.7 of `docs/mobile-api-contract.md`.
- `VITE_LIVE_FEED` — set to `0` to close the live channel (see *Live updates* below). The poll
  stays on either way; this switch only removes the two-second latency win.
- `VITE_FIREBASE_*` — public web client config, web push only. Not required for Android push,
  and not a credential.

## Screens

| Route | Screen | Talks to |
| --- | --- | --- |
| `/login` | `LoginScreen` | `POST /auth/login` |
| `/password` | `PasswordScreen` | `POST /auth/password` — also the forced-change gate when `must_change_password` is set |
| `/dashboard` | `DashboardScreen` | `GET /dashboard/summary`, `GET /incidents` (active) |
| `/incidents` | `IncidentHistoryScreen` | `GET /incidents` with filters and cursor |
| `/incidents/:id` | `IncidentDetailScreen` | detail, activity, response actions, evidence |
| `/incidents/:id/notes` | `InvestigationNotesScreen` | `GET /incidents/:id`, `GET /incidents/:id/activity`, `POST /incidents/:id/note` |
| `/notifications` | `NotificationsScreen` | `GET /notifications`, read/open marks |
| `/profile` | `ProfileScreen` | `GET /profile` — identity and navigation only |
| `/profile/account` | `AccountInfoScreen` | `GET /profile` — contact, roles, camera scope, effective permissions |
| `/profile/devices` | `DeviceStatusScreen` | `GET`/`PATCH /devices`, plus this session's push and live state |
| `/profile/about` | `AboutScreen` | `GET /healthz` (service root, outside `/api/v1`, unauthenticated) |
| `/settings/notifications` | `NotificationSettingsScreen` | `GET`/`PUT /profile/preferences` |

The launch screen in the mockup is the boot gate in `App.tsx`, not a route: it shows while the
stored session is being restored and then hands over to `/login` or `/dashboard`.

## Visual design and what it is allowed to claim

The layout follows the supplied 10-panel mockup (splash, login, dashboard, notification centre,
incident detail, acknowledgement, investigation notes, history, profile, preferences, device
status). Every tile on those screens is bound to a field the API actually returns, and a mockup
element with no backing is **left out rather than faked**:

- no "Database Connected" badge — the About screen reads `GET /healthz` and reports what the
  service said, including "degraded" and "not probed" under fixtures;
- no "FCM Connected" — the Device status screen derives its wording from the real permission and
  registration state and says so plainly when no Firebase project is in the build;
- no evidence upload — evidence is captured at the station and opened through a short-lived link,
  so the mockup's "Attach Evidence" is a link to the captured assets;
- no digest mode, no per-channel (e-mail/SMS) switches, no "system update" alerts, no working
  password-reset mail — the preferences screen exposes only `min_severity`, `kinds`, `quiet_hours`
  and `sound`, which is all `PUT /profile/preferences` accepts.

`public/brand/afit-emblem.png` is AFIT's own emblem, supplied 2026-11-03. The night-campus backdrop
beside it is still an AI-generated placeholder named `*.generated`. Both are served from `public/`,
and every derived icon — the favicon, the Android launcher set at five densities, the adaptive-icon
foregrounds and the native splash screens — is rebuilt from the emblem by
`python scripts/make_brand_assets.py` at the repository root rather than hand-saved. See
`public/brand/README.md`.

Incident responses are acknowledge / under investigation / note / escalate / resolve. There is
no assign-a-person control: the console owns assignment, and an acknowledgement from a handset
only records who picked it up when nobody was assigned.

Response actions are **candidate** reports from a human review queue. Nothing in the UI presents
an AI detection as a confirmed finding.

## State, session, permissions

`SessionProvider` owns the token pair. `api/client.ts` attaches the bearer token, times out,
and on a 401 runs a **single-flight refresh**: concurrent requests queue behind one refresh
rather than each spending the rotation token, because presenting a rotated token twice is how
a legitimate session gets revoked as theft.

`auth/permissions.ts` mirrors the server's role and permission checks so the app can hide
actions a person cannot perform. It is a convenience, never an authorisation decision — the
server answers `forbidden` regardless of what the client rendered.

Tokens are kept in the Capacitor secure-storage plugin on a handset and in `sessionStorage`
on web, with the web path documented as weaker rather than pretended to be equivalent.

## Push

`push/pushRuntime.ts` is the only place that touches notifications:

1. request permission (`POST_NOTIFICATIONS` on Android 13+);
2. create the five channels — `watchtower-critical` (manifest default), `watchtower-high`,
   `watchtower-warning`, `watchtower-informational`, `watchtower-camera-health`;
3. register the device with the API, sending the FCM token once, over TLS, to the cloud that
   seals it;
4. route an incoming tap to the incident.

Channel ids are the contract with the server: `cloud/push.py` names a channel from this list,
and `tests/test_cloud_delivery.py` reads this file to keep the two in step. Android discards a
notification naming a channel that does not exist, so a mismatch is a silent outage, not a
cosmetic difference. **Change a channel id here and expect that Python test to fail.**

A channel's tone and importance belong to the handset once it exists — neither this app nor the
server can rewrite them per message. That is why the profile's `sound` preference is honoured
as silent-versus-not and the actual tone is a phone setting.

## Live updates

One authenticated Server-Sent-Events connection per signed-in session
(`api/stream.ts` → `GET <api>/events/stream`, contract §10.8), started by `SessionProvider` and
never by a screen. Two feeds would mean two copies of one alert and a badge count that drifts.

What arrives is turned into exactly three things:

- a `notification` frame becomes an in-app banner, an unread bump and a quiet re-read of the queue.
  The banner id is derived from the notification id, so the same row delivered by both the stream
  and the poll is one banner, not two.
- an `incident_activity` frame bumps a revision counter. The incident list and the open incident
  re-read on it, which is how "another officer acknowledged this" reaches a screen that did not
  write it. Nothing is invented locally from the frame — the row is re-fetched, because the server
  is the only thing that knows the caller's grants.
- a `heartbeat` frame is not forwarded to any screen. It resets the reader's idle watchdog, and
  that is its whole job: three missing heartbeats close a connection that has stopped producing
  but has not been noticed by anybody.

The shell states the channel's state in one line — a quiet `Live`, or the reason it is not
(§10.7's poll then carries the load, up to `VITE_ALERT_POLL_SECONDS` behind). That line is not
decoration: an officer who has learned that a banner means trouble must be able to tell "nothing
happened" from "nothing reached me yet".

Two rules the reader keeps, and why:

- The credential is a header, never a query parameter. `EventSource` cannot set headers and the
  query-string alternative writes a bearer token into every proxy and hosting access log between
  the phone and the service, so this is `fetch` with a `ReadableStream` and a few lines of parsing.
- It does not refresh tokens. `api/client.ts` is the single place a refresh-token family rotates;
  a second refresher would rotate it twice and trip the server's reuse detection. So a `401` ends
  the feed, and the fresh pair the client installs is the signal that reopens it.

Reconnect is 1s, 2s, 5s, 10s, 30s and holds there; a successful `ready` resets the ladder, a stream
the *service* closed on schedule (`lifetime`) reconnects at once, and an answer that will not change
(`stream_disabled`, `404`, `405`) stops asking for good. Resumption uses the cursor from the last
frame's `id:` line, so a reconnect delivers what happened during the gap once each, not everything
from the beginning of the table.

## Deep links

Two forms are handled by `push/deeplink.ts`, and the app treats both as untrusted input:

- `watchtower://incidents/<id>` — the custom scheme, fixed and not environment-configurable,
  because the server puts this exact string into push payloads.
- `https://<api-host>/incidents/<id>` — Android App Links, verified through
  `/.well-known/assetlinks.json`. The host in `android/app/src/main/AndroidManifest.xml` is
  still the placeholder `watchtower-api.example.invalid`; replace it and publish the file
  before expecting an HTTPS link to open the app instead of a browser.

A link yields an incident **id** and nothing else. The screen then fetches that incident from
the API under the officer's own scope, so a crafted or stale payload can point at an id but
cannot describe an incident. Anything that is not a parseable incident reference is ignored —
a bare click action never becomes a destination.

## Native project

`android/` is generated by Capacitor; edit `capacitor.config.ts` and `src/` instead, except for
`AndroidManifest.xml`, `app/build.gradle`, `google-services.json` and signing. The launcher and
splash images under `app/src/main/res/` are a third exception, and they are not hand-edited either:
`python scripts/make_brand_assets.py` rewrites them from `public/brand/afit-emblem.png`. Build
requirements and their sources are in `docs/android-build.md` §1. `app/build.gradle` applies
the google-services plugin only when `google-services.json` exists, so a missing file is not a
build failure — it is a build that cannot receive push.

## Tests

125 cases in twelve files (`npm run test:run`): the API client and its refresh queue, the error
code map, the endpoint resolver and its four states (ready, unconfigured, plain-HTTP, local — and
which of them may send a password), the permission mirror, the fixture transport's validation, the
severity/channel/sound vocabulary, the alert-kind vocabulary and its absent-means-enabled rule, the
deep-link parser, the live-feed reader and the two list hooks — including the foreground polling
that is the only alert delivery on a build without a Firebase project. They run against fakes
in-process; none of them contacts a server, and none of them proves a phone behaved.

No test renders a screen, so restyling cannot break the suite — and equally, the suite says
nothing about whether a screen looks right. Layout is checked in a browser.

## Walking the UI without a backend

`.env.development` turns fixtures on, so on a fresh clone this is all it takes:

```
npm run dev
```

Sign in as `a.ahiya` / `watchtower`. A machine that has the cloud API running locally overrides it —
this repository's `.env.development.local` sets `VITE_USE_FIXTURES=0` and points
`VITE_API_BASE_URL` at `http://127.0.0.1:8080`. Fixture data is scripted in `src/devfixtures/data.ts`
and is reachable only in a dev build (`import.meta.env.DEV`); every screen carries the
"FIXTURE DATA — not live" banner, and `verify:fixtures` fails a production bundle that contains
the transport.
