# AFIT WATCH TOWER

AI-assisted security camera monitoring and incident management, implemented from the
project proposal *From Passive Surveillance to Intelligent Security Awareness*.

This repository is the **controlled prototype** described in the proposal's Phase 1-5
scope, plus the personnel-mobile extension requested afterwards. It is not a deployed
surveillance system and it has not been approved for operational use at AFIT.

## Status at a glance

| Area | State |
|---|---|
| PostgreSQL schema and migrations (section 8) | implemented; 29 tables in three linear revisions, applied to the project Neon database at `0003_personnel_columns` |
| Camera registration, Method A + Method B (section 6.1-6.3) | implemented, including credential extraction and secure sealing |
| Connection testing with the eight documented results (section 6.5) | implemented; reachability and RTSP handshake tested, frame decode needs a real camera |
| Supervised multi-camera ingestion (section 7) | implemented; worker processes, backoff, restart ceiling, capacity limits verified against an unreachable host |
| Browser live view (section 9) | implemented as an authenticated JPEG relay sharing one managed stream; WebRTC/HLS gateway documented but not installed |
| Camera health monitoring (section 10) | implemented with all nine states and change-only event recording |
| AI video analysis (section 11) | partially implemented - see `docs/detection-limitations.md`; classical-CV detectors only, no trained model |
| Incident and evidence management (section 12) | implemented, including SHA-256 integrity and retention |
| RBAC, five roles, group scoping, audit (sections 14, 16) | implemented |
| Notifications (section 15) | dashboard and webhook delivery implemented; email/SMS have no sender and are recorded as unconfigured, not faked |
| Dashboard UI (section 13) | implemented as a no-build vanilla frontend |
| Personnel-mobile API (`watchtower.cloud`) | implemented: auth, devices, incidents, evidence, profile, signed ingest, targeting, FCM payload, escalation |
| Local-to-cloud forwarding | implemented as a PostgreSQL transactional outbox with a JSONL last-resort spool. No Redis |
| Android / web app (`personnel-app/`) | implemented: 8 screens wired to real endpoints, push runtime, deep links, 70 unit tests. **Never built on a handset** |
| Push delivery | **not operational** - no Firebase project exists. Alerts are recorded as failed with `error_code=not_configured` |
| Real-camera verification (section 6.4) | **not done - requires the camera and AFIT authorization** |
| Capacity and pilot evaluation (sections 19-21) | **not done - requires the pilot** |

Verification state: `python -m pytest -q` and `python -m ruff check src tests migrations
scripts` green; `npm run verify` (typecheck, build, bundle fixture-scan, unit tests) green in
`personnel-app/`. Neither proves a phone received a notification - see
`docs/testing.md` for the acceptance matrix and what each blocked item is waiting on.

## What the system guarantees

Four rules are enforced in code rather than left to convention:

1. **A camera is never `Online` because a form was submitted.** Registration creates a
   pending record and runs a real connection test. Activation starts a managed session and
   the status becomes `testing`; only confirmed frame delivery makes it `online`
   (`src/watchtower/services/cameras.py`, `src/watchtower/health/evaluator.py`).
2. **Camera credentials never leave the backend.** The password is sealed with a key from a
   separate ring and referenced by id; responses, audit rows, logs and error text are run
   through `redact()` (`src/watchtower/security/secrets.py`).
3. **AI detections are candidate events, never conclusions.** They require human review,
   are deduplicated, and are stored separately from camera-health events
   (`src/watchtower/services/incidents.py`).
4. **The phone cannot reach anything it should not.** The app holds no database credential,
   no Firebase server credential, no storage secret and no RTSP address; evidence is fetched
   through a short-lived, single-purpose retrieval rather than a permanent public link; and
   the monitoring host only ever makes outbound calls to the cloud API
   (`docs/system-architecture.md` §1, `personnel-app/.env.example`).

## Quick start: the monitoring host

Requirements: Python 3.11+ (developed on 3.14), PostgreSQL 14+, `pip install -r requirements.txt`.

```bash
cd watchtower
cp .env.example .env          # edit the two PASTE values before continuing
python -m pip install -r requirements.txt

# The project is a src/ layout and is not packaged, so the CLI is only importable when src/
# is on the path. On Windows the same line is `set PYTHONPATH=src`, in the same window.
export PYTHONPATH=src

# Nothing in this project reads `.env` by itself - there is no dotenv dependency. `--env-file`
# is a global flag, so it goes before the subcommand, and without it a command that needs the
# database exits 2 with `WATCHTOWER_DATABASE_URL is required` even though the value is in the file.
python -m watchtower.cli --env-file .env secret-key          # key ring; refuses to invent one in production
python -m watchtower.cli --env-file .env migrate             # once, against PostgreSQL
python -m watchtower.cli --env-file .env check-schema        # compares the revision to the scripts' head
python -m watchtower.cli --env-file .env bootstrap           # roles, permissions, first administrator
python -m watchtower.cli --env-file .env serve --host 127.0.0.1 --port 8040   # development only
```

`bootstrap` asks for the administrator password with a prompt that does not echo; the characters
are typed, not shown. On a fresh local PostgreSQL cluster the database itself is created first
(`createdb watchtower`); with a managed provider such as Neon it already exists. For real use put
nginx or Caddy with TLS in front of the serve command.

Open `http://127.0.0.1:8040/dashboard`, sign in, then **Camera Management > Add Camera**.

`.env.example` is a template with placeholders; `.env` is the real thing and is gitignored.
Do not put live values into the template - if a value has ever been real, rotate it.

### No PostgreSQL on this machine yet

`scripts/dev_serve.py` starts the same application against a SQLite file under `var/dev/`
so the console, the registration workflow and a real RTSP connection test can be walked
locally. It is a demo process, not a deployment: it does not use the Alembic migrations,
it runs without HTTPS behind loopback only, and `load_settings()` still refuses a
non-PostgreSQL URL, so nothing here becomes a supported configuration by accident.

```bash
cd watchtower
python scripts/dev_serve.py --port 8040      # prints a one-time administrator password
```

No `PYTHONPATH` is needed for this one - the script puts `src/` on the path itself. Nothing
about registration changes in demo mode: the probe opens a real socket, a camera only
reaches `online` after frames are confirmed (section 6.6), and a failed test writes no
registry row.

For the first camera, verify the stream in VLC exactly as described in
`docs/camera-preparation-runbook.md`, then paste the working address as registration
Method A. The registration form rejects anything that is not RTSP, has no stream path, or
has an out-of-range port, and it will show the specific failure reason rather than a
generic error.

## Quick start: the cloud API and the app

Two separate deliverables, one shared database. The cloud half installs `requirements-cloud.txt`
- its own import graph, without the camera stack in it; `requirements.txt` stays on the monitoring
host.

```bash
cd watchtower
export PYTHONPATH=src
python -m watchtower.cli --env-file .env migrate         # once, against the shared PostgreSQL
python -m watchtower.cloud --env-file .env verify    # what is configured, what is missing
python -m watchtower.cloud --env-file .env service-key   # one id/secret pair for the monitoring host
python -m watchtower.cloud --env-file .env serve --host 127.0.0.1 --port 8080
```

One process is enough on this machine: `serve` runs delivery and escalation in-process. A hosted
deployment splits the same work into three units - `serve --no-worker`, `worker --jobs delivery`
and `worker --jobs escalation` - and binds whatever port the platform publishes as `PORT`;
`docs/deployment.md` §5 and `render.yaml` cover that.

Give the printed pair to the monitoring host as `WATCHTOWER_CLOUD_API_URL`,
`WATCHTOWER_CLOUD_KEY_ID` and `WATCHTOWER_CLOUD_KEY_SECRET`; the cloud side needs the same
pair inside `CLOUD_SERVICE_KEYS_JSON`. `verify` ends with `Ready to serve.` while push is
unconfigured - Firebase is an optional capability, and an unconfigured one is reported, not
simulated.

```bash
cd personnel-app
npm install
npm run verify        # typecheck + build + endpoint + fixture scan + 125 unit tests
npm run dev           # responsive web build on loopback
```

Android needs JDK 21 and an SDK with platform 36; `docs/android-build.md` states where each
requirement comes from and what has not been built.

## Layout

```
src/watchtower/
  config.py db.py models.py        settings, engine, the 19 monitoring tables
  security/                        sealed credentials, passwords, RBAC, audit
  rtsp/                            connection-string parsing, section 6.5 testing
  ingest/                          supervised worker processes, stream registry
  health/                          nine-state evaluation, change-only events
  analysis/                        frame sampling and detectors
  services/                        registration workflow, incidents, evidence,
                                   notifications, supervision loop
  api/                             FastAPI app, routers, dashboard templates
  cli/                             migrate, bootstrap, serve, purge, secret-key
  mobile/                          the ten personnel-mobile tables, transactional outbox,
                                   signed forwarder, alert hook, drain thread
  cloud/                           personnel API, targeting, FCM delivery, ingest, worker
migrations/                        Alembic, PostgreSQL-only by design
scripts/dev_serve.py             local demo process (SQLite; not a deployment)
personnel-app/                   React + TypeScript + Vite + Tailwind + Capacitor
  src/screens/                   login, incidents, detail, evidence, profile, settings
  src/push/                      channel creation, registration, deep-link parsing
  android/                       generated native project (minSdk 24, targetSdk 36)
docs/                              runbook, installation, gateway, testing, mobile, android
tests/                             pytest suite (backend, cloud, mobile)
```

## Documentation

Monitoring side:

- `docs/camera-preparation-runbook.md` - RTSP enablement and VLC verification (section 6.4)
- `docs/installation.md` - monitoring-host deployment, TLS, network isolation, backups
- `docs/media-gateway.md` - WebRTC/HLS evaluation and the MediaMTX path
- `docs/detection-limitations.md` - what the detectors can and cannot claim
- `docs/pilot-evaluation.md` - metrics to measure before any expansion (section 21)

Personnel-mobile side:

- `docs/system-architecture.md` - how the two halves, one database and the phone fit together
- `docs/database-schema.md` - all 29 tables, column by column, and what is applied where
- `docs/mobile-api-contract.md` - every endpoint, error code, payload and targeting rule
- `docs/deployment.md` - cloud host, Neon, Render and hosted platforms, TLS, rotation
- `docs/firebase-setup.md` - the two Firebase artefacts and the package-id match
- `docs/android-build.md` - toolchain, build commands, deep links, what is unproven
- `docs/troubleshooting.md` - symptom-first, using the strings the code actually writes
- `docs/testing.md` - the proposal's section 18 plan and the ten mobile acceptance tests

## Boundaries of this prototype

- No camera model other than the one tested through VLC is assumed compatible. The
  `ceshi.ini` procedure is documented as camera-specific, not general.
- RTSP does not encrypt video or credentials in transit. The deployment must use network
  isolation; camera streams must not be reachable from the public internet.
- Detection quality has not been measured in the AFIT environment, so no precision or
  false-positive claim is made anywhere in this codebase.
- Nothing has been deployed, no handset has run this app, and no push has ever been sent to
  Google from here. A feature blocked on credentials is described as blocked.
- Broad deployment, changes to operational cameras and any pilot require AFIT approval.
