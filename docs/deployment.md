# Deployment

`docs/installation.md` covers the **monitoring host** - the machine by the cameras. This file
covers the rest: where the cloud API runs, how the two halves are wired together, how the
Android app gets onto handsets, and what a hosted platform such as Render does and does not
give you.

Nothing here has been deployed. There is no cloud host provisioned for this project, no
handset running the built app, and no production traffic this code has ever carried. Every
command below is written from the code in this repository, but the first real deployment
will be the first time they are executed together.

## 1. Three units, one database

| Unit | Runs | Must be reachable from |
| --- | --- | --- |
| **Monitoring host** (AFIT site) | dashboard + API, stream workers, supervision loop, outbox forwarder | operators on the site network; the cameras' RTSP ports |
| **Cloud host** | `watchtower.cloud serve` (personnel API) and its delivery/escalation worker | the phones, over HTTPS; the monitoring host |
| **PostgreSQL** | one database shared by both halves | both hosts, encrypted |

The monitoring host makes **outbound** connections only. Nothing at AFIT is port-forwarded,
and the camera VLAN is never routable from the internet. The phone talks to the cloud host
and never to the monitoring PC or a camera - that is the whole reason the evidence bytes are
relayed rather than linked (`docs/system-architecture.md` §3).

Two consequences for hosting choices:

- The cloud host and the database are on the critical path for **delivery**. If either is
  down, the console still works, alerts keep queueing locally, and nothing is lost - but no
  phone rings.
- The monitoring host and the cameras must survive losing the cloud host without losing
  recording or health history. Local behaviour is the same whether or not forwarding is
  configured, by design.

## 2. Cloud host

Python 3.11 or newer, `requirements-cloud.txt`, plus the `watchtower.cloud` module. That file is
the cloud service's own import graph rather than a copy of `requirements.txt`: `cv2` and `numpy`
are unreachable from `watchtower.cloud`, and were proven so by importing the app, CLI, worker,
delivery and dependency wiring in a process where both names raise `ImportError` on sight. A
hosted API that serves JSON has no business installing a video-decoding stack; the install is
hundreds of megabytes and the first deploy is the wrong day to find out that the platform timed
out. The monitoring host still installs `requirements.txt` - do not put this file there.

One line in that list is not in the import graph and must not be dropped: `argon2-cffi`. Personnel
password hashes were written by the monitoring host as Argon2id, and `verify_password` returns
False for such a hash when the library is missing (`security/passwords.py:65-68`) - a service with
that dependency absent boots cleanly, answers `/healthz` with `database: ok`, and rejects every
real login as `invalid_credentials`. Proven on 2026-11-03 in a throwaway virtual environment built
from the list alone, and re-proven as fixed after the line was added.

Every test in this repository has been run on CPython 3.14, which is the version to ask for if
the platform offers it; the code is written to the 3.11 baseline `ruff.toml` targets, and
`render.yaml` pins 3.12. That combination has not been executed - a 3.12 build is unverified here,
and the first deploy should read the build log rather than assume.

One database serves both halves, so the DSN is the same value; `CLOUD_DATABASE_URL` is read first
and falls back to `WATCHTOWER_DATABASE_URL`. From the repository root on the cloud host:

```bat
set WATCHTOWER_DATABASE_URL=postgresql://...?sslmode=require&channel_binding=require
```

(On Linux, `export`. Quoting a DSN with `&` in a Windows shell is a trap - set it in the
process environment or a service unit file rather than a bare `set` on a line that the shell
will split at the ampersand.)

Then the `CLOUD_*` set, all of which `python -m watchtower.cloud verify` will report on:

| Variable | What it decides |
| --- | --- |
| `CLOUD_DATABASE_URL` | the shared PostgreSQL DSN; same Postgres-only refusal as the app |
| `CLOUD_JWT_SECRET` | signs access tokens. 32 characters minimum, boot refused below it |
| `CLOUD_ENVIRONMENT` | anything other than `production` allows loopback HTTP **and** serves `/docs` + `/openapi.json` |
| `CLOUD_REQUIRE_HTTPS` | default `1` outside development; a phone on mobile data is the whole audience |
| `CLOUD_PUBLIC_BASE_URL` | the origin the app is told to use, and the host deep links are built against |
| `CLOUD_ALLOWED_ORIGINS` | CORS. Includes the packaged Android app's own origin, `https://localhost` - empty is not "native-only", it is a broken app (§5.3) |
| `CLOUD_SECRET_KEY_PATH` | the ring that seals FCM tokens - separate from the monitoring ring |
| `CLOUD_EVIDENCE_DIR` | where relayed evidence bytes land; paths are confined to it |
| `CLOUD_SERVICE_KEYS_JSON` | the monitoring host's id/secret pairs accepted for ingest |
| `CLOUD_ESCALATE_AFTER_SECONDS` | how long a critical unacknowledged incident waits before a wider re-page |
| `CLOUD_FORCED_ALERTS` | severities/kinds that ignore a recipient's quieting preference |
| `CLOUD_FIREBASE_PROJECT_ID` + `CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE` | push. Both or neither |

The listening socket is configured by the command, not the environment: `serve --host` (default
`127.0.0.1`) and `serve --port`, which falls back to the platform's `PORT` and then to 8080.

Order of operations:

```bat
python -m watchtower.cli --env-file .env migrate
python -m watchtower.cli --env-file .env check-schema
python -m watchtower.cloud --env-file .env verify
python -m watchtower.cloud --env-file .env service-key
python -m watchtower.cloud --env-file .env serve --host 127.0.0.1 --port 8080 --trusted-proxy 127.0.0.1
```

`--env-file` is what hands the command the values in `.env` - no module in this project reads
that file on its own, because there is no dotenv dependency. Omit it and a command that needs
the database exits 2 with `WATCHTOWER_DATABASE_URL is required` even when the line is present
in the file. On a host that exports real environment variables (systemd `EnvironmentFile`,
Render's env panel) the flag is not needed and should not be used; `.env` stays a local file.

Three things about this file and its loader have each cost real time, and all three are worth
knowing before debugging a "configuration error" that the file plainly does not contain:

- **A repeated key is not merged; the first one wins.** The loader is `setdefault`, so the second
  `CLOUD_SERVICE_KEYS_JSON=` in a file is the one nobody sees. This happened on this machine: an
  invalid 30-character secret under `afit-control-room-01` sat above the working `host-1` pair, and
  `serve`, `worker` and `verify` all refused to start with an error naming a key id that the bottom
  of the file said was not being used. The stale line is now commented out, with the reason. If a
  second monitoring machine is real, it gets a fresh `service-key` and **both** ids go inside the
  one JSON object - not two lines.
- **A value already in the process environment shadows the file** - which is also why a variable
  cannot be *blanked* from a Windows shell. `set CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE=` in cmd
  **deletes** the variable, so `setdefault` then reads the value out of `.env` and the command fails
  with `points at '/app/secrets/...', which does not exist`. The 2026-11-03 attempt to run the cloud
  API locally with a shell-shaped override failed for exactly that reason.
- Because of both of the above, **`.env` on this machine is the local run shape**
  (`CLOUD_ENVIRONMENT=development`, loopback origin, `var\cloud.key`, `var\cloud-evidence`, and the
  two `CLOUD_FIREBASE_*` lines commented out). It needs no overrides: `python -m watchtower.cloud
  --env-file .env verify` ends `Ready to serve.` with `[!!] push delivery: not configured`, which is
  the honest state of a machine with no Firebase key file - the schema is at
  `0003_personnel_columns`, all personnel tables are present and the one ingest key is read.
  The hosted shape is not a file on this PC; it is the `watchtower-cloud` env group in the
  platform's dashboard, where `CLOUD_ENVIRONMENT=production`, the real `CLOUD_PUBLIC_BASE_URL`, the
  ring and service-account under `/etc/secrets/` and evidence on a disk under `/var/lib/watchtower/`
  belong - §5.3 explains why each is where it is.
  Commenting the Firebase pair is how this file turns push off; `.env.example` ships it as two
  empty values, which also means off, because an empty string assigned by the loader stays empty.
  What does **not** work is blanking it from the shell - see the bullet above. Either way the config
  layer refuses a half-configured push, which is the guard working, not an obstacle.

`migrate` before `check-schema`, and `check-schema` is now the gate that catches a database
behind the code: it compares `alembic_version` to the scripts' head and exits non-zero
instead of printing a revision and calling it fine. A schema one revision behind boots,
answers health checks, and then fails on the first login that touches a missing column -
the worst possible time to discover it.

`service-key` prints one id/secret pair. Put the **id and secret on the monitoring host**
and the same pair inside `CLOUD_SERVICE_KEYS_JSON` on the cloud host. Two forms of the
configuration exist (`CLOUD_SERVICE_KEYS_JSON` and the single `CLOUD_INGEST_KEY_ID` /
`CLOUD_INGEST_KEY_SECRET` pair); they may coexist but one id cannot carry two different
secrets, and `verify` says so.

`serve` runs delivery and escalation in-process by default. Use `--no-worker` and run `python -m
watchtower.cloud worker` as its own process whenever more than one API instance might exist: two
API processes each starting their own worker means two dispatch loops, which the
`FOR UPDATE SKIP LOCKED` claim and the unique dedupe keys survive - but a separately scaled worker
is the arrangement you can reason about at 3 a.m. `worker --jobs delivery` and
`worker --jobs escalation` split the two loops apart when you want a faulty push sender restarted
without stopping the sweep; `--jobs both`, the default, is one process doing what it always did.

`--access-log` is off by default on purpose: a request line can contain a bearer token if
anything ever puts one in a query string.

## 3. TLS and the reverse proxy

The app is HTTPS-only in any non-development setting, and the contract says so. Put a TLS
terminating proxy in front and start the API on loopback, telling it which proxy address to
believe `X-Forwarded-*` from via `--trusted-proxy`. Believing those headers from anybody is
what turns a rate limiter and an audit trail's `source_ip` into fiction, which is why the
default is one address and not a wildcard.

`CLOUD_PUBLIC_BASE_URL` must equal the origin the proxy serves. Deep links and the
`watchtower://` payload the push sender builds are derived from it; a mismatch produces
notifications that open the wrong host, and App Links verification that never succeeds
(`docs/android-build.md` §5).

One decision to make deliberately: an interactive API listing is served at `/docs` whenever
`CLOUD_ENVIRONMENT` is not `production` (`cloud/app.py:177`). On a host with a public DNS
name that means the whole personnel API surface is documented for anybody who guesses the
URL. It is not an authentication bypass - every endpoint still requires a token - but it is
free reconnaissance. Either set the environment to a non-development value or construct the
app with `docs_enabled=False`; do not leave it on the default and discover it later.

## 4. Neon

The project's database is Neon and already holds the schema at `0003_personnel_columns`
(applied 2026-11-02, after which the mobile API's user queries work; before that they would
have failed). Keep the rules that host enforces:

- the long `postgresql://` prefix - the short `postgres://` form is refused;
- `?sslmode=require`, and `channel_binding=require` where the endpoint offers it;
- percent-encode any `@`, `#`, `/` or `%` in the password;
- the **pooler** endpoint for application traffic. Migrations want the direct endpoint if
  the pooler's mode would break DDL.

Both halves connect to the same database with different credentials. Give the cloud host
its own role: it needs DML and no DDL after the migration, and a leaked app credential
should not be able to alter the schema.

Latency is the thing to watch: the cloud worker polls (`CLOUD_POLL_SECONDS`, default 5) and
every dispatch is a round trip. On a distant region that is fine for tens of handsets; it is
not fine for hundreds, and the honest way to find out is to measure before a pilot rather
than after.

## 5. Render, and hosted platforms generally

Asked directly: yes, the cloud API can run on Render, and `render.yaml` at the repository root
describes how. It is a description, not a deployment - no service in this file has ever started,
and nothing here may be published without AFIT's approval (§9). Read §5.2 and §5.4 before the first
deploy; they are the two decisions a platform cannot make for you.

### 5.1 The three start commands

The brief asks for a Cloud API, a Notification worker and an Escalation worker as separate units,
and the CLI supports exactly that:

| Unit | Command | Binds a socket | Reads |
| --- | --- | --- | --- |
| Cloud API | `python -m watchtower.cloud serve --no-worker --host 0.0.0.0` | the platform's `PORT` | everything below |
| Notification worker | `python -m watchtower.cloud worker --jobs delivery` | no | queue, FCM, the key ring |
| Escalation worker | `python -m watchtower.cloud worker --jobs escalation` | no | incidents, roles, the queue |

- `serve` takes its port from `PORT` when `--port` is absent, so the same command works on a
  platform that assigns 10000 and on a workstation that assigns 8080. A `PORT` that is not a
  number, or is outside 1-65535, stops the service at startup rather than binding something the
  proxy is not looking at. `--port` still wins when given.
- `--host` keeps its loopback default. `0.0.0.0` appears only in the hosted command, because a
  default of every-interface would turn every local run into a service the whole network can reach.
- `--jobs` defaults to `both`, which is what `serve` runs in-process and what a single host wants.
  Splitting them is what lets a faulty push sender be restarted without stopping the sweep that
  decides who gets paged next. An escalation-only worker queues re-pages that stay `pending` until
  a delivery worker exists - that is the point of the split, not a fault, but it does mean the
  delivery unit is not optional in production.
- `--no-worker` on the API is not a performance setting. Every API instance starting its own
  worker multiplies dispatch loops; the `FOR UPDATE SKIP LOCKED` claim and the unique dedupe keys
  survive it, but the retry counts stop meaning anything.

The three units share one environment group (`watchtower-cloud` in the blueprint). They must: they
read the same database, and delivery and escalation both open the ring that seals stored FCM
tokens.

### 5.2 Migrations run from the monitoring host, not the cloud host

`migrations/env.py` builds its engine through the **monitoring application's** `load_settings()`,
which reads `WATCHTOWER_DATABASE_URL` and `WATCHTOWER_JWT_SECRET`. So:

```bat
cd C:\path\to\watchtower
python -m watchtower.cli --env-file .env migrate
python -m watchtower.cli --env-file .env check-schema
```

Run those on the machine that already holds the monitoring configuration, against the same Neon
database the cloud service will use, before you deploy. The alternative - putting `WATCHTOWER_*`
into the cloud environment so a Render `preDeployCommand` can migrate - means copying the control
room's signing secret onto a public hosting platform to save yourself one command. Do not do it.

`check-schema` is the gate: it compares `alembic_version` to the scripts' head and exits non-zero
if they differ. A schema one revision behind boots, answers `/healthz`, and fails on the first
login that touches the missing column.

There is no schema change in this repository's current state to apply: the personnel tables are at
`0003_personnel_columns` and Neon already carries them (§4). If a later revision lands, deploy the
code that matches it *after* migrating, not before.

### 5.3 Ephemeral disk: three things must not disappear on redeploy

Relayed evidence written to `CLOUD_EVIDENCE_DIR` vanishes when the instance restarts. So does the
key ring at `CLOUD_SECRET_KEY_PATH` - and that one is worse than lost data: the ring seals every
stored FCM token, and in production the service **refuses to mint a new ring** rather than strand
those tokens silently (`security/secrets.py:56`). A redeploy onto a fresh filesystem therefore
either fails at startup, or, if someone "fixes" it by running non-production, decrypts nothing and
records every push as a token failure. The Firebase service-account JSON has to survive too.

Render's own filesystem rules decide this layout, and each of the three was read off Render's
documentation on 2026-11-03 rather than assumed:

- **Secret files mount at `/etc/secrets/<filename>` and nowhere else.** The path is not a free
  choice, so the ring is `CLOUD_SECRET_KEY_PATH=/etc/secrets/cloud.key` and the service account is
  `CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE=/etc/secrets/firebase-service-account.json`. Both are created
  in the dashboard (Environment → Secret Files); a blueprint cannot declare them at all.
- **A persistent disk belongs to exactly one service and cannot be shared.** Which is why the ring is
  *not* on a disk: three services with three disks would hold three different rings, and a token
  sealed by the API cannot be unsealed by the push worker's copy - every push would fail, on a
  service that deployed cleanly and passed its health check. Reading the mounted file is all the
  cloud ever does; writing a ring happens in `create_if_missing` (development) and in `rotate()`
  (`security/secrets.py:83`), which only `watchtower.cli rotate-keys` calls, and that runs on the
  monitoring host.
- **A service with a disk cannot run more than one instance**, so `numInstances: 1` on the API is a
  requirement of this layout, not conservatism.

The disk therefore holds exactly one thing - relayed evidence - mounted at `/var/lib/watchtower` on
the API. Both workers override `CLOUD_EVIDENCE_DIR` to `/tmp/watchtower-evidence`, because
`cmd_worker` creates the directory on the way up (`cloud/cli.py:171`) while no worker ever writes an
evidence file, and a value set on the service beats the same key from the attached group.

The ring to upload already exists: `var\cloud.key` on this machine, minted by the local development
run (version 1, one key). Uploading that file unchanged is what keeps every FCM token already stored
in Neon decryptable. Uploading a different ring is the mistake, and it will look like a Firebase
outage rather than a key mismatch.

**The other thing that breaks a clean-looking deploy: CORS.** The packaged Android app is a WebView
making `fetch` calls, and with `androidScheme: 'https'` its own origin is `https://localhost` - a
browser origin, subject to the allow-list. Verified against the running service: `OPTIONS
/api/v1/auth/login` with an unlisted `Origin: https://localhost` returns **400 with no
`access-control-allow-origin`**, and with a listed origin **200**. So an empty
`CLOUD_ALLOWED_ORIGINS` is not a warning to ignore; it is an app that cannot sign anybody in. The
blueprint ships `https://localhost,http://localhost` for exactly that reason, and a hosted web build
gets its real https origin appended, comma-separated.

Until the disk and the two secret files exist, evidence retrieval works for the life of the instance
and no longer - `evidence_relay_states` will show the gap as "still arriving" - and no push can be
sent at all, because there is no service account to sign the request with.

### 5.4 `--trusted-proxy '*'`, and what it costs

`CLOUD_REQUIRE_HTTPS=1` is enforced from the ASGI scheme (`cloud/app.py:105-114`), and behind a
TLS-terminating proxy the scheme is only `https` if the server believes `X-Forwarded-Proto`. On a
control-room box that means `--trusted-proxy 127.0.0.1` beside your own nginx. On Render there is
no local proxy and no published, stable load-balancer address to name, so the blueprint passes
`--trusted-proxy '*'`.

What that buys: phones can talk to the service at all.

What it costs: uvicorn's proxy middleware rewrites the *client address* from `X-Forwarded-For`
when it rewrites the scheme, and the first entry of that list is attacker-controlled.
`cloud/deps.py:159-167` deliberately reads the TCP peer rather than a header for exactly this
reason - the login rate limiter and every audit `source_ip` are keyed on it. With `*`, both become
spoofable on this platform. The scheme decision and the address decision are not separable through
uvicorn's flag.

Two things make that acceptable for a pilot, and one decision is still owed:

1. Turn on the platform's Force HTTPS so the outer hop is TLS regardless of what the application
   believes.
2. The abuse available is a weaker rate-limit key and a writable audit field. It is not
   authentication bypass: tokens still have to be correct.
3. The fix, if AFIT wants the source address to be trustworthy in production, is a small deliberate
   change - read the forwarded proto in `HttpsOnlyMiddleware` under its own trust list instead of
   taking uvicorn's rewrite of `client`. That change has **not** been made. Do not deploy to real
   personnel data until somebody has decided which of the two matters more.

### 5.5 Health check, and the documentation endpoint

- Point the platform's health check at `/healthz`. It answers 200 when the database answers and 503
  when it does not (`cloud/app.py:273-312`). There is no `/readyz` on the cloud API - that name
  belongs to the monitoring console (`api/app.py:174`) - and a check pointed at it gets a
  `404 not_found`, which on a platform that restarts on failed checks looks like a crashing
  service. `CLOUD_REQUIRE_HTTPS` exempts `/healthz` and `/` only, so a probe with no TLS
  termination still gets through.
- **Put `connect_timeout` in the DSN, or "503 when the database is down" is only true after the
  operating system gives up.** Measured on this machine, 2026-11-03: `psycopg.connect()` to a port
  where nothing listens did not return at all inside 60 seconds; the same DSN with
  `&connect_timeout=2` raised `ConnectionTimeout` in 2.00s. `/healthz` runs one `SELECT 1` and has
  no timeout of its own, and neither does `db.build_engine`, so a hung database host means a hung
  probe rather than a fast 503. The platform's own probe timeout eventually masks this, which is
  the worst way to learn it - so add the parameter:
  `?sslmode=require&channel_binding=require&connect_timeout=5`. The loader does not object to extra
  query parameters, and this is a configuration change, not a code change.
- `/docs` and `/openapi.json` are served whenever `CLOUD_ENVIRONMENT` is not `production`
  (`cloud/app.py:177`). The blueprint sets it to `production`; a host that leaves it at the default
  publishes the whole personnel API surface for anybody who guesses the URL. Not an
  authentication bypass - free reconnaissance is.

### 5.6 Order of operations

1. §5.2 - migrate and `check-schema` from the monitoring host, against Neon.
2. §6 - generate the ingest pair (`service-key`), put id + secret in the monitoring host's `.env`,
   and the same pair inside `CLOUD_SERVICE_KEYS_JSON` on the cloud side.
3. `docs/firebase-setup.md` - create the Firebase project, upload the service-account JSON as a
   **Secret File** named `firebase-service-account.json`, and set `CLOUD_FIREBASE_PROJECT_ID` in the
   group. Both or neither.
4. A Git repository Render can read - **this does not exist yet**: the project on this machine is not
   a Git repository at all, so `git init`, commit, push to a *private* GitHub repository. `.gitignore`
   already keeps `.env`, `var/` (the rings and evidence), `personnel-app/node_modules`, `dist` and
   `google-services.json` out of it; check `git status` before the first push and confirm the same.
   `render.yaml` is read from the repository root, next to `requirements-cloud.txt` - the file every
   one of its three `buildCommand` lines installs, and a different file from the monitoring host's
   `requirements.txt`. Nothing deploys from a local folder.
5. Apply the blueprint, then fill the `sync: false` values in the dashboard: the Neon DSN (pooled
   endpoint for the app), `CLOUD_PUBLIC_BASE_URL` (the https origin - the real hostname, never a
   placeholder) and `CLOUD_SERVICE_KEYS_JSON`.
6. §5.3 - upload `var\cloud.key` (the existing ring, unchanged) as a **Secret File**, and check the
   attached evidence disk mounted at `/var/lib/watchtower` on the API. Neither can come from the
   blueprint.
7. One instance of each unit, always-on plan. Do not autoscale, and do not add a second API instance
   while it has a disk.
8. `python -m watchtower.cloud verify` is what the platform's shell does for you on the **API**: it
   reports the database, the schema revision, the ring, the two doors (ingest and push) and the
   origin, and exits non-zero on anything blocking. A background worker has no shell like that, so
   its proof is the log line it prints at startup - `cloud worker started: jobs delivery, push
   enabled` - and a ring or service-account problem shows there as a refusal to start.
9. `docs/android-build.md` §3a - build the app against the origin from step 5, then install.
   A release build with no host configured refuses to sign anybody in, by design.

The same checklist applies to any PaaS. What you cannot substitute is the outbound-only rule for
the AFIT side: no hosted platform can host the camera connections, and none should try.

### 5.7 The free layout: one web service, everything in it

Everything above assumes a paid plan, and not only for politeness. Render's free compute covers
**web services**, Key Value and Postgres - a background worker is paid, a persistent disk is paid,
and the secret files §5.3 relies on are paid. Applying `render.yaml` asks for a subscription too -
reported from the dashboard when this was written, not from the documentation, and either way the
three-service shape cannot be free.
A pilot that costs nothing is therefore a different shape, not a smaller version of the same one:
**one free web service, started without `--no-worker`**, so the API and both jobs run in the one
process the code has always supported for a single host.

Build command `pip install -r requirements-cloud.txt`; start command, all one line:

```
mkdir -p /tmp/watchtower && printf '%s' "$CLOUD_SECRET_KEY_RING_B64" | base64 -d \
  > /tmp/watchtower/cloud.key && chmod 600 /tmp/watchtower/cloud.key && \
  exec python -m watchtower.cloud --log-level INFO serve --host 0.0.0.0 --trusted-proxy '*'
```

The `exec` matters: without it Python is a child of the shell and Render's stop signal kills the
shell and leaves the server. No `--port`, because the platform's `PORT` is what the service binds
(`cloud/cli.py` `_resolve_port`). The environment is §5's list with three changes:

- `CLOUD_SECRET_KEY_PATH=/tmp/watchtower/cloud.key` and `CLOUD_EVIDENCE_DIR=/tmp/watchtower/evidence`
  - `/tmp` because nothing else on the free tier survives, and the parent directory is created above.
- `CLOUD_SECRET_KEY_RING_B64` holds the ring itself, base64 of `var\cloud.key` - the existing file,
  not a new one: `[IO.File]::ReadAllBytes` in PowerShell, paste the single line into the dashboard.
  A secret file would be better and is paid; this is why the bootstrap rewrites the file on every
  boot instead of storing it anywhere.
- `PYTHONPATH=src`, as always, or the start command fails with `No module named 'watchtower'`.

When Firebase arrives, add `CLOUD_FIREBASE_PROJECT_ID`,
`CLOUD_FIREBASE_SERVICE_ACCOUNT_FILE=/tmp/watchtower/firebase-service-account.json` and a second
`printf '%s' "$CLOUD_FIREBASE_JSON_B64" | base64 -d > ...` clause in the same start command. A
service-account JSON is a private key: putting it in the env panel is the weakest part of this
layout, it is why the paid layout exists, and the panel should be visible only to people AFIT trusts.

What the free tier gives up, stated because each one is silent:

1. **It spins down after 15 minutes without inbound traffic.** A forwarded incident is inbound
   traffic, so the usual path still works - the POST wakes the service and the in-process delivery
   job runs while it is awake. A retry that was waiting on backoff does not get its second attempt
   until something else wakes it.
2. **Escalation only advances while the service is awake.** `CLOUD_ESCALATE_AFTER_SECONDS` is a
   timer, and a sleeping process has no timers. This is the feature the paid `worker --jobs
   escalation` service exists for, and on the free tier it is not reliable.
3. **Relayed evidence disappears at every spin-down and redeploy**, because `/tmp` is not a disk.
   The `evidence_assets` rows survive and the app keeps reporting the frames as still arriving,
   which is the truth; the bytes are gone. Alerts still arrive with their text.
4. **One instance, forever.** In-process jobs mean a second instance pages the same officer twice.
   The free tier cannot scale anyway, but this is a rule, not a limitation.

Upgrade to the paid layout in §5.1-§5.3 when either of two things becomes true: the escalation timer
has to actually fire, or evidence has to be retrievable after a redeploy. Between now and then this
runs real personnel logins, real incident data and real acknowledgement workflow at no cost - the
first time a push is genuinely sent is still a Firebase question, not a billing one.

## 6. Monitoring host

`docs/installation.md` through section 5, plus the forwarding lines:

```bat
WATCHTOWER_CLOUD_API_URL=https://api.example.ac.ng   # must be https
WATCHTOWER_CLOUD_KEY_ID=<id from service-key>
WATCHTOWER_CLOUD_KEY_SECRET=<32+ characters>
WATCHTOWER_SPOOL_DIR=./var/spool
```

All three of URL, id and secret are required together once a URL is set - the config layer
refuses a half-configured forwarder rather than silently dropping alerts, and refuses a
secret shorter than 32 characters because it HMAC-signs every request. With none of them set,
forwarding is off, the console shows `disabled`, and the system remains a working local
monitoring deployment.

`WATCHTOWER_SPOOL_DIR` is the last-resort JSONL spool for the case where even the database is
unreachable. It needs to be on durable storage and inside the backup set, and it should be
monitored: a spool that keeps growing means the outbox is not being drained.

## 7. Android distribution

`docs/android-build.md` §3 for the build. For getting it onto handsets, in increasing order
of formality: copy the debug APK to a handset (pilot only; requires unknown-sources);
distribute a signed release APK over an internal channel AFIT already trusts; or a managed
store / Play internal track. The release path needs a keystore that does not live in the
repository, and the manifest's placeholder App-Link host needs replacing before HTTPS deep
links route to the app instead of a browser.

## 8. Rotation and backup

| Secret | Rotation |
| --- | --- |
| Camera-credential ring (`WATCHTOWER_SECRET_KEY_PATH`) | back up **before** rotating; `secret-key` supports it, `camera_secrets.key_id` records which ring sealed what. Losing it means losing every camera password. |
| Cloud ring (`CLOUD_SECRET_KEY_PATH`) | seals FCM tokens; same rule |
| JWT / `CLOUD_JWT_SECRET` | changing it invalidates dashboard sessions; coordinate before rotating |
| Ingest key pair | generate a new pair, add it to `CLOUD_SERVICE_KEYS_JSON` alongside the old, switch the monitoring host, then remove the old |
| Firebase service account | a file on the cloud host only; revoke it in Google if it may have leaked |
| `google-services.json` | client config; not a credential, but the package id in it must still match |

Database backups on the schedule in `docs/installation.md` §8, plus the spool directory and
both key rings. A restore that brings back the database and not the rings produces rows whose
sealed values can never be opened.

## 9. What is not operational yet, and what no deployment can fix

- **No cloud host exists.** Everything in §2 through §5 is instructions, not a running system.
  `render.yaml` has never been applied, and the platform has never parsed it. §5.4 records a
  decision AFIT still owes before this goes in front of real personnel.
- **No Firebase project.** Until one exists there is no `google-services.json`, no service
  account file, and no push. `verify` reports `push delivery … not configured` and alerts
  are recorded with `failure_reason=push_not_configured` - which is the intended honest
  behaviour, not a bug to switch off.
- **No real camera has been connected.** The registry, health and evidence paths are covered
  by tests that use frames the harness provides. Acceptance Test 1 of the runbook - a
  VLC-verified AFIT address registering and going `online` - has not been run here.
- **Nothing has been measured in AFIT conditions**, so no detection-quality claim appears in
  this repository.
- **Broad deployment, changes to operational cameras and any pilot require AFIT approval.**
  A working `deploy` command is not authorisation.
