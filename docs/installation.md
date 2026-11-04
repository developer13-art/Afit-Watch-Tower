# Installation and Deployment

Covers proposal sections 8, 16, 19 (Phase 1) and 20. The commands below are the ones the
codebase actually ships; anything requiring a decision the project cannot make for you is
called out rather than invented.

## Prerequisites

| Requirement | Note |
|---|---|
| Python 3.11+ | developed and verified on 3.14 |
| PostgreSQL 14+ | section 8.1. The tooling **refuses** a non-PostgreSQL URL — SQLite is not a supported deployment target, only a convenience for isolated unit tests |
| `pip install -r requirements.txt` | FastAPI, SQLAlchemy 2, Alembic, psycopg 3, cryptography, PyJWT, Jinja2, OpenCV, NumPy |
| TLS termination | nginx or Caddy in front of the app for anything other than `development` |
| Isolated camera network | see "Network isolation" below |

## 1. Environment

```bash
cd watchtower
cp .env.example .env
```

`.env` must never be committed. Two values are mandatory and the application refuses to
start without them:

- `WATCHTOWER_DATABASE_URL` — must begin with `postgresql://` or `postgresql+psycopg://`.
  `config.py::load_settings` raises `ConfigError` otherwise, so a misconfigured deployment
  fails at boot rather than silently running against a file database. The short
  `postgres://` form some hosts print is refused; add the `ql`.
- `WATCHTOWER_JWT_SECRET` — signs dashboard session tokens, **32 characters minimum**. The
  value is HKDF-expanded into the HMAC key, so a short or guessed one lets anyone forge a
  signed-in session; the sample `CHANGE_ME` is now refused at boot rather than accepted.
  Generate a fresh long value:
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(48))"
  ```

### Managed PostgreSQL (Neon, RDS, Supabase)

The connection string a managed host gives you works unchanged, with three things checked:

- keep its TLS parameter, normally `?sslmode=require` — these hosts drop plaintext
  connections, and it reaches the driver intact.
- percent-encode the password if it contains `@`, `#`, `/` or `%` (`@` becomes `%40`),
  otherwise the host portion does not parse.
- use the **pooled** endpoint for the application. The supervision loop holds a pool
  (`pool_size=10`, `pool_recycle=1800`, pre-ping on checkout); serverless endpoints idle out
  faster than that, and pre-ping reconnects rather than failing the cycle.

An internet-hosted database is not a network-isolated one. Proposal section 16 asks for
isolation, and this schema holds user accounts and password hashes, camera usernames and
secret references, the audit trail and incident records — so treat a managed-host database
as a demonstration or development store and register no AFIT camera credential into it. What
is *not* in that database is the plaintext camera password (it is sealed with the local key
ring) and the video evidence (it stays in `WATCHTOWER_EVIDENCE_DIR` on this host). Both of
those must be backed up with this machine, and losing the key ring makes every sealed
credential unreadable.

`WATCHTOWER_ENVIRONMENT` selects the posture:

- `development` — HTTPS enforcement off by default, API docs enabled.
- `pilot` / `production` — HTTPS enforced, API docs disabled, and `serve` **refuses to
  start** if HTTPS enforcement is switched off. The middleware sets HSTS, CSP,
  `X-Frame-Options: DENY` and `X-Content-Type-Options: nosniff`.

`WATCHTOWER_REQUIRE_HTTPS` is explicit and is honoured even in `development`. Leaving it at
`1` while serving plain http over loopback makes the console look broken in two ways at once:
every GET is redirected to `https://`, which nothing is listening for, and the session cookie
is marked `Secure`, so the browser stops sending it and sign-in bounces back to `/login`.
Set it to `0` until TLS actually terminates in front of the app.

## 2. Camera-credential key ring

Every `python -m watchtower.cli …` command below assumes the package is importable. The
project uses a `src/` layout and ships no packaging file, so set the path first in the same
shell — `export PYTHONPATH=src` on Linux, `set PYTHONPATH=src` in Windows cmd — and for the
service unit use `Environment=PYTHONPATH=/opt/watchtower/src` as shown in the example unit.

```bash
python -m watchtower.cli secret-key
```

Writes to `WATCHTOWER_SECRET_KEY_PATH` (default `./var/watchtower.key`) with mode `0600`.
In a non-development environment the ring **refuses to create itself silently** — it will
not invent a key on a production boot, because an auto-generated key that nobody backed up
means every camera password becomes unrecoverable on the next reimage.

Rotation:

```bash
python -m watchtower.cli secret-key --force
```

This adds a new active key and keeps the previous ones in the ring, so existing sealed
secrets still decrypt. Rotation does **not** re-encrypt existing rows; it only changes
which key protects newly saved credentials. Losing this file loses every camera password —
treat it as a backup-critical asset and keep it out of the web root.

## 3. Database

```bash
createdb watchtower
python -m watchtower.cli migrate        # alembic upgrade head
python -m watchtower.cli check-schema   # reachable + at head?
```

`alembic.ini` deliberately contains no URL; `migrations/env.py` reads the environment, so
credentials live in one place and never in a versioned file. Migration `0001_core_schema`
creates the 19 application tables plus `alembic_version`, with indexes, foreign keys and
the retention-relevant constraints. Verify the DDL without a server if you want to review
it first:

```bash
alembic upgrade head --sql
```

## 4. Access control and the first administrator

```bash
python -m watchtower.cli bootstrap
```

Seeds the role catalogue, permissions and role-permission grants, then creates one
`system_administrator` account. The password is read through `getpass` with a 12-character
minimum, so it never lands in shell history. If users already exist the command stops and
explains rather than guessing; `--force` adds another account.

The five roles from section 14 are seeded by `bootstrap_access_control`. Camera-group
scoping is optional: a grant without a `camera_group_id` is institution-wide. Administrative
permission and video-viewing permission are separate codes — being able to manage a camera
does not automatically grant the right to watch it.

Create additional accounts through the dashboard, not by editing rows in `psql`; the audit
trail is part of the design.

## 5. Serve

```bash
python -m watchtower.cli serve --host 127.0.0.1 --port 8040
```

Bind to loopback and let the reverse proxy terminate TLS. Relevant flags:

- `--trusted-proxy` — comma-separated proxy IPs permitted to assert `X-Forwarded-Proto`.
  Without this, `proxy_headers` cannot be trusted and HTTPS enforcement can be spoofed.
- `--no-analysis` — start without the AI pass. Ingestion, live view and health monitoring
  keep working; this is the correct posture for Phase 1, where detection has not been
  validated in the AFIT environment.

Open `/dashboard`. Note that `uvicorn` is the development server; run it behind a process
supervisor (`systemd`, `supervisord`) for a pilot and use a single process — the stream
supervisor keeps its worker registry in-process, so multiple app workers would each try to
own the same cameras.

Example unit file:

```ini
[Service]
WorkingDirectory=/opt/watchtower
EnvironmentFile=/etc/watchtower/watchtower.env
Environment=PYTHONPATH=/opt/watchtower/src
ExecStart=/opt/watchtower/.venv/bin/python -m watchtower.cli serve \
  --host 127.0.0.1 --port 8040 --trusted-proxy 127.0.0.1
Restart=always
User=watchtower
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/watchtower /var/log/watchtower
```

`ReadWritePaths` must cover the evidence directory and the key ring path.

## 6. Network isolation

This is a security requirement, not a tuning suggestion.

- RTSP encrypts neither video nor credentials in transit. Cameras and the ingestion host
  belong on a segment that is not routable from the public internet.
- Never port-forward a camera address. The dashboard is the only intended entry point.
- The browser is never given a raw RTSP URL or a camera password. Live view is an
  authenticated relay served from the backend session that already owns the managed stream.
- Restrict the application database port to the app host.
- Put the dashboard behind AFIT's approved TLS terminator with a real certificate.
  Self-signed certificates in a pilot produce the habit of clicking through warnings, which
  is how credential leakage actually happens.

## 7. Retention and scheduled jobs

```bash
python -m watchtower.cli purge
```

Applies `WATCHTOWER_EVIDENCE_RETENTION_DAYS` to evidence assets. Run it on a schedule
(systemd timer or cron) rather than relying on a background thread, so the run is visible
in the job log and in the system's own scheduling record. Health-event and audit retention
are configured with `WATCHTOWER_HEALTH_RETENTION_DAYS` and `WATCHTOWER_AUDIT_RETENTION_DAYS`.

Audit retention has no scheduled job and no dashboard button, deliberately. Erasing the trail
is itself something the trail should record, so it happens only as an explicit authenticated
`POST /api/admin/audit/purge?before=<instant>` from an account holding `admin.policies`, which
counts the rows it is about to remove and writes an `admin.audit.purge` entry. It is not a GET:
a crawler, a browser prefetch or an `<img>` tag must not be able to delete it.

```bash
curl -X POST "https://tower.afit.local/api/admin/audit/purge?before=2025-10-29T00:00:00Z" \
  -H "Authorization: Bearer $WATCHTOWER_ADMIN_TOKEN" \
  -H "X-Watchtower-Client: dashboard"
```

## 8. Backups

Back up, and test restoring:

1. `pg_dump` of the application database.
2. The key ring file — **without it the database's sealed camera passwords are useless**.
3. The evidence directory.

Backups and configuration exports must be protected against accidental disclosure; camera
records themselves contain secret *references*, not secrets, but the key ring plus database
combination is the full credential set. Encrypt at rest and restrict access.

## 9. Pre-pilot checklist

Nothing here is optional before an authorized pilot:

- [ ] `WATCHTOWER_ENVIRONMENT` is `pilot`, HTTPS enforced, real certificate installed.
- [ ] `WATCHTOWER_JWT_SECRET` and the database password are not the template values.
- [ ] Key ring exists, is `0600`, is backed up separately from the database.
- [ ] Default administrator has been replaced or given a strong credential; second-line
      and operator accounts exist with scoped roles rather than shared admin access.
- [ ] `max_concurrent_streams` and `max_concurrent_connection_tests` match what the host
      was actually benchmarked with — the shipped defaults (8 and 2) are a starting ceiling,
      not a capacity claim.
- [ ] Retention timers installed.
- [ ] Cameras registered one at a time via the runbook, each with a passed connection test.
- [ ] `docs/pilot-evaluation.md` in hand, with the metrics owners named.
- [ ] AFIT authorization obtained in writing for the pilot scope, cameras involved and
      recording/retention rules.

## What this installation does not do

It does not register cameras by itself, does not enable RTSP on any camera, does not
discover devices on the network, and does not send email, SMS or push alerts until an
approved gateway is configured. Unconfigured channels are recorded as failed deliveries
with the reason "gateway is not configured" — the system does not report an alert as sent
when it was not.
