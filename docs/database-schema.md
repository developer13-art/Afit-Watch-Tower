# Database Schema

One PostgreSQL database, 29 application tables, two services.

The authoritative definitions are `src/watchtower/models.py` (monitoring console schema, 19
tables) and `src/watchtower/mobile/models.py` (personnel-mobile layer, 10 tables). Both attach
to the same SQLAlchemy `Base` (`src/watchtower/models.py:50`), so one metadata object describes
the whole schema and Alembic autogenerates against all 29 tables at once. Everything below is
read from those two files and from `migrations/versions/`; where a claim comes from behaviour
rather than DDL, the code location is named.

## 1. The overall picture

Both services point at the same Neon PostgreSQL database and read and write the *same* rows.
There are no duplicate incident or camera records for the mobile side, and no mobile-only copy
of either table.

| Service | Package | Owns | Reads |
|---|---|---|---|
| Monitoring application | `src/watchtower/` | cameras, streams, health, detections, incidents, evidence, audit | — |
| Personnel cloud API | `src/watchtower/cloud/` | devices, tokens, delivery, ack, ingest bookkeeping | `incidents`, `cameras`, `detection_events`, `evidence_assets`, `notifications`, `audit_logs`, `users` |

The sharing is stated in the source, not merely implied:

- `src/watchtower/cloud/__init__.py:4` — "It reads and writes the same Neon database as the
  monitoring application - one incident, one record, one owner".
- `src/watchtower/mobile/models.py:3-7` — the mobile tables "extend the core schema … they do
  not replace it", and duplicating incidents or cameras for the phone "would create two sources
  of truth about a security event, which is worse than no phone app".
- The cloud **refuses** to invent an incident. `POST /api/v1/ingest/incident` loads the row the
  monitoring host already wrote and rejects the call if it is absent
  (`src/watchtower/cloud/routers/ingest.py:147-155`, error code `incident_unavailable`). What
  the cloud writes against an incident is `notifications`, `notification_attempts`,
  `incident_acknowledgements`, `incident_actions`, `evidence_relay_states` and `audit_logs`.

The configuration guards enforce the single-database posture:

| Refusal | Location | Message |
|---|---|---|
| A non-PostgreSQL `WATCHTOWER_DATABASE_URL` is rejected at boot | `src/watchtower/config.py:170-174` | `WATCHTOWER_DATABASE_URL must be a PostgreSQL URL (section 8.1)` |
| A non-PostgreSQL URL is rejected again during migrations | `migrations/env.py:45-47` | `refusing to migrate: <url> is not a PostgreSQL URL.` |
| The cloud's own URL (`CLOUD_DATABASE_URL`, falling back to `WATCHTOWER_DATABASE_URL`) is checked the same way | `src/watchtower/cloud/config.py:169-179` | `CLOUD_DATABASE_URL must be a PostgreSQL URL.` |

Accepted schemes in all three cases are `postgresql://` and `postgresql+psycopg://` only; the
short `postgres://` form some hosts print is refused. There is no hard-coded fallback URL in
`alembic.ini` (`sqlalchemy.url` is empty by design, `alembic.ini:6`), so a migration cannot
silently run against an unintended database.

## 2. Conventions used in the tables below

- **Types** are given as PostgreSQL DDL types. `String(n)` → `varchar(n)`,
  `DateTime(timezone=True)` → `timestamptz`, `Uuid(as_uuid=True)` → `uuid`,
  `LargeBinary` → `bytea`, `Float` → `double precision`, `Text` → `text`, `JsonType` → `jsonb`.
- **`jsonb` vs `json`**: `JsonType` is `JSONB` with a plain `JSON` variant for SQLite only
  (`src/watchtower/models.py:47`). A deployed database sees `jsonb`.
- **Enum columns** are `varchar(64)` written through `EnumColumn`
  (`src/watchtower/models.py:139-167`). The Python enum is the source of truth and the value is
  validated at the database boundary: an unknown value raises `ValueError`, wrapped by
  SQLAlchemy as `StatementError`, before it is written
  (`src/watchtower/models.py:158-164`).
  **There is no `CHECK` constraint in the DDL for any enum column** — the only check constraint
  in the whole schema is `ck_profile_port_range` (`src/watchtower/models.py:337`, created at
  `migrations/versions/0001_core_schema.py:157`). The module docstring at
  `src/watchtower/models.py:3-5` says enum columns are stored "as VARCHAR with check
  constraints"; that describes the original intent, not the shipped DDL. It matters if anything
  ever writes these columns outside the ORM, because raw SQL is not checked.
- **Defaults are Python-side.** Values in the `Default` column below come from SQLAlchemy
  `default=` / `onupdate=` arguments and are supplied by the ORM on insert. The migration DDL
  carries no `DEFAULT` clause at all except `users.must_change_password`
  (`migrations/versions/0003_personnel_columns.py:32-35`, `server_default=sa.false()`). A
  hand-written `INSERT` that omits a `NOT NULL` state column therefore fails rather than
  receiving a fallback.
- **Timestamps** are timezone-aware. Where a naive value reaches the evidence layer it is read
  as UTC by convention (`src/watchtower/services/evidence.py:40-44`).
- **Foreign keys** are listed as `references`, with the `ondelete` behaviour, because that
  behaviour is what an operator deletes next. `SET NULL` means history survives the loss of the
  parent row; `CASCADE` means it goes with it.

## 3. Identity and access

Five tables, seeded by `python -m watchtower.cli bootstrap` via `bootstrap_access_control`
(`src/watchtower/security/rbac.py:176`). All five are core-schema tables in
`src/watchtower/models.py`.

### `users` (`src/watchtower/models.py:176`)

An account — console operator or personnel. The cloud admin endpoint creates personnel accounts
in the same table (`src/watchtower/cloud/routers/admin.py:290`); there is no separate
personnel table.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | PK | |
| `username` | varchar(64) | no | | `unique` |
| `display_name` | varchar(128) | no | | |
| `email` | varchar(256) | yes | | not an alert channel in this build (section 9) |
| `phone` | varchar(32) | yes | | as above |
| `password_hash` | varchar(256) | no | | never the password; written by `security.passwords.hash_password` |
| `is_active` | boolean | no | `True` | deactivating blocks refresh rotation (`src/watchtower/cloud/tokens.py:252`) |
| `failed_login_count` | integer | no | `0` | lockout counter |
| `locked_until` | timestamptz | yes | | |
| `password_changed_at` | timestamptz | no | now | |
| `must_change_password` | boolean | no | `False` | added by revision `0003`; the only server-side default in the schema |
| `last_login_at` | timestamptz | yes | | |
| `created_at` | timestamptz | no | now | |

`must_change_password` is enforced server-side, not client-side: a caller carrying the flag is
routed to the change-password screen (`src/watchtower/cloud/deps.py:231`). An admin can set it
again at `src/watchtower/cloud/routers/admin.py:431`.

### `roles` (`src/watchtower/models.py:208`)

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | integer | no | PK |
| `code` | varchar(48) | no | `unique`; the five seeded codes are `system_administrator`, `security_supervisor`, `security_operator`, `technical_operator`, `auditor_read_only` (`src/watchtower/security/rbac.py:46-90`) |
| `name` | varchar(128) | no | |
| `description` | text | yes | |
| `is_administrative` | boolean | no | separates administrative rights from video-viewing rights |

### `permissions` (`src/watchtower/models.py:219`)

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | integer | no | PK |
| `code` | varchar(96) | no | `unique`; 20 codes seeded (`src/watchtower/security/rbac.py:22-43`) |
| `description` | text | yes | |

### `role_permissions` (`src/watchtower/models.py:227`)

Pure join table, no surrogate key.

| Column | Type | Notes |
|---|---|---|
| `role_id` | integer | PK, references `roles.id` `ON DELETE CASCADE` |
| `permission_id` | integer | PK, references `permissions.id` `ON DELETE CASCADE` |

### `user_roles` (`src/watchtower/models.py:238`)

A role grant, optionally scoped to one camera group. An unscoped grant is institution-wide.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | integer | no | PK |
| `user_id` | integer | no | references `users.id` `CASCADE`; index `ix_user_roles_user` |
| `role_id` | integer | no | references `roles.id` `CASCADE` |
| `camera_group_id` | integer | yes | references `camera_groups.id` `CASCADE` |

Constraint `uq_user_role_scope` on (`user_id`, `role_id`, `camera_group_id`)
(`src/watchtower/models.py:263`) — the same scoped grant cannot be recorded twice. Note that
`camera_group_id` is nullable and PostgreSQL treats NULLs as distinct, so an institution-wide
grant (NULL group) can be inserted twice; the ORM path does not guard against it.

## 4. Cameras and ingestion

Six tables. The registry deliberately keeps secrets and validated connection parameters out of
the `cameras` row.

### `camera_groups` (`src/watchtower/models.py:273`)

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | integer | no | PK |
| `code` | varchar(48) | no | `unique` |
| `name` | varchar(128) | no | |
| `description` | text | yes | |
| `parent_id` | integer | yes | self reference to `camera_groups.id` `ON DELETE SET NULL` |

### `camera_secrets` (`src/watchtower/models.py:285`)

One sealed camera credential. See section 11 for how a row is produced.

| Column | Type | Null | Notes |
|---|---|---|---|
| `id` | integer | no | PK |
| `reference` | varchar(64) | no | `unique`; opaque handle shaped `sec_<16 hex>` (`src/watchtower/security/secrets.py:120`) |
| `ciphertext` | bytea | no | Fernet token, not the password |
| `key_id` | varchar(32) | no | which key-ring entry can read it |
| `created_at` | timestamptz | no | |
| `rotated_at` | timestamptz | yes | set by `SecretStore.replace` (`src/watchtower/security/secrets.py:150-155`) |

### `camera_connection_profiles` (`src/watchtower/models.py:301`)

Validated, non-secret connection parameters. `username` is stored in the clear
(`src/watchtower/models.py:314`) — only the password is sealed. No column here holds a
password, and no column reassembles a credential-bearing URL
(`src/watchtower/models.py:303-306`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `host` | varchar(256) | no | | index `ix_profiles_host_port` with `port` |
| `port` | integer | no | `554` | `CHECK ck_profile_port_range: port > 0 AND port <= 65535` |
| `stream_path` | varchar(256) | no | | |
| `username` | varchar(128) | yes | | plaintext camera username |
| `secret_reference` | varchar(64) | yes | | references `camera_secrets.reference` `ON DELETE SET NULL` |
| `transport` | varchar(64) | no | `tcp` | `EnumColumn(Transport)`: `tcp`, `udp` |
| `verified_in_vlc` | boolean | no | `False` | operator checkbox, proposal section 6.3 |
| `last_probe_result` | varchar(64) | yes | | free column carrying the `ProbeResult` vocabulary (section 9) |
| `last_probe_at` | timestamptz | yes | | |
| `created_at` | timestamptz | no | now | |
| `updated_at` | timestamptz | no | now, `onupdate` | |

A profile belongs to exactly one camera and is deleted with it — the relationship is
`cascade="all, delete-orphan"` with `single_parent=True`
(`src/watchtower/models.py:412-418`), so a profile is not shared between cameras.

### `monitoring_policies` (`src/watchtower/models.py:341`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `code` | varchar(48) | no | | `unique` |
| `name` | varchar(128) | no | | |
| `enabled` | boolean | no | `False` | |
| `detector_codes` | jsonb | no | `[]` | list of detector identifiers |
| `min_confidence` | double precision | no | `0.55` | |
| `analysis_fps` | double precision | no | `4.0` | |
| `zones` | jsonb | no | `[]` | restricted-zone polygons; institution-approved geometry |
| `duplicate_window_seconds` | integer | no | `90` | feeds `detection_events.dedupe_key` |
| `severity` | varchar(64) | no | `medium` | `EnumColumn(Severity)` |
| `updated_at` | timestamptz | no | now, `onupdate` | |

A policy is referenced by many cameras (`cameras.monitoring_policy_id`), so changing detection
settings for a set of cameras is one row, not a migration.

### `cameras` (`src/watchtower/models.py:364`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | uuid | no | | PK; assigned by the application, not the database |
| `code` | varchar(64) | no | | `unique` |
| `display_name` | varchar(128) | no | | the only camera attribute the phone ever sees |
| `campus_location` | varchar(256) | no | | index `ix_cameras_location` |
| `camera_group_id` | integer | yes | | references `camera_groups.id` `SET NULL`; index `ix_cameras_group` |
| `model` | varchar(128) | yes | | |
| `description` | text | yes | | |
| `connection_profile_id` | integer | yes | | references `camera_connection_profiles.id` `SET NULL` |
| `monitoring_policy_id` | integer | yes | | references `monitoring_policies.id` `SET NULL` |
| `recording_policy` | jsonb | no | `{}` | approved settings blob, not free-form |
| `status` | varchar(64) | no | `pending_setup` | `EnumColumn(CameraStatus)`; index `ix_cameras_status` |
| `desired_state` | varchar(24) | no | `stopped` | unchecked string; the code only ever writes `stopped` or `running` (`src/watchtower/services/cameras.py:191,362,397,483`) and the supervision pass filters on `running` (`src/watchtower/services/runtime.py:113`) |
| `is_registered` | boolean | no | `False` | |
| `last_successful_frame_at` | timestamptz | yes | | |
| `last_error_code` | varchar(64) | yes | | |
| `created_by` | integer | yes | | references `users.id` `SET NULL` |
| `modified_by` | integer | yes | | references `users.id` `SET NULL` |
| `created_at` | timestamptz | no | now | |
| `updated_at` | timestamptz | no | now, `onupdate` | |

`status` is what the health evaluator observed; `desired_state` is what the operator asked for.
They are two columns because "stopped" and "broken" must not be confused, and an activated
camera is managed by flipping `desired_state` without a server restart
(`src/watchtower/models.py:395-396`).

### `camera_stream_sessions` (`src/watchtower/models.py:429`)

One row per supervised stream session; a camera has many.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `camera_id` | uuid | no | | references `cameras.id` `CASCADE`; index `ix_sessions_camera_started` with `started_at` |
| `pid` | integer | yes | | OS process id of the supervised worker |
| `state` | varchar(32) | no | `starting` | unchecked string; values written by the code are `starting`, `connecting`, `reconnecting`, `online`, `failed`, `stopped` (`src/watchtower/ingest/worker.py:85-171`, `src/watchtower/ingest/supervisor.py:125,152`) |
| `started_at` | timestamptz | no | now | |
| `last_frame_at` | timestamptz | yes | | |
| `frames_received` | integer | no | `0` | |
| `frames_dropped` | integer | no | `0` | |
| `decode_failures` | integer | no | `0` | |
| `retry_count` | integer | no | `0` | |
| `viewer_count` | integer | no | `0` | |
| `measured_fps` | double precision | no | `0.0` | |
| `terminal` | boolean | no | `False` | the session row is closed and will not be resumed |
| `termination_reason` | varchar(64) | yes | | |

## 5. Health and analysis

Three tables. Health state is kept out of the incident table on purpose: "health events stay
distinct from AI-detected security incidents" (`src/watchtower/models.py:461`).

### `camera_health_events` (`src/watchtower/models.py:460`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `camera_id` | uuid | no | | references `cameras.id` `CASCADE`; index `ix_health_camera_observed` with `observed_at` |
| `previous_status` | varchar(48) | yes | | unchecked; carries the `CameraStatus` vocabulary (`src/watchtower/health/evaluator.py:208`) |
| `status` | varchar(48) | no | | unchecked; same vocabulary (`src/watchtower/health/evaluator.py:209`) |
| `reason_code` | varchar(64) | no | | e.g. `operator_disabled` (`src/watchtower/services/cameras.py:404`) |
| `detail` | text | yes | | |
| `observed_at` | timestamptz | no | now | |
| `duration_seconds` | double precision | yes | | |
| `notified` | boolean | no | `False` | alert-suppression bookkeeping |

Because `status` here is a plain `varchar(48)` and not an `EnumColumn`, an invalid value is
accepted by the database. The `cameras.status` column is checked; this history column is not.
The evaluator writes a row when the state moves, so this table is a change log rather than a
sampled history.

### `detection_events` (`src/watchtower/models.py:491`)

One candidate event from the analysis pass, or a manual or health-sourced candidate.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `camera_id` | uuid | no | | references `cameras.id` `CASCADE` |
| `policy_id` | integer | yes | | references `monitoring_policies.id` `SET NULL` |
| `category` | varchar(64) | no | | detector category |
| `confidence` | double precision | no | | |
| `occurred_at` | timestamptz | no | now | index `ix_events_status_occurred` with `status` |
| `metadata` | jsonb | no | `{}` | the Python attribute is `event_metadata`, because `metadata` is reserved by the declarative base (`src/watchtower/models.py:510-512`) |
| `status` | varchar(64) | no | `new` | `EnumColumn(EventStatus)` |
| `dedupe_key` | varchar(160) | yes | | see constraint below |
| `suppressed` | boolean | no | `False` | |
| `reviewed_by` | integer | yes | | references `users.id` `SET NULL` |
| `reviewed_at` | timestamptz | yes | | |
| `review_note` | text | yes | | |

`uq_event_dedupe` is a **composite unique key on (`camera_id`, `dedupe_key`)**
(`src/watchtower/models.py:525`). That is the duplicate-suppression rule: the same detection for
the same camera inside `monitoring_policies.duplicate_window_seconds` collides on insert instead
of raising a second alert. An event written with `dedupe_key IS NULL` is exempt, because
PostgreSQL treats NULLs as distinct in a unique index — a candidate produced without a dedupe
key is never blocked by this constraint.

The three detection source labels used by the incident-creation path are module constants, not
columns: `ai_candidate`, `manual`, `health`
(`src/watchtower/mobile/models.py:456-458`).

### `system_jobs` (`src/watchtower/models.py:708`)

Declared in the model and created by `0001_core_schema`
(`migrations/versions/0001_core_schema.py:89`), but **no code in `src/` or `tests/` reads or
writes it** — no `SystemJob` reference exists outside `src/watchtower/models.py`. Treat it as an
empty table, not as a queue to monitor.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `kind` | varchar(64) | no | | |
| `payload` | jsonb | no | `{}` | |
| `state` | varchar(64) | no | `queued` | `EnumColumn(JobState)`; index `ix_jobs_state_scheduled` with `scheduled_for` |
| `attempts` | integer | no | `0` | |
| `scheduled_for` | timestamptz | no | now | |
| `started_at` | timestamptz | yes | | |
| `finished_at` | timestamptz | yes | | |
| `last_error` | text | yes | | |

## 6. Incidents and evidence

Five tables. `incidents` is written by the monitoring application; the cloud reads it and appends
to the child tables.

### `incidents` (`src/watchtower/models.py:530`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `reference` | varchar(32) | no | | `unique`; human reference such as `WT-2026-0007` |
| `title` | varchar(256) | no | | |
| `summary` | text | yes | | |
| `category` | varchar(64) | no | | |
| `severity` | varchar(64) | no | `medium` | `EnumColumn(Severity)` |
| `status` | varchar(64) | no | `open` | `EnumColumn(IncidentStatus)`; index `ix_incidents_status_occurred` with `occurred_at` |
| `camera_id` | uuid | yes | | references `cameras.id` `SET NULL`; index `ix_incidents_camera` — a camera can be removed without losing the incident |
| `origin_event_id` | integer | yes | | references `detection_events.id` `SET NULL` — the provenance back to the frame-level proposal |
| `campus_location` | varchar(256) | yes | | copied at creation, so the location survives a camera edit |
| `occurred_at` | timestamptz | no | now | |
| `assigned_to` | integer | yes | | references `users.id` `SET NULL` |
| `escalated_to` | integer | yes | | references `users.id` `SET NULL` |
| `resolved_at` | timestamptz | yes | | cleared on reopen (`src/watchtower/services/incidents.py:400-406`) |
| `resolution` | text | yes | | cleared on reopen |
| `outcome` | varchar(64) | yes | | cleared on reopen |
| `created_by` | integer | yes | | references `users.id` `SET NULL` |
| `created_at` | timestamptz | no | now | |
| `updated_at` | timestamptz | no | now, `onupdate` | |

### `incident_actions` (`src/watchtower/models.py:583`)

The activity trail of one incident: assignment, escalation, notes, resolution, reopen, close.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `incident_id` | integer | no | | references `incidents.id` `CASCADE`; index `ix_actions_incident` |
| `action` | varchar(48) | no | | unchecked; written values include `created`, `assigned`, `escalated`, `note`, `investigation_note`, `resolved`, `reopened`, `closed` (`src/watchtower/services/incidents.py:182-426`) |
| `note` | text | yes | | |
| `actor_id` | integer | yes | | references `users.id` `SET NULL` |
| `created_at` | timestamptz | no | now | |

Cascade order matters operationally: deleting a camera leaves the incident (`SET NULL`), but
deleting an incident deletes its actions and its evidence rows
(`src/watchtower/models.py:570-575`, `cascade="all, delete-orphan"`).

### `incident_acknowledgements` (`src/watchtower/mobile/models.py:313`)

Who accepted responsibility for an incident, and when.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `incident_id` | integer | no | | references `incidents.id` `CASCADE`; index `ix_ack_incident` |
| `user_id` | integer | no | | references `users.id` `SET NULL` — an acknowledgement survives the account |
| `notification_id` | integer | yes | | references `notifications.id` `SET NULL` |
| `source` | varchar(24) | no | `mobile` | unchecked; the cloud writes `mobile` (`src/watchtower/cloud/routers/incidents.py:412`) |
| `note` | text | yes | | |
| `acknowledged_at` | timestamptz | no | now | |

`uq_ack_per_incident_user` on (`incident_id`, `user_id`)
(`src/watchtower/mobile/models.py:341`) is the duplicate-acknowledgement rule, enforced by the
database rather than by an application check: two phones tapping acknowledge at the same moment
produce one record and one `already_acknowledged` response. Two different users may acknowledge
the same incident, and the constraint permits that.

### `evidence_assets` (`src/watchtower/models.py:604`)

Metadata only. The bytes live on the filesystem under `WATCHTOWER_EVIDENCE_DIR`, never in a
database row (`src/watchtower/services/evidence.py:3-6`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `incident_id` | integer | yes | | references `incidents.id` `CASCADE`; index `ix_evidence_incident` — evidence is lost with its incident |
| `camera_id` | uuid | yes | | references `cameras.id` `SET NULL` |
| `detection_event_id` | integer | yes | | references `detection_events.id` `SET NULL` |
| `kind` | varchar(24) | no | | the write path uses `snapshot` (`src/watchtower/services/evidence.py:68,134`); the cloud's filename validator admits `snapshot`, `clip`, `frame`, `upload` (`src/watchtower/cloud/storage.py:27`) |
| `filename` | varchar(512) | no | | |
| `storage_key` | varchar(512) | no | | `unique` — the path under the evidence root, e.g. `2026/11/02/<uuid hex>.jpg` (`src/watchtower/services/evidence.py:84`) |
| `content_type` | varchar(64) | no | | `image/jpeg` on the snapshot path |
| `byte_size` | integer | no | | |
| `sha256` | varchar(64) | no | | the integrity digest — see section 11 |
| `captured_at` | timestamptz | no | now | |
| `expires_at` | timestamptz | yes | | retention expiry — see section 11 |
| `deleted_at` | timestamptz | yes | | set when the file is retired; the row stays as the record that evidence existed |

There is no URL column here: retrieval is brokered per request, and `storage_key` is a
filesystem key, not an address.

### `evidence_relay_states` (`src/watchtower/mobile/models.py:426`)

Cloud-side tracking of the monitor-to-cloud copy of the bytes. `evidence_assets` remains the
single record of an asset; this row exists so the phone can display "the incident exists but its
image has not arrived yet" honestly instead of as a broken image
(`src/watchtower/mobile/models.py:427-432`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `asset_id` | integer | no | | references `evidence_assets.id` `CASCADE`, **`unique`** — at most one relay state per asset (`src/watchtower/mobile/models.py:437-439`) |
| `state` | varchar(64) | no | `pending_upload` | `EnumColumn(UploadState)`; index `ix_relay_state` |
| `expected_sha256` | varchar(64) | yes | | copied from `evidence_assets.sha256` when unset (`src/watchtower/cloud/routers/ingest.py:385`) |
| `received_sha256` | varchar(64) | yes | | digest of the bytes that actually arrived |
| `bytes_received` | integer | no | `0` | |
| `updated_at` | timestamptz | no | now, `onupdate` | |

A relayed file is refused if the declared digest does not match the asset row
(`src/watchtower/cloud/routers/ingest.py:270-273`) and marked `missing` if the received bytes
fail verification (`src/watchtower/cloud/routers/ingest.py:300-337`).

## 7. Notifications and mobile

Nine tables. The first is the shared alert record; the rest are the mobile machinery.

### `notifications` (`src/watchtower/models.py:637`)

One alert routed to one recipient over one channel, with delivery state. Written by both sides:
the console through `services/notifications.py:118`, the cloud through `cloud/delivery.py:116,153`.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `kind` | varchar(48) | no | | e.g. `event.new`, `incident.resolved`, `camera.<status>` (`src/watchtower/services/notifications.py:213-245`) |
| `title` | varchar(200) | no | | |
| `body` | text | no | | |
| `severity` | varchar(64) | no | `medium` | `EnumColumn(Severity)` |
| `channel` | varchar(64) | no | `dashboard` | `EnumColumn(NotificationChannel)` |
| `state` | varchar(64) | no | `pending` | `EnumColumn(NotificationState)`; index `ix_notifications_recipient_state` with `recipient_id` |
| `dedupe_key` | varchar(160) | yes | | see constraint below |
| `camera_id` | uuid | yes | | references `cameras.id` `CASCADE` |
| `incident_id` | integer | yes | | references `incidents.id` `CASCADE` |
| `event_id` | integer | yes | | references `detection_events.id` `CASCADE` |
| `recipient_id` | integer | yes | | references `users.id` `CASCADE` |
| `created_at` | timestamptz | no | now | |
| `delivered_at` | timestamptz | yes | | |
| `read_at` | timestamptz | yes | | added by revision `0003` |
| `acknowledged_at` | timestamptz | yes | | |
| `failure_reason` | varchar(256) | yes | | |

`uq_notification_dedupe` on (`dedupe_key`, `recipient_id`, `channel`)
(`src/watchtower/models.py:678`) is what stops one incident paging one person twice over the
same route. `read_at` and `acknowledged_at` are two columns because reading and acknowledging
are two different facts; `state` alone cannot tell "opened" from "accepted responsibility"
(`src/watchtower/models.py:671-674`).

### `notification_outbox` (`src/watchtower/mobile/models.py:115`)

The transactional outbox. A row is written inside the same database transaction that creates the
incident, so an incident can never be recorded while its alert is silently lost, and an internet
outage leaves these rows `queued` with a `next_retry_at` rather than dropping them
(`src/watchtower/mobile/models.py:11-14`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `idempotency_key` | varchar(160) | no | | **`unique`** (`src/watchtower/mobile/models.py:125`) |
| `kind` | varchar(48) | no | | written from `AlertIntent.kind`, truncated to 48 (`src/watchtower/cloud/delivery.py:117`, `:154`). The values the code produces are `incident.created`, `incident.assigned`, `incident.escalated`, `incident.resolved` (`src/watchtower/mobile/outbox.py:177` with the kinds in `src/watchtower/mobile/alerts.py:25-28`, `src/watchtower/cloud/worker.py:40`) and `event.new` (`src/watchtower/cloud/targeting.py:58`) |
| `severity` | varchar(64) | no | `medium` | `EnumColumn(Severity)` |
| `title` | varchar(200) | no | | |
| `body` | text | no | | |
| `incident_id` | integer | yes | | references `incidents.id` `SET NULL`; index `ix_outbox_incident` |
| `event_id` | integer | yes | | references `detection_events.id` `SET NULL` |
| `camera_id` | uuid | yes | | references `cameras.id` `SET NULL` |
| `payload` | jsonb | no | `{}` | the exact JSON the forwarder will POST |
| `evidence_keys` | jsonb | no | `[]` | `storage_key` values to relay, in upload order |
| `state` | varchar(64) | no | `queued` | `EnumColumn(OutboxState)`; index `ix_outbox_state_retry` with `next_retry_at` |
| `attempts` | integer | no | `0` | |
| `next_retry_at` | timestamptz | no | now | the drain query is `state IN (...) AND next_retry_at <= now()` |
| `last_error` | varchar(512) | yes | | |
| `created_at` | timestamptz | no | now | |
| `processing_at` | timestamptz | yes | | the claim that keeps two forwarders off one row (`src/watchtower/mobile/outbox.py:367`) |
| `completed_at` | timestamptz | yes | | |

The unique `idempotency_key` is the whole replay answer: the key is stable across retries —
`incident:<id>:<kind>` (`src/watchtower/mobile/outbox.py:80-81`), `event:<id>:candidate`,
`evidence:<asset id>:<first 16 of sha256>` (`src/watchtower/mobile/outbox.py:609`) — and
`enqueue()` looks the key up before inserting (`src/watchtower/mobile/outbox.py:197-207`), so a
retry is folded into the existing row instead of producing a second push.

### `notification_attempts` (`src/watchtower/mobile/models.py:269`)

One send of one notification to one device. `accepted_at` means FCM queued the message; it is
not proof that a human saw anything (`src/watchtower/mobile/models.py:271-274`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `notification_id` | integer | no | | references `notifications.id` `CASCADE`; index `ix_attempt_notification` |
| `device_id` | integer | yes | | references `mobile_devices.id` `SET NULL` |
| `provider` | varchar(16) | no | `fcm` | |
| `provider_message_id` | varchar(128) | yes | | |
| `state` | varchar(64) | no | `submitted` | `EnumColumn(AttemptState)` |
| `idempotency_key` | varchar(160) | no | | part of the composite key below |
| `requested_at` | timestamptz | no | now | |
| `accepted_at` | timestamptz | yes | | |
| `failed_at` | timestamptz | yes | | |
| `opened_at` | timestamptz | yes | | recorded separately from acceptance |
| `error_code` | varchar(64) | yes | | |
| `failure_reason` | varchar(256) | yes | | |

`uq_attempt_per_device` on (`notification_id`, `device_id`, `idempotency_key`)
(`src/watchtower/mobile/models.py:306-308`). As with the other composite keys, `device_id` is
nullable and PostgreSQL treats NULLs as distinct, so an attempt written without a device is not
covered by this constraint.

### `mobile_devices` (`src/watchtower/mobile/models.py:178`)

One installed application on one handset, owned by one personnel account.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `user_id` | integer | no | | references `users.id` `CASCADE` |
| `installation_id` | varchar(64) | no | | opaque id the app owns |
| `platform` | varchar(16) | no | `android` | unchecked; validated in code against `android`, `ios`, `web` (`src/watchtower/cloud/devices.py:27,111`) |
| `push_provider` | varchar(16) | no | `fcm` | |
| `push_token_ciphertext` | bytea | yes | | Fernet token, never the registration token |
| `push_token_key_id` | varchar(32) | yes | | key-ring reference |
| `push_token_fingerprint` | varchar(16) | yes | | first 12 hex of SHA-256 of the token; index `ix_device_token_fingerprint` |
| `push_state` | varchar(64) | no | `active` | `EnumColumn(PushState)`; index `ix_device_push_state` |
| `model` | varchar(128) | yes | | |
| `os_version` | varchar(32) | yes | | |
| `app_version` | varchar(32) | yes | | |
| `registered_at` | timestamptz | no | now | |
| `last_seen_at` | timestamptz | no | now | |
| `token_updated_at` | timestamptz | yes | | |
| `deactivated_at` | timestamptz | yes | | a device with this set is not a delivery target (`src/watchtower/cloud/devices.py:236`) |
| `invalid_reason` | varchar(128) | yes | | |

`uq_device_per_user` on (`user_id`, `installation_id`)
(`src/watchtower/mobile/models.py:217`): one row per installation per account. A shared test
handset used by two accounts is two rows, not a conflict.

### `refresh_tokens` (`src/watchtower/mobile/models.py:223`)

Device-bound, single-use, rotated, with reuse detection. Only the digest is stored
(`src/watchtower/mobile/models.py:224-229`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `user_id` | integer | no | | references `users.id` `CASCADE` |
| `device_id` | integer | yes | | references `mobile_devices.id` `SET NULL` |
| `token_hash` | varchar(64) | no | | `unique`; SHA-256 hex of the plaintext (`src/watchtower/cloud/tokens.py:54-55`) |
| `family` | uuid | no | | one rotation chain per login; index `ix_refresh_family` |
| `generation` | integer | no | `1` | incremented per rotation (`src/watchtower/cloud/tokens.py:177-180`) |
| `issued_at` | timestamptz | no | now | |
| `expires_at` | timestamptz | no | | index `ix_refresh_user_expires` with `user_id` |
| `rotated_at` | timestamptz | yes | | set on the parent when it is spent |
| `revoked_at` | timestamptz | yes | | |
| `reuse_detected` | boolean | no | `False` | set across the whole family by `_revoke_family` (`src/watchtower/cloud/tokens.py:289-298`) |
| `replaced_by_id` | integer | yes | | self reference to `refresh_tokens.id` `SET NULL` |
| `client_ip` | varchar(64) | yes | | |
| `user_agent` | varchar(256) | yes | | |

The unique `token_hash` plus `rotated_at` is the reuse detector: presenting a token whose digest
is already marked rotated means two parties hold the value, so every row in that `family` is
revoked and `auth.refresh_reuse` is audited
(`src/watchtower/cloud/tokens.py:227-247`).

### `personnel_preferences` (`src/watchtower/mobile/models.py:346`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `user_id` | integer | no | | references `users.id` `CASCADE`, **`unique`** — one preference row per account |
| `min_severity` | varchar(64) | no | `low` | `EnumColumn(Severity)` |
| `kinds` | jsonb | no | `{}` | |
| `quiet_hours` | jsonb | no | `{}` | |
| `sound` | varchar(24) | no | `default` | |
| `updated_at` | timestamptz | no | now, `onupdate` | |

### `monitoring_heartbeats` (`src/watchtower/mobile/models.py:409`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `monitoring_host` | varchar(128) | no | | index `ix_heartbeat_host_received` with `received_at` |
| `app_version` | varchar(32) | yes | | |
| `outbox_pending` | integer | no | `0` | queued + processing at report time (`src/watchtower/mobile/outbox.py:635-637`) |
| `outbox_failed` | integer | no | `0` | dead at report time (`src/watchtower/mobile/outbox.py:638`) |
| `received_at` | timestamptz | no | now | |

Append-only: one row per heartbeat. Idempotency is handled at the transport level by the key
`heartbeat:<host>:<unix minute>` (`src/watchtower/mobile/outbox.py:632`), not by a constraint on
this table.

### `ingest_nonces` (`src/watchtower/mobile/models.py:368`)

The persisted replay cache for service-to-service ingest calls. An in-memory cache is not enough:
a cloud restart would forget every nonce and a captured request could be replayed into duplicate
pushes (`src/watchtower/mobile/models.py:369-374`).

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `key_id` | varchar(64) | no | | which service credential signed the request |
| `nonce` | varchar(64) | no | | |
| `seen_at` | timestamptz | no | now | |

`uq_ingest_nonce` on (`key_id`, `nonce`) (`src/watchtower/mobile/models.py:385`). Inserting the
row *is* the replay check — the collision raises `IntegrityError` and the request is refused as
already processed (`src/watchtower/cloud/ingest.py:112-126`). The pair, not the nonce alone, so a
different service credential may reuse the same nonce string.

### `ingest_records` (`src/watchtower/mobile/models.py:388`)

Processed ingest calls, keyed by idempotency key, so a retry is answered with the first response.

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `idempotency_key` | varchar(160) | no | | `unique` |
| `route` | varchar(96) | no | | e.g. `/api/v1/ingest/incident` |
| `key_id` | varchar(64) | no | | |
| `request_digest` | varchar(64) | no | | `content_sha256` of the signed body |
| `incident_id` | integer | yes | | references `incidents.id` `SET NULL`; index `ix_ingest_incident` |
| `response` | jsonb | no | `{}` | replayed verbatim to a duplicate caller (`src/watchtower/cloud/routers/ingest.py:136-137`) |
| `processed_at` | timestamptz | no | now | |

A racing second writer on the same key loses the insert and reads back what the winner stored,
instead of duplicating the work (`src/watchtower/cloud/ingest.py:178`). `request_digest` is
compared on the way in: a call that reuses a spent key with **different** content is refused
`409 idempotency_conflict` (`src/watchtower/cloud/ingest.py:152-169`) rather than being answered
with the stored response. Without that comparison the retry path would report success and
silently discard the second alert - the one place in this design where an alert could vanish
without leaving a failed row. A genuine retry of the same body still answers with the stored
response and `"duplicate": true`.

## 8. Audit

### `audit_logs` (`src/watchtower/models.py:683`)

| Column | Type | Null | Default | Notes |
|---|---|---|---|---|
| `id` | integer | no | | PK |
| `actor_id` | integer | yes | | references `users.id` `SET NULL`; index `ix_audit_actor_created` with `created_at` |
| `actor_username` | varchar(64) | yes | | denormalised, so the actor is still readable after the account is renamed or removed |
| `action` | varchar(96) | no | | e.g. `event.acknowledge`, `incident.resolve`, `auth.refresh_reuse`; index `ix_audit_action_created` with `created_at` |
| `object_type` | varchar(48) | yes | | |
| `object_id` | varchar(64) | yes | | string, so it can hold a uuid or an integer |
| `details` | jsonb | no | `{}` | sanitised before the write (section 11); `src/watchtower/models.py:694` |
| `outcome` | varchar(24) | no | `success` | unchecked; `success` and `failure` are the values the audit helper is given |
| `source_ip` | varchar(64) | yes | | |
| `created_at` | timestamptz | no | now | indexed on its own (`index=True`, `src/watchtower/models.py:699`) |

## 9. Enum vocabularies

These are the exact strings the code accepts, taken from the enum definitions. A value outside
the set raises at the database boundary for `EnumColumn` columns. "Terminal" describes what the
**code** treats as final; the database enforces no state machine anywhere in this schema. Where a
row below says "unchecked", the column is a plain `varchar` and the database accepts any string —
only the columns actually wrapped in `EnumColumn` validate, and they validate in Python, never as
a SQL check constraint.

| Enum | Column(s) | Values | Terminal |
|---|---|---|---|
| `CameraStatus` (`models.py:59`) | `cameras.status` (checked); `camera_health_events.status`, `previous_status` (unchecked `varchar(48)`) | `pending_setup`, `testing`, `online`, `degraded`, `reconnecting`, `offline`, `authentication_failed`, `maintenance`, `disabled` | none — health is a cycle; `disabled` is the operator-set state |
| `ProbeResult` (`models.py:73`) | `camera_connection_profiles.last_probe_result` (unchecked `varchar(64)`) | `testing`, `connection_successful`, `authentication_failed`, `host_unreachable`, `stream_path_invalid_or_unsupported`, `video_decode_failed`, `timed_out`, `test_cancelled` | every value except `testing` ends one probe; a new probe overwrites the column |
| `Transport` (`models.py:86`) | `camera_connection_profiles.transport` | `tcp`, `udp` | n/a |
| `Severity` (`models.py:107`) | `monitoring_policies.severity`, `incidents.severity`, `notifications.severity`, `notification_outbox.severity`, `personnel_preferences.min_severity` | `low`, `medium`, `high`, `critical` | n/a. Order is not a database property: `SEVERITY_RANK` maps the strings to integers in Python (`src/watchtower/cloud/targeting.py:28`, `src/watchtower/services/notifications.py:38`), so the `varchar(64)` column itself carries no ordering |
| `EventStatus` (`models.py:91`) | `detection_events.status` | `new`, `acknowledged`, `dismissed`, `escalated` | none. The review pass checks no prior status and overwrites `status` from any value (`src/watchtower/services/incidents.py:106-112`); `new` is only the review-queue filter (`:147`) |
| `IncidentStatus` (`models.py:98`) | `incidents.status` | `open`, `investigating`, `assigned`, `resolved`, `closed`, `false_positive` | `false_positive` is final in the current code: reopen accepts only `resolved` or `closed` (`src/watchtower/services/incidents.py:395-399`) |
| `NotificationChannel` (`models.py:114`) | `notifications.channel` | `dashboard`, `email`, `sms`, `webhook`, `mobile_push` | n/a. Only `dashboard`, `webhook` and `mobile_push` have delivery paths (`src/watchtower/services/notifications.py:159-163`, `src/watchtower/cloud/delivery.py:121`); `email` and `sms` are vocabulary with no sender |
| `NotificationState` (`models.py:122`) | `notifications.state` | `pending`, `delivered`, `read`, `acknowledged`, `failed`, `suppressed` | `acknowledged`, `suppressed`; `failed` is retried by the delivery pass (`src/watchtower/cloud/delivery.py:208-237`) |
| `JobState` (`models.py:131`) | `system_jobs.state` | `queued`, `running`, `succeeded`, `failed`, `cancelled` | `succeeded`, `cancelled`, `failed` — table unused, see section 5 |
| `OutboxState` (`mobile/models.py:75`) | `notification_outbox.state` | `queued`, `processing`, `delivered`, `failed`, `dead` | `delivered`, `dead`. `dead` is reached at `attempts >= WATCHTOWER_OUTBOX_MAX_ATTEMPTS` (default 12, `src/watchtower/config.py:90`) in `src/watchtower/mobile/outbox.py:390-391`; `failed` stays claimable (`mobile/outbox.py:346`) |
| `PushState` (`mobile/models.py:83`) | `mobile_devices.push_state` | `active`, `inactive`, `revoked`, `invalid` | `revoked` — re-registering the installation does not restore it (`src/watchtower/cloud/devices.py:139-145`). `invalid` returns to `active` only when a new token is sealed (`cloud/devices.py:181`) |
| `AttemptState` (`mobile/models.py:90`) | `notification_attempts.state` | `submitted`, `accepted`, `failed` | `accepted`, `failed`. `submitted` is only the insert default (`mobile/models.py:290`); the provider reply writes the outcome (`src/watchtower/cloud/delivery.py:257-296`, `:375-384`) |
| `UploadState` (`mobile/models.py:103`) | `evidence_relay_states.state` | `available`, `pending_upload`, `missing`, `deleted` | none enforced as final; `deleted` is vocabulary with no writer in the code |
| `EvidenceHost` (`mobile/models.py:96`) | no column of any table | `monitor`, `cloud` | n/a. Declared and never used: `src/watchtower/` reads it nowhere, so the intent in its own docstring ("where the evidence bytes actually are") is carried in practice by `evidence_relay_states.state` |
| `Transport` as declared versus stored | — | — | `camera_connection_profiles.transport` is the only `EnumColumn(Transport)` in the schema; `cameras` carries no transport column, so per-camera transport lives in the stream URL |

## 10. Migration history

Three linear revisions, no branches. Head is **`0003_personnel_columns`**, confirmed locally
with `python -m alembic history` (read-only; it opens no database connection).

| Revision | File | Depends on | What it adds |
|---|---|---|---|
| `0001_core_schema` | `migrations/versions/0001_core_schema.py` | base | All 19 core tables: `camera_groups`, `camera_secrets`, `monitoring_policies`, `permissions`, `roles`, `system_jobs`, `users`, `audit_logs`, `camera_connection_profiles`, `role_permissions`, `user_roles`, `cameras`, `camera_health_events`, `camera_stream_sessions`, `detection_events`, `incidents`, `evidence_assets`, `incident_actions`, `notifications`. Plus the indexes, foreign keys and unique constraints listed above, and the only check constraint in the schema (`ck_profile_port_range`, line 157) |
| `0002_personnel_mobile` | `migrations/versions/0002_personnel_mobile.py` | `0001` | All 10 mobile tables: `ingest_nonces`, `monitoring_heartbeats`, `mobile_devices`, `personnel_preferences`, `refresh_tokens`, `ingest_records`, `notification_outbox`, `evidence_relay_states`, `incident_acknowledgements`, `notification_attempts`. Entirely additive — no core table is altered, renamed or dropped, because the mobile app reads `incidents`, `cameras`, `evidence_assets` and `notifications` rather than duplicating them (docstring, lines 7-10) |
| `0003_personnel_columns` | `migrations/versions/0003_personnel_columns.py` | `0002` | Two columns: `users.must_change_password` (`boolean NOT NULL`, server default `false`) and `notifications.read_at` (`timestamptz`, nullable). Both additive, so an existing deployment upgrades with no data migration and no invalidated dashboard session — older notification rows simply keep an empty `read_at` |

Two things an operator should know about these files:

1. `migrations/env.py:27` exists because the mobile tables live in a separate module. That
   comment used to say "nine extra tables" when `src/watchtower/mobile/models.py` defines ten
   and `tests/test_mobile_schema.py:22-33` names ten; it now says ten. The import itself is the
   load-bearing part — without it `alembic revision --autogenerate` silently omits the mobile
   schema — so `tests/test_mobile_schema.py` fails if a new process forgets the import.
2. `migrations/versions/__pycache__/3160ff941f72_personnel_mobile.cpython-314.pyc` is the
   compiled leftover of an earlier copy of the same migration carrying revision id
   `3160ff941f72` (same `down_revision` `0001_core_schema`, same create date), since renamed to
   `0002_personnel_mobile`. No `.py` file for that id exists. Consequence: a database stamped by
   the pre-rename file will report `3160ff941f72` from `alembic current`, and Alembic will not
   find that revision in `versions/`. If that happens, stamping the correct id is a deliberate
   operator decision, not something to guess at.

### What is written versus what is applied

On **2026-11-02** the project's Neon database was inspected and found at
`0002_personnel_mobile`, one revision behind this checkout. `users.must_change_password` and
`notifications.read_at` were absent, so the mobile API's first user query — which names
`must_change_password` — raised `UndefinedColumn` and every login would have returned a 500.
`python -m watchtower.cli migrate` was run and the database is now at
`0003_personnel_columns`; 30 tables are present (the 29 mapped ones plus `alembic_version`),
one account (`afit_admin`, `must_change_password = false`), and `cameras`, `incidents`,
`evidence_assets`, `mobile_devices` and `notification_outbox` are all empty. That is a point-in-time
observation, not a permanent fact: an environment can drift from this checkout again, which is
what the check below is for.

```bash
PYTHONPATH=src python -m watchtower.cli check-schema   # reachable AND at this checkout's head?
PYTHONPATH=src python -m watchtower.cli migrate        # applies 0001 -> 0002 -> 0003
python -m alembic current                               # same answer, read-only
```

`check-schema` connects, reads the revision and compares it to the head of the migration
scripts. It exits non-zero when the database has no schema, when the scripts have more than one
head (a branched history cannot be compared to one revision, so it says so rather than guessing),
and when the database revision is not the scripts' head — with the message
`the code in this checkout needs <head>`. It previously printed the found revision and exited 0
regardless, which is how a schema-one-revision-behind deployment passes its own health check and
then fails at runtime on the first query naming a column the missing revision adds.
`tests/test_mobile_schema.py` keeps the history single-headed so that comparison can never be
meaningless.

Because the cloud service uses the same database, applying migrations once is enough for both;
there is no separate cloud schema to upgrade. If the cloud runs against a distinct connection
string (`CLOUD_DATABASE_URL`), verify its revision separately — the guard at
`src/watchtower/cloud/config.py:169` checks the scheme, not the revision.

## 11. Retention and integrity

### Evidence expiry

| Concern | Column | Where it is set |
|---|---|---|
| Expiry | `evidence_assets.expires_at` | `captured_at + <n> days` at write time (`src/watchtower/services/evidence.py:99`, `:141`); `n` is `WATCHTOWER_EVIDENCE_RETENTION_DAYS`, default 90 (`src/watchtower/config.py:209`), overridable per write through the `retention_days` argument (`services/evidence.py:73-81`) |
| Retirement | `evidence_assets.deleted_at` | `EvidenceStore.purge_expired()` selects `expires_at IS NOT NULL AND expires_at <= now AND deleted_at IS NULL`, unlinks the file and stamps `deleted_at` (`src/watchtower/services/evidence.py:184-199`) |
| Row retention | `evidence_assets` (the row itself) | never deleted by the retention path; the row stays as the record that the asset existed and when it went, which is what keeps the chain of custody intact for an incident whose footage has aged out |

`expires_at` and `deleted_at` are the only retention columns in the schema. There is no
retention column on `camera_health_events`, `audit_logs`, `detection_events` or `incidents`, and
no setting for health or audit retention exists in `src/watchtower/config.py` — those tables
grow until an operator deletes rows.

Purging is not automatic. `python -m watchtower.cli purge` is "intended for a scheduled
invocation, not a silent background job" (`src/watchtower/cli/main.py:159-170`), and nothing in
the application calls `purge_expired()` on a timer. A deployment with no scheduler keeps expired
evidence indefinitely.

Cloud-side expiry is display-only: an asset with `deleted_at` set is treated as gone
(`src/watchtower/cloud/routers/evidence.py:107-108`), and `expires_at` is reported to the phone
(`src/watchtower/cloud/routers/evidence.py:263`).

### The integrity digest

`evidence_assets.sha256` (`src/watchtower/models.py:625`) is a lowercase hex SHA-256 of the
bytes, computed when they are written (`src/watchtower/services/evidence.py:97`) or taken from
the candidate snapshot when a row is adopted (`src/watchtower/services/evidence.py:119,139`). It
is checked on every read:

- monitoring side, before the file is served: `src/watchtower/services/evidence.py:168`, raising
  `IntegrityMismatch`
- cloud side, before serving: `src/watchtower/cloud/routers/evidence.py:196-197`
- on relay, both against the declared digest
  (`src/watchtower/cloud/routers/ingest.py:270-273`) and against the stored file after writing
  (`src/watchtower/cloud/routers/ingest.py:333-342`), recorded as `expected_sha256` /
  `received_sha256` on `evidence_relay_states`

Two further hashes in the schema, neither of them a credential: `refresh_tokens.token_hash`
(SHA-256 of a refresh token, `src/watchtower/cloud/tokens.py:54-55`) and
`mobile_devices.push_token_fingerprint` (first 12 hex characters of the SHA-256 of the FCM token,
`src/watchtower/security/secrets.py:231-233`, stored in a `varchar(16)` column).

### How a sealed secret is stored

`SecretStore.seal()` (`src/watchtower/security/secrets.py:115-123`) encrypts the plaintext with
the **active** Fernet key from a file-backed key ring and returns an opaque reference, the
ciphertext, the key id and the plaintext length. `persist()` writes the first three into
`camera_secrets` (`src/watchtower/security/secrets.py:125-133`).

| Piece | Column or file | Note |
|---|---|---|
| Encrypted value | `camera_secrets.ciphertext` (`bytea`) | a Fernet token; not reversible without the key |
| Key-ring reference | `camera_secrets.key_id` (`varchar(32)`) | the id of the key that can read it (an 8-hex-character token id, `src/watchtower/security/secrets.py:48`) |
| Handle used elsewhere | `camera_secrets.reference` (`varchar(64)`, unique) | what `camera_connection_profiles.secret_reference` points at; never the secret |
| The ring itself | `WATCHTOWER_SECRET_KEY_PATH`, default `./var/watchtower.key` (`src/watchtower/config.py:203`); `CLOUD_SECRET_KEY_PATH`, default `./var/cloud.key` (`src/watchtower/cloud/config.py:43`, `:215`) | JSON `{version, active_key_id, keys}` (`src/watchtower/security/secrets.py:49-53`), written with mode `0o600` — advisory on Windows (`src/watchtower/security/secrets.py:61-70`) |
| Rotation | `camera_secrets.rotated_at`, `key_id` | `SecretStore.replace()` re-seals with the active key and stamps `rotated_at` (`src/watchtower/security/secrets.py:150-155`) |

**No plaintext camera password is ever stored.** `cameras` and `camera_connection_profiles` hold
no password column and no credential-bearing URL (`src/watchtower/models.py:7-11`,
`src/watchtower/models.py:303-306`); the raw RTSP URL is accepted as input only, parsed and
discarded, so the credential reaches no log line, no API response and no column
(`src/watchtower/security/secrets.py:3-7`). `camera_connection_profiles.username` does hold the
camera username in plain text (`src/watchtower/models.py:314`) — the username is not treated as
the secret; the password is. Decrypting a secret is possible only with the ring file, so the
database and the ring must not be lost together: `reveal()` raises `SecretStoreError` with
"key ring mismatch" when the stored `key_id` is not in the ring
(`src/watchtower/security/secrets.py:143-148`).

**No plaintext FCM registration token is ever stored.** A token is a bearer capability to deliver
someone's security alerts to a device (`src/watchtower/mobile/models.py:15-17`), so
`mobile_devices` keeps `push_token_ciphertext` plus `push_token_key_id`, produced by the same
`SecretStore` the camera path uses (`src/watchtower/cloud/deps.py:49-51`), and a non-reversible
`push_token_fingerprint` that answers "did this token change?" without decrypting
(`src/watchtower/cloud/devices.py:159-183`). Revoking or invalidating a device nulls all three
columns — the secret is dropped, the history is kept
(`src/watchtower/cloud/devices.py:199-217`). A sealing failure is raised as a storage error
rather than stored in the clear (`src/watchtower/cloud/devices.py:166-176`).

Two related custody points: `users` stores `password_hash`, never a password; and
`audit_logs.details` is sanitised before it is written — any mapping key that names a credential
is replaced with `***` (`src/watchtower/security/audit.py:52-58,85`, using `key_is_secret` from
`src/watchtower/security/secrets.py:207-210`).

In production the cloud key ring is **not** created at boot: `create_if_missing=False`
(`src/watchtower/cloud/deps.py:32-36`), because silently minting a new key would strand every
stored FCM token and the operator would only learn from failed pushes.

## 12. How to inspect it

The project is a `src/` layout and is not packaged, so `PYTHONPATH=src` is required for every
`python -m watchtower.cli …` invocation. In Bash: `PYTHONPATH=src python -m watchtower.cli …`.
In Windows cmd: `set PYTHONPATH=src` in the same window first. Running from the project root is
also required — the CLI looks for `alembic.ini` relative to the repository and exits with
`cannot find …; run the CLI from the project root.` otherwise
(`src/watchtower/cli/main.py:31-37`).

The subcommands that exist are exactly these (`src/watchtower/cli/main.py:191-234`):

| Command | What it does | Source |
|---|---|---|
| `python -m watchtower.cli migrate` | `alembic upgrade head` through `migrations/env.py`, then prints the resulting revision. Loads settings first, so a bad configuration fails before any DDL | `cli/main.py:45` |
| `python -m watchtower.cli check-schema` | `SELECT 1`, the current Alembic revision, and a comparison against the migration scripts' head. Prints `connected; alembic revision = <rev> (matches this checkout)`; exits 1 for no schema, a behind database, or a branched script history | `cli/main.py:63` |
| `python -m watchtower.cli bootstrap` | seeds roles, permissions and grants, then creates the first `system_administrator`; stops if users exist unless `--force` | `cli/main.py:79` |
| `python -m watchtower.cli serve` | runs the console and API (`--host`, `--port`, `--trusted-proxy`, `--no-analysis`) | `cli/main.py:135` |
| `python -m watchtower.cli purge` | applies evidence retention, prints how many assets were retired | `cli/main.py:159` |
| `python -m watchtower.cli secret-key` | creates the key ring, or rotates the active key with `--force` | `cli/main.py:173` |

There is no `python -m watchtower.cli` command that inspects rows, dumps the schema or applies
health/audit retention; those do not exist in `cli/main.py`.

A global `--env-file <path>` may precede the subcommand to load `KEY=VALUE` pairs first
(`src/watchtower/cli/main.py:193-196,237-243`). Nothing in this CLI executes at application
import time, so a stray process start cannot alter access control or create accounts
(`src/watchtower/cli/main.py:3-6`).

Alembic itself, without the wrapper (`alembic.ini` puts `src/` on the path via
`prepend_sys_path`, so `PYTHONPATH` is not needed for these):

| Command | What it does |
|---|---|
| `python -m alembic current` | the revision recorded in the live database's `alembic_version` table |
| `python -m alembic history` | the revision chain in `migrations/versions/`; opens no database connection |
| `python -m alembic heads` | the head revision; currently one, `0003_personnel_columns` |
| `python -m alembic upgrade head --sql` | the DDL, printed offline for review without touching a server |

Schema guards that run as tests rather than as commands:

| Command | What it checks |
|---|---|
| `python -m pytest tests/test_mobile_schema.py` | the mobile tables are attached to the shared `Base`, that no core table is forked by a second class, that the unique constraints reject a duplicate, and that a push token is never stored in the clear |
| `python var/schema_parity.py` | a repository scratch script comparing the offline migration DDL against what `models.py` declares; not a supported command and not part of the CLI |

`alembic_version` is a 30th table in the database. Alembic creates and owns it; no model in this
repository maps it, and nothing in the application reads it except
`migration.MigrationContext.get_current_revision()` (`src/watchtower/cli/main.py:40-42`).

## 13. Unknowns

Stated rather than guessed:

- What the live Neon database holds **now**. It was at `0002` and migrated to `0003` on
  2026-11-02 (section 10); after that date it is whatever the next deployment leaves it at, so
  re-run `check-schema` rather than assuming.
- Whether any column in the deployed database differs from the models. `0002` was autogenerated
  and hand-cleaned (its docstring says so); a fresh `alembic revision --autogenerate`, reviewed
  without applying, is the only way to know.
- The vocabulary of several unchecked string columns is known only from what the code writes:
  `cameras.desired_state`, `camera_stream_sessions.state`,
  `camera_health_events.status` / `previous_status`,
  `camera_connection_profiles.last_probe_result`, `evidence_assets.kind`, `notifications.kind`,
  `incident_actions.action`, `incident_acknowledgements.source`, `audit_logs.action` /
  `outcome`, `mobile_devices.push_provider`. The database enforces no constraint on any of them,
  so a stray value would be accepted.
