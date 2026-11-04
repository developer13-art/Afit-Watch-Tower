/**
 * Contract types for the cloud API.
 *
 * This file is transcribed from the *running service* (`src/watchtower/cloud/routers/*` and
 * `cloud/views.py`), not from a design document. Where the two disagreed, the router won: the
 * app is a client, and a client that matches a stale spec fails at runtime in ways no type
 * checker can see. Each block names the route that produces it.
 *
 * Two rules the backend holds to and this file therefore mirrors:
 *   - Response bodies carry API vocabularies, never UI labels. Labels live in `lib/severity.ts`.
 *   - Timestamps are RFC 3339 with an explicit offset, so `string | null` is the whole truth.
 */

// ---------------------------------------------------------------- vocabulary

/** `models.Severity` — the only four values the server accepts or emits. */
export type Severity = 'low' | 'medium' | 'high' | 'critical';

/** `models.IncidentStatus` — six states, not four; `assigned` and `false_positive` are real. */
export type IncidentStatus =
  | 'open'
  | 'investigating'
  | 'assigned'
  | 'resolved'
  | 'closed'
  | 'false_positive';

/** `detection_source_for()` answers with one of these two, always. */
export type DetectionSource = 'ai_candidate' | 'manual';

/** `models.NotificationState` — the alert row's own state. */
export type NotificationState =
  | 'pending'
  | 'delivered'
  | 'read'
  | 'acknowledged'
  | 'failed'
  | 'suppressed';

/** `storage.asset_state()` — the five values the evidence panel must explain separately. */
export type EvidenceState = 'available' | 'processing' | 'expired' | 'deleted' | 'unavailable';

export type EvidenceKind = 'snapshot' | 'clip' | (string & {});

/** `devices.PLATFORMS`. */
export type DevicePlatform = 'android' | 'ios' | 'web' | (string & {});

/** `mobile.models.PushState`: active | invalid | revoked (plus whatever the registry adds). */
export type PushState = 'active' | 'invalid' | 'revoked' | (string & {});

/** `profile.KNOWN_KINDS` — the only kinds the preferences endpoint will accept. */
export type NotificationKind =
  | 'incident.created'
  | 'incident.assigned'
  | 'incident.escalated'
  | 'incident.resolved'
  | 'camera.health'
  | 'event.new'
  | (string & {});

// ---------------------------------------------------------------- errors

export interface ApiErrorBody {
  error: {
    code: string;
    message: string;
    request_id?: string;
  };
}

/**
 * Error codes, keyed by the string the service puts in the envelope.
 *
 * These are the `CloudError(...)` codes from `src/watchtower/cloud/**`, and the key names match
 * the values deliberately: a client that checks for `refresh_token_reused` when the server sends
 * `refresh_reused` silently stops treating a replayed token as the emergency it is.
 *
 * The four `NETWORK_*` / `INVALID_RESPONSE` / `UNKNOWN` codes below are the app's own — the
 * service cannot send them because they describe a request that never completed.
 */
export const ERROR_CODES = {
  // auth & sessions
  INVALID_CREDENTIALS: 'invalid_credentials',
  ACCOUNT_LOCKED: 'account_locked',
  PASSWORD_CHANGE_REQUIRED: 'password_change_required',
  CURRENT_PASSWORD_INCORRECT: 'current_password_incorrect',
  INVALID_REFRESH: 'invalid_refresh',
  REFRESH_REUSED: 'refresh_reused',
  REFRESH_EXPIRED: 'refresh_expired',
  SESSION_REVOKED: 'session_revoked',
  ACCESS_EXPIRED: 'access_expired',
  INVALID_TOKEN: 'invalid_token',
  // generic HTTP-shaped refusals
  AUTHENTICATION_REQUIRED: 'authentication_required',
  FORBIDDEN: 'forbidden',
  NOT_FOUND: 'not_found',
  VALIDATION_FAILED: 'validation_failed',
  INVALID_JSON: 'invalid_json',
  RATE_LIMITED: 'rate_limited',
  TOO_MANY_LOGIN_ATTEMPTS: 'too_many_login_attempts',
  TOO_MANY_REFRESH_ATTEMPTS: 'too_many_refresh_attempts',
  TOO_MANY_PASSWORD_ATTEMPTS: 'too_many_password_attempts',
  TOO_MANY_ACTIONS: 'too_many_actions',
  /**
   * `errors._FRAMEWORK_CODES` gives these names to refusals the framework raises before a route
   * body runs, so a 415 from Starlette reads the same as a deliberate one. They are only ever
   * reachable by a malformed request, never by a valid one.
   */
  INVALID_REQUEST: 'invalid_request',
  METHOD_NOT_ALLOWED: 'method_not_allowed',
  REQUEST_TIMEOUT: 'request_timeout',
  PAYLOAD_TOO_LARGE: 'payload_too_large',
  CONTENT_TYPE_UNSUPPORTED: 'content_type_unsupported',
  INTERNAL_ERROR: 'internal_error',
  STORAGE_UNAVAILABLE: 'storage_unavailable',
  // incidents
  INCIDENT_NOT_ACTIONABLE: 'incident_not_actionable',
  INCIDENT_UNAVAILABLE: 'incident_unavailable',
  /**
   * `already_resolved` and `invalid_state` are listed by `routers/incidents.py::_fail()` as codes
   * it will translate to 409, but no service method raises either one today — a second `resolve`
   * is accepted and rewrites the outcome. They stay in the vocabulary because the mapping is the
   * contract; nothing in this app depends on receiving them.
   */
  ALREADY_RESOLVED: 'already_resolved',
  NOT_RESOLVED: 'not_resolved',
  INVALID_STATE: 'invalid_state',
  INVALID_DECISION: 'invalid_decision',
  NOTE_REQUIRED: 'note_required',
  ESCALATION_TARGET_UNAVAILABLE: 'escalation_target_unavailable',
  UNKNOWN_ROLE: 'unknown_role',
  ROLE_REQUIRED: 'role_required',
  STATUS_INVALID: 'status_invalid',
  SEVERITY_INVALID: 'severity_invalid',
  CAMERA_ID_INVALID: 'camera_id_invalid',
  CURSOR_INVALID: 'cursor_invalid',
  // devices
  INSTALLATION_ID_REQUIRED: 'installation_id_required',
  INSTALLATION_ID_INVALID: 'installation_id_invalid',
  PLATFORM_UNSUPPORTED: 'platform_unsupported',
  PUSH_TOKEN_REQUIRED: 'push_token_required',
  SELF_DEACTIVATION: 'self_deactivation',
  // evidence
  EVIDENCE_EXPIRED: 'evidence_expired',
  EVIDENCE_UNAVAILABLE: 'evidence_unavailable',
  EVIDENCE_TOKEN_INVALID: 'evidence_token_invalid',
  EVIDENCE_TOKEN_EXPIRED: 'evidence_token_expired',
  EVIDENCE_TYPE_UNSUPPORTED: 'evidence_type_unsupported',
  EVIDENCE_INTEGRITY_FAILED: 'evidence_integrity_failed',
  RANGE_INVALID: 'range_invalid',
  RANGE_UNSATISFIABLE: 'range_unsatisfiable',
  TOO_MANY_EVIDENCE_READS: 'too_many_evidence_reads',
  // client-side only — never sent by the server
  NETWORK_OFFLINE: 'network_offline',
  NETWORK_TIMEOUT: 'network_timeout',
  INVALID_RESPONSE: 'invalid_response',
  UNKNOWN: 'unknown_error',
} as const;

export type KnownErrorCode = (typeof ERROR_CODES)[keyof typeof ERROR_CODES];

// ---------------------------------------------------------------- auth  (POST /auth/login, /auth/refresh, /auth/me)

export interface DeviceDescriptor {
  installation_id: string;
  platform: DevicePlatform;
  push_token?: string | null;
  model?: string;
  os_version?: string;
  app_version?: string;
}

export interface LoginRequest {
  username: string;
  password: string;
  device?: DeviceDescriptor;
}

/** `views.user_view()` — `/auth/me` returns exactly this, and nothing else. */
export interface UserPermissions {
  id: number;
  username: string;
  display_name: string;
  email: string | null;
  phone: string | null;
  roles: string[];
  permissions: string[];
  is_active: boolean;
  must_change_password: boolean;
  last_login_at: string | null;
  camera_scope: CameraScope;
}

/**
 * `views._scope()`: `"all"` means institution-wide, an array of camera-group ids means the
 * caller sees only those groups. The server treats `incident.view` and `evidence.view` as
 * separate scopes, so the app must not assume one implies the other.
 */
export type GroupScope = 'all' | number[];

export interface CameraScope {
  'incident.view': GroupScope;
  'evidence.view': GroupScope;
}

export interface TokenPair {
  access_token: string;
  token_type: 'Bearer';
  expires_in: number;
  refresh_token: string;
  refresh_expires_in: number;
}

export interface LoginResponse extends TokenPair {
  user: UserPermissions;
}

/** POST /auth/refresh — the login shape minus `user`. */
export type RefreshResponse = TokenPair;

/** GET /auth/me. */
export type AuthMeResponse = UserPermissions;

/** POST /auth/logout. `device_forgotten` is false when no `x-installation-id` header was sent. */
export interface LogoutResponse {
  signed_out: boolean;
  device_forgotten: boolean;
}

/** POST /auth/password. */
export interface PasswordChangeResponse {
  changed?: boolean;
  sessions_revoked?: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------- devices  (/devices)

/** POST /devices body — `DeviceBody`. `push_provider` is required by the model. */
export interface DeviceRegistrationRequest extends DeviceDescriptor {
  push_provider: 'fcm' | (string & {});
}

/** POST /devices response. */
export interface DeviceRegistrationResponse {
  id: number;
  installation_id: string;
  platform: DevicePlatform;
  push_provider: string;
  push_state: PushState;
  installed_at: string;
  last_seen_at: string;
  token_changed: boolean;
}

/**
 * GET /devices items — `devices.DeviceView`. Note `registered_at`, not `installed_at`, and that
 * the push token itself is never returned: `push_capable` is the answer to "can this handset be
 * paged?" without exposing a bearer capability to a screen-share.
 */
export interface DeviceListItem {
  id: number;
  installation_id: string;
  platform: DevicePlatform;
  model: string | null;
  os_version: string | null;
  app_version: string | null;
  push_state: PushState;
  push_capable: boolean;
  registered_at: string;
  last_seen_at: string;
}

export interface DeviceListResponse {
  items: DeviceListItem[];
}

/** DELETE /devices/{installation_id}. Revokes the sessions minted from that handset. */
export interface DeviceForgetResponse {
  deactivated: boolean;
  sessions_revoked: number;
}

/** POST /devices/{installation_id}/push-token — FCM rotated the token mid-session. */
export interface PushTokenRotationResponse {
  id: number;
  push_state: PushState;
  token_changed: boolean;
}

// ---------------------------------------------------------------- dashboard  (GET /dashboard/summary)

export interface DashboardSummary {
  generated_at: string;
  incidents: {
    active: number;
    awaiting_acknowledgement: number;
    critical_open: number;
    high_open: number;
    acknowledged_last_24h: number;
    resolved_last_24h: number;
  };
  notifications: {
    unread: number;
    failed_delivery: number;
  };
  delivery: {
    outbox_pending: number;
    outbox_failed: number;
    last_successful_push_at: string | null;
    active_devices: number;
  };
  personnel: {
    display_name: string | null;
    roles: string[];
    permissions: string[];
  };
}

// ---------------------------------------------------------------- notifications  (/notifications)

/** `views.notification_view()`. `deep_link` is present only when the alert names an incident. */
export interface NotificationItem {
  id: number;
  kind: NotificationKind;
  title: string;
  body: string;
  severity: Severity;
  state: NotificationState;
  read_at: string | null;
  acknowledged_at: string | null;
  delivered_at: string | null;
  created_at: string;
  incident_id: number | null;
  incident_reference: string | null;
  camera_id: string | null;
  camera_name: string | null;
  campus_location: string | null;
  /** Set only while `state === 'failed'`; the server withholds it otherwise. */
  failure_reason: string | null;
  deep_link?: string;
}

export interface NotificationListResponse {
  items: NotificationItem[];
  next_cursor: string | null;
  total_unread: number;
}

/** GET /notifications query. `from`/`to` are the server's names (with `alias="from"`). */
export interface NotificationListQuery {
  unread_only?: boolean;
  severity?: Severity[];
  from?: string;
  to?: string;
  kind?: NotificationKind;
  cursor?: string;
  limit?: number;
}

/** POST /notifications/{id}/read — `unchanged: true` when the row was never unread. */
export interface MarkReadResponse {
  id: number;
  state: NotificationState;
  read_at: string | null;
  unchanged?: boolean;
}

/** POST /notifications/read-all. */
export interface MarkAllReadResponse {
  marked_read: number;
}

/** POST /notifications/{id}/open — per-attempt telemetry, not a state change. */
export interface OpenReportResponse {
  id: number;
  attempts_marked_open: number;
  opened_at: string;
}

// ---------------------------------------------------------------- incidents  (/incidents)

/** `views.camera_brief()` spread into every incident body. */
export interface CameraBrief {
  camera_id: string | null;
  camera_name: string | null;
  campus_location: string | null;
}

/** `incidents._evidence_brief()` — an id and a coarse state, no signed link. */
export interface IncidentEvidenceRef {
  id: number;
  kind: EvidenceKind;
  content_type: string;
  state: 'available' | 'deleted';
}

/** `views.incident_summary()` + `detection_fields()`, plus the list endpoint's `evidence`. */
export interface IncidentSummary extends CameraBrief {
  id: number;
  reference: string;
  title: string;
  category: string;
  severity: Severity;
  status: IncidentStatus;
  occurred_at: string;
  created_at: string;
  /** A user id, not an object: names come from the activity/acknowledgement lists. */
  assigned_to: number | null;
  /** Also a user id — who the incident was escalated *to*, not a role name. */
  escalated_to: number | null;
  /**
   * Resolved display names for the two ids above, added by `actor_name_fields()` in one query
   * for the whole page. Without them a phone would show `assigned_to: 7`, which tells a duty
   * officer nothing they can act on.
   */
  assigned_to_name: string | null;
  escalated_to_name: string | null;
  /** `detection_fields()`; the list endpoint sends it too, so the queue can label a candidate. */
  detection_source: DetectionSource;
  confidence: number | null;
  evidence?: IncidentEvidenceRef[];
}

/** `incidents._acknowledgements()`. */
export interface IncidentAcknowledgement {
  user_id: number;
  display_name: string | null;
  source: string;
  note: string | null;
  acknowledged_at: string;
}

/** `incidents.activity()` items — `actor_name`, not `actor_display_name`, and no nested actor. */
export interface IncidentActivityEntry {
  id: number;
  action: string;
  note: string | null;
  actor_id: number | null;
  actor_name: string | null;
  created_at: string;
}

/** `views.incident_detail()` + `_full()`'s additions. */
export interface IncidentDetail extends IncidentSummary {
  summary: string | null;
  resolution: string | null;
  outcome: string | null;
  resolved_at: string | null;
  updated_at: string | null;
  origin_event_id: number | null;
  acknowledgements: IncidentAcknowledgement[];
  /** The first acknowledger's user id, or null. Not an object. */
  acknowledged_by: number | null;
}

export interface IncidentListResponse {
  items: IncidentSummary[];
  next_cursor: string | null;
}

/**
 * GET /incidents query. The date filters are `since`/`until` here — the notifications endpoint
 * uses `from`/`to`, so the two must not share a query-builder helper.
 */
export interface IncidentListQuery {
  status?: IncidentStatus[];
  severity?: Severity[];
  category?: string;
  camera_id?: string;
  location?: string;
  q?: string;
  since?: string;
  until?: string;
  cursor?: string;
  limit?: number;
}

export interface ActivityListResponse {
  items: IncidentActivityEntry[];
  next_cursor: string | null;
}

/**
 * `delivery.EnqueueReport.as_dict()`, attached by the four actions that page other people
 * (`escalate`, `assign`, `resolve`, `reopen`). It counts notifications, not deliveries: FCM has
 * not answered yet when this response is written.
 */
export interface IncidentActionNotifications {
  notifications_created: number;
  notifications_suppressed: number;
  duplicate_recipients: number;
  devices_targeted: number;
  suppression_reasons: Record<string, number>;
}

/**
 * Every successful action route answers with the full incident; acknowledge adds the flag, and
 * the actions that page someone add `notifications`. The app reads the incident and does not
 * render `notifications` yet — it is typed here because the route sends it, and a client that
 * ignores a field should at least know it exists.
 */
export type IncidentActionResponse = IncidentDetail & {
  already_acknowledged?: boolean;
  notifications?: IncidentActionNotifications;
};

/** `ResolveBody.outcome` is a free string (3–64); the console's vocabulary, not an enum. */
export type IncidentOutcome = string;

export interface ResolveRequest {
  outcome: IncidentOutcome;
  resolution: string;
  false_positive?: boolean;
}

/** `EscalateBody` — `reason` is required and becomes the activity note; there is no `note`. */
export interface EscalateRequest {
  reason: string;
  to_user_id?: number;
  to_role?: string;
}

/** `AssignBody` — one field. */
export interface AssignRequest {
  user_id: number;
}

/** `NoteBody`, shared by /acknowledge, /investigating and /notes. */
export interface NoteRequest {
  note?: string;
}

/** `ReopenBody` — `reason` only. */
export interface ReopenRequest {
  reason: string;
}

/** GET /incidents/{id}/preferences-check — "would this account have been paged?" */
export interface PreferencesCheckResponse {
  incident_id: number;
  severity: Severity;
  acknowledgements: number;
  /** Null when the account has never saved a preference, which is not the same as `low`. */
  min_severity: Severity | null;
  /** True only when quiet hours are switched on *and* the window covers this instant in UTC. */
  quiet_hours: boolean;
}

// ---------------------------------------------------------------- evidence  (/incidents/{id}/evidence)

/**
 * One item of GET /incidents/{id}/evidence.
 *
 * Two expiries and conflating them is a bug: `expires_at` is the asset's retention date, while
 * `expires_at_token` is when the signed link in `url` stops working. Only the second one means
 * "Refetch links".
 */
export interface EvidenceAsset {
  id: number;
  kind: EvidenceKind;
  content_type: string;
  byte_size: number | null;
  captured_at: string | null;
  expires_at: string | null;
  state: EvidenceState;
  sha256: string | null;
  /** Present only when `state === 'available'`; a single-asset signed link. */
  url: string | null;
  expires_at_token: string | null;
}

export interface EvidenceListResponse {
  items: EvidenceAsset[];
  incident_id: number;
  reference: string;
}

/** GET /evidence/{asset_id} — metadata only, no link. */
export interface EvidenceMetadata {
  id: number;
  kind: EvidenceKind;
  content_type: string;
  byte_size: number | null;
  sha256: string | null;
  captured_at: string | null;
  expires_at: string | null;
  state: EvidenceState;
  incident_id: number | null;
  camera_id: string | null;
}

// ---------------------------------------------------------------- profile  (/profile)

/** `profile._roles()` item. */
export interface RoleDescription {
  code: string;
  name: string;
  description: string | null;
}

/** GET /profile — `user_view` plus three additions. `roles` stays a string array. */
export interface ProfileResponse extends UserPermissions {
  roles_with_descriptions: RoleDescription[];
  devices: DeviceListItem[];
  preferences: NotificationPreferencesResponse;
}

export interface QuietHours {
  enabled: boolean;
  /**
   * `HH:MM`, compared against the delivery worker's clock — `targeting.resolve_recipients()`
   * evaluates the window at `datetime.now(UTC)`, not at the handset's zone. A station in Kaduna
   * (UTC+1) therefore has to enter times one hour later than the local hours it means, and the
   * settings screen says so on the face of the form.
   */
  start: string;
  end: string;
}

/** `profile._preference_body()` — the writable part… */
export interface NotificationPreferences {
  min_severity: Severity;
  kinds: Record<string, boolean>;
  quiet_hours: QuietHours;
  /** `profile.SOUNDS`. There is no `vibrate`: silence is a sound choice, not a haptics flag. */
  sound: 'default' | 'alarm' | 'silent' | (string & {});
}

/** …plus the two fields the server adds. `forced` is the list the UI must grey out. */
export interface NotificationPreferencesResponse extends NotificationPreferences {
  forced: string[];
  updated_at: string | null;
}

/** PUT /profile/preferences accepts the writable part only. */
export type UpdatePreferencesRequest = NotificationPreferences;

// ---------------------------------------------------------------- live channel  (/events/stream)

/**
 * `ready` — the frame that proves the connection is genuinely open, and the cursor a reconnect
 * resumes from. `poll_seconds` is the server's own read cadence; it is shown, not used to time
 * anything on this side.
 */
export interface LiveReadyFrame {
  cursor: string;
  poll_seconds: number;
  heartbeat_seconds: number;
  server_time: string;
}

export interface LiveHeartbeatFrame {
  cursor: string;
  server_time: string;
}

/**
 * `closing` — the server ended the stream. `lifetime` is scheduled (the service caps a
 * connection below its own access-token TTL, so reconnecting re-checks permissions);
 * `database_unavailable` is not, and the app should fall back to its poll cadence.
 */
export interface LiveClosingFrame {
  reason: 'lifetime' | 'database_unavailable' | (string & {});
  cursor: string;
  server_time: string;
}

/** `notification` — the same body `GET /notifications` returns for the same row. */
export type LiveNotificationFrame = NotificationItem;

/**
 * `incident_activity` — one row of an incident's timeline, addressed by id because the handset
 * may be looking at that incident, at a list, or at nothing at all.
 */
export interface LiveActivityFrame extends IncidentActivityEntry {
  incident_id: number;
  incident_reference: string;
  incident_status: IncidentStatus;
  incident_severity: Severity;
}

/**
 * Every frame carries in its SSE `id:` line the cursor *after* the row it describes, which is what
 * a reconnect sends back as `?since=`. The data bodies do not repeat it.
 */
export interface LiveFrameOf<TName extends LiveEventName, TData> {
  name: TName;
  id: string;
  data: TData;
}

export type LiveEventName = 'ready' | 'notification' | 'incident_activity' | 'heartbeat' | 'closing';

export type LiveFrame =
  | LiveFrameOf<'ready', LiveReadyFrame>
  | LiveFrameOf<'notification', LiveNotificationFrame>
  | LiveFrameOf<'incident_activity', LiveActivityFrame>
  | LiveFrameOf<'heartbeat', LiveHeartbeatFrame>
  | LiveFrameOf<'closing', LiveClosingFrame>;

/** What the officer is told about the channel, in the words the shell uses. */
export type LiveStatus =
  | 'off'
  | 'connecting'
  | 'live'
  | 'reconnecting'
  | 'unavailable'
  | 'unsupported';


// ---------------------------------------------------------------- helpers

export interface OkResponse {
  ok?: boolean;
  [key: string]: unknown;
}
