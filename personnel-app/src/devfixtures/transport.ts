/**
 * Fixture transport — a fake `fetch` used only in DEV with VITE_USE_FIXTURES=1.
 *
 * It implements the contract's status codes, cursor pagination, filters and
 * conflict rules against the in-memory data in `./data.ts`, so fixture mode
 * exercises the same client code paths (refresh, error normalisation, 409
 * handling) as the real service. That is the point: a fixture screen that only
 * renders the happy path proves nothing.
 *
 * Bodies are the shapes the routers actually return — activity is a separate
 * paginated collection, an actor is a user id plus a resolved name, and a write
 * answers with the whole incident. A fixture that returned what the UI wants
 * rather than what the server sends would let a broken screen pass review.
 */
import type {
  ActivityListResponse,
  EvidenceListResponse,
  IncidentActionResponse,
  IncidentDetail,
  IncidentListResponse,
  IncidentSummary,
  LoginResponse,
  NotificationListResponse,
  QuietHours,
  RefreshResponse,
} from '../types/api';
import { ERROR_CODES } from '../types/api';
import { PREFERENCE_SOUNDS, SEVERITY_ORDER, STATUS_ORDER } from '../lib/severity';
import {
  fixtureActivity,
  fixtureDashboard,
  fixtureDevices,
  fixtureEvidence,
  fixtureIncidentDetails,
  fixtureNotifications,
  fixturePreferences,
  fixtureProfile,
  fixtureSiti,
  fixtureUser,
} from './data';

const LATENCY = 220;

/** Keys that `incident_summary()` does not carry; the list response strips them. */
const DETAIL_ONLY_KEYS = ['summary', 'resolution', 'outcome', 'resolved_at', 'updated_at', 'origin_event_id', 'acknowledgements', 'acknowledged_by'] as const;

function asSummary(detail: IncidentDetail): IncidentSummary {
  const copy: Record<string, unknown> = { ...detail };
  for (const key of DETAIL_ONLY_KEYS) delete copy[key];
  return copy as unknown as IncidentSummary;
}

/**
 * Fixture refresh tokens rotate exactly once, mirroring §2.2, so the reuse
 * path in `client.ts` can be demonstrated in DEV by replaying a token.
 */
let validFixtureRefresh = 'fixture-refresh-token-1';

function json<T>(data: T, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'x-request-id': `req_fixture_${Math.random().toString(16).slice(2, 8)}`,
      ...headers,
    },
  });
}

function envelope(code: string, message: string, status: number): Response {
  return json({ error: { code, message, request_id: `req_fixture_${Math.random().toString(16).slice(2, 8)}` } }, status);
}

/** Fixture credentials: `a.ahiya` / `watchtower` — documented in README. */
function checkLogin(body: { username?: string; password?: string }): Response {
  if (body?.username === 'locked' && body?.password === 'x') {
    return envelope(ERROR_CODES.ACCOUNT_LOCKED, 'Account locked for 5 minutes after repeated failures.', 401);
  }
  if (body?.username !== 'a.ahiya' || body?.password !== 'watchtower') {
    return envelope(ERROR_CODES.INVALID_CREDENTIALS, 'Username or password is incorrect.', 401);
  }
  const res: LoginResponse = {
    access_token: 'fixture.access.token',
    token_type: 'Bearer',
    expires_in: 900,
    refresh_token: 'fixture-refresh-token-login',
    refresh_expires_in: 2592000,
    user: fixtureUser,
  };
  validFixtureRefresh = res.refresh_token;
  return json(res);
}

function paginate<T extends { id: number; created_at?: string }>(
  rows: T[],
  params: URLSearchParams,
  defaultLimit: number,
): { items: T[]; next_cursor: string | null } {
  // The cursor is the opaque base64 JSON the route hands back; decoding it here is what makes
  // "load more" work in fixture mode, and a screen that ignores it would show only page one.
  let cursor = 0;
  const raw = params.get('cursor');
  if (raw) {
    try {
      const decoded = JSON.parse(atob(raw)) as { i?: number };
      cursor = typeof decoded.i === 'number' ? decoded.i : 0;
    } catch {
      cursor = 0;
    }
  }
  const limit = Math.min(Number(params.get('limit') ?? String(defaultLimit)) || defaultLimit, 100);
  const sorted = [...rows].sort((a, b) => b.id - a.id);
  const window = cursor > 0 ? sorted.filter((r) => r.id < cursor) : sorted;
  const slice = window.slice(0, limit);
  const last = slice[slice.length - 1];
  return {
    items: slice,
    next_cursor: slice.length === limit && last ? btoa(`{"i":${last.id}}`) : null,
  };
}

/**
 * `targeting.quiet_hours_active()`: an enabled switch alone is not a silence — the window has to
 * cover the present moment on the server's clock, which is UTC.
 */
function quietHoursActive(quiet: QuietHours, now: Date): boolean {
  if (!quiet.enabled) return false;
  const toMinutes = (value: string): number | null => {
    const parts = value.split(':');
    if (parts.length !== 2 || !parts.every((part) => /^\d+$/.test(part))) return null;
    const [hour, minute] = parts.map(Number);
    if (hour > 23 || minute > 59) return null;
    return hour * 60 + minute;
  };
  const start = toMinutes(quiet.start);
  const end = toMinutes(quiet.end);
  if (start === null || end === null) return false;
  const current = now.getUTCHours() * 60 + now.getUTCMinutes();
  return start <= end ? current >= start && current < end : current >= start || current < end;
}

/** `incidents._acknowledgements()` / `activity()` are appended, never replaced. */
function pushActivity(detail: IncidentDetail, action: string, note: string | null, at: string): void {
  const rows = fixtureActivity[detail.id] ?? [];
  rows.unshift({
    id: Date.now(),
    action,
    note,
    actor_id: fixtureUser.id,
    actor_name: fixtureUser.display_name,
    created_at: at,
  });
  fixtureActivity[detail.id] = rows;
}

export const fixtureFetch: typeof fetch = async (input, init) => {
  const url = new URL(typeof input === 'string' ? input : input.toString());
  const method = (init?.method ?? 'GET').toUpperCase();
  const path = url.pathname.replace(/^\/api\/v1/, '');
  const params = url.searchParams;
  const body = (() => {
    const raw = init?.body;
    if (typeof raw !== 'string') return {} as Record<string, unknown>;
    try {
      return JSON.parse(raw) as Record<string, unknown>;
    } catch {
      return {} as Record<string, unknown>;
    }
  })();

  await new Promise((r) => setTimeout(r, LATENCY));

  // -------------------------------------------------------------- auth (§2)
  if (method === 'POST' && path === '/auth/login') return checkLogin(body as never);

  if (method === 'POST' && path === '/auth/refresh') {
    if (body.refresh_token !== validFixtureRefresh) {
      return envelope(ERROR_CODES.REFRESH_REUSED, 'That refresh token was already rotated.', 401);
    }
    const res: RefreshResponse = {
      access_token: 'fixture.access.token.rotated',
      token_type: 'Bearer',
      expires_in: 900,
      refresh_token: `fixture-refresh-token-${Date.now()}`,
      refresh_expires_in: 2592000,
    };
    validFixtureRefresh = res.refresh_token;
    return json(res);
  }

  if (method === 'POST' && path === '/auth/logout') {
    // `device_forgotten` follows the real rule: it needs the installation id
    // header, and a header the client only sends once the device is registered.
    // `init.headers` is a plain object for every caller in this app, so reading
    // it only as a `Headers` would answer `device_forgotten: false` forever.
    const sent = init?.headers;
    const installationId =
      sent instanceof Headers
        ? sent.get('x-installation-id')
        : Array.isArray(sent)
          ? (sent.find(([name]) => name.toLowerCase() === 'x-installation-id')?.[1] ?? null)
          : ((sent as Record<string, string> | undefined)?.['x-installation-id'] ?? null);
    return json({ signed_out: true, device_forgotten: Boolean(installationId && body.forget_device) });
  }

  if (method === 'POST' && path === '/auth/password') {
    if (typeof body.new_password === 'string' && body.new_password.length < 12) {
      return envelope(ERROR_CODES.VALIDATION_FAILED, 'Minimum password length is 12 characters.', 422);
    }
    fixtureUser.must_change_password = false;
    return json({ changed: true, sessions_revoked: body.keep_other_sessions ? 0 : 3 });
  }

  if (method === 'GET' && path === '/auth/me') return json(fixtureUser);

  // -------------------------------------------------------------- devices (§3)
  if (method === 'POST' && path === '/devices') {
    const installationId = String(body.installation_id ?? '');
    const existing = fixtureDevices.find((d) => d.installation_id === installationId);
    if (!existing) return envelope(ERROR_CODES.NOT_FOUND, 'Fixture device list has no this installation.', 404);
    existing.push_state = 'active';
    existing.push_capable = Boolean(body.push_token);
    existing.last_seen_at = new Date().toISOString();
    return json({
      id: existing.id,
      installation_id: existing.installation_id,
      platform: existing.platform,
      push_provider: String(body.push_provider ?? 'fcm'),
      push_state: existing.push_state,
      installed_at: existing.registered_at,
      last_seen_at: existing.last_seen_at,
      token_changed: true,
    });
  }
  if (method === 'GET' && path === '/devices') return json({ items: fixtureDevices });

  const deviceDelete = /^\/devices\/([^/]+)$/.exec(path);
  if (method === 'DELETE' && deviceDelete) {
    const row = fixtureDevices.find((d) => d.installation_id === decodeURIComponent(deviceDelete[1]));
    if (!row) return envelope(ERROR_CODES.NOT_FOUND, 'No such device on this account.', 404);
    row.push_state = 'revoked';
    row.push_capable = false;
    return json({ deactivated: true, sessions_revoked: 2 });
  }

  const deviceRotate = /^\/devices\/([^/]+)\/push-token$/.exec(path);
  if (method === 'POST' && deviceRotate) {
    const row = fixtureDevices.find((d) => d.installation_id === decodeURIComponent(deviceRotate[1]));
    if (!row) return envelope(ERROR_CODES.NOT_FOUND, 'No such device on this account.', 404);
    if (!body.push_token) return envelope(ERROR_CODES.PUSH_TOKEN_REQUIRED, 'A token is required to rotate.', 422);
    row.push_state = 'active';
    row.push_capable = true;
    return json({ id: row.id, push_state: row.push_state, token_changed: true });
  }

  // -------------------------------------------------------------- dashboard (§4)
  if (method === 'GET' && path === '/dashboard/summary') return json(fixtureDashboard());

  // -------------------------------------------------------------- notifications (§5)
  if (method === 'GET' && path === '/notifications') {
    let rows = [...fixtureNotifications];
    if (params.get('unread_only') === 'true' || params.get('unread_only') === '1') rows = rows.filter((n) => !n.read_at);
    const severities = params.getAll('severity');
    if (severities.length) rows = rows.filter((n) => severities.includes(n.severity));
    const kind = params.get('kind');
    if (kind) rows = rows.filter((n) => n.kind === kind);
    const from = params.get('from');
    if (from) rows = rows.filter((n) => new Date(n.created_at) >= new Date(from));
    const to = params.get('to');
    if (to) rows = rows.filter((n) => new Date(n.created_at) <= new Date(to));
    const page = paginate(rows, params, 25);
    const res: NotificationListResponse = {
      ...page,
      total_unread: fixtureNotifications.filter((n) => !n.read_at).length,
    };
    return json(res);
  }

  const readMatch = /^\/notifications\/(\d+)\/read$/.exec(path);
  if (method === 'POST' && readMatch) {
    const row = fixtureNotifications.find((n) => n.id === Number(readMatch[1]));
    if (!row) return envelope(ERROR_CODES.NOT_FOUND, 'No such notification.', 404);
    const unchanged = row.read_at !== null;
    if (!unchanged) {
      row.state = 'read';
      row.read_at = new Date().toISOString();
    }
    return json({ id: row.id, state: row.state, read_at: row.read_at, unchanged });
  }

  if (method === 'POST' && path === '/notifications/read-all') {
    let marked = 0;
    for (const n of fixtureNotifications) {
      if (!n.read_at && (n.state === 'pending' || n.state === 'delivered')) {
        n.state = 'read';
        n.read_at = new Date().toISOString();
        marked += 1;
      }
    }
    return json({ marked_read: marked });
  }

  const openMatch = /^\/notifications\/(\d+)\/open$/.exec(path);
  if (method === 'POST' && openMatch) {
    const row = fixtureNotifications.find((n) => n.id === Number(openMatch[1]));
    if (!row) return envelope(ERROR_CODES.NOT_FOUND, 'No such notification.', 404);
    return json({ id: row.id, attempts_marked_open: 1, opened_at: new Date().toISOString() });
  }

  // -------------------------------------------------------------- incidents (§6)
  if (method === 'GET' && path === '/incidents') {
    let rows = Object.values(fixtureIncidentDetails);
    const statuses = params.getAll('status');
    // The route refuses a value outside `IncidentStatus` by name rather than filtering it out, so
    // a typo in a filter chip is a 422 the operator can see instead of an empty queue.
    for (const value of statuses) {
      if (!STATUS_ORDER.includes(value as never)) {
        return envelope(ERROR_CODES.STATUS_INVALID, `Unknown incident status '${value}'.`, 422);
      }
    }
    if (statuses.length) rows = rows.filter((i) => statuses.includes(i.status));
    const sev = params.getAll('severity');
    for (const value of sev) {
      if (!SEVERITY_ORDER.includes(value as never)) {
        return envelope(ERROR_CODES.SEVERITY_INVALID, `Unknown severity '${value}'.`, 422);
      }
    }
    if (sev.length) rows = rows.filter((i) => sev.includes(i.severity));
    const category = params.get('category');
    if (category) rows = rows.filter((i) => i.category === category);
    const cameraId = params.get('camera_id');
    if (cameraId) rows = rows.filter((i) => i.camera_id === cameraId);
    const location = params.get('location');
    if (location) rows = rows.filter((i) => (i.campus_location ?? '').toLowerCase().includes(location.toLowerCase()));
    const q = params.get('q');
    if (q) {
      const needle = q.toLowerCase();
      rows = rows.filter(
        (i) =>
          i.reference.toLowerCase().includes(needle) ||
          i.title.toLowerCase().includes(needle) ||
          (i.summary ?? '').toLowerCase().includes(needle),
      );
    }
    // The incidents route calls its date filters `since`/`until`; `from`/`to`
    // belong to notifications. Honouring both here would hide a wiring bug.
    const since = params.get('since');
    if (since) rows = rows.filter((i) => new Date(i.occurred_at) >= new Date(since));
    const until = params.get('until');
    if (until) rows = rows.filter((i) => new Date(i.occurred_at) <= new Date(until));
    const page = paginate(rows, params, 25);
    const res: IncidentListResponse = {
      items: page.items.map(asSummary),
      next_cursor: page.next_cursor,
    };
    return json(res);
  }

  const detailMatch = /^\/incidents\/(\d+)$/.exec(path);
  if (method === 'GET' && detailMatch) {
    const id = Number(detailMatch[1]);
    const detail = fixtureIncidentDetails[id];
    if (!detail) return envelope(ERROR_CODES.NOT_FOUND, 'Not found, or outside your assigned area.', 404);
    return json(detail);
  }

  const activityMatch = /^\/incidents\/(\d+)\/activity$/.exec(path);
  if (method === 'GET' && activityMatch) {
    const id = Number(activityMatch[1]);
    if (!fixtureIncidentDetails[id]) return envelope(ERROR_CODES.NOT_FOUND, 'Not found.', 404);
    // `ORDER BY id DESC` with a cursor below the last id, which is what the route does.
    const rows = [...(fixtureActivity[id] ?? [])].sort((a, b) => b.id - a.id);
    const page = paginate(rows, params, 50);
    return json<ActivityListResponse>({ items: page.items, next_cursor: page.next_cursor });
  }

  const evidenceMatch = /^\/incidents\/(\d+)\/evidence$/.exec(path);
  if (method === 'GET' && evidenceMatch) {
    const id = Number(evidenceMatch[1]);
    const detail = fixtureIncidentDetails[id];
    if (!detail) return envelope(ERROR_CODES.NOT_FOUND, 'Not found, or outside your assigned area.', 404);
    const res: EvidenceListResponse = { items: fixtureEvidence(id), incident_id: id, reference: detail.reference };
    return json(res);
  }

  const prefCheckMatch = /^\/incidents\/(\d+)\/preferences-check$/.exec(path);
  if (method === 'GET' && prefCheckMatch) {
    const detail = fixtureIncidentDetails[Number(prefCheckMatch[1])];
    if (!detail) return envelope(ERROR_CODES.NOT_FOUND, 'Not found.', 404);
    return json({
      incident_id: detail.id,
      severity: detail.severity,
      acknowledgements: detail.acknowledgements.length,
      min_severity: fixturePreferences.min_severity,
      quiet_hours: quietHoursActive(fixturePreferences.quiet_hours, new Date()),
    });
  }

  const actionMatch = /^\/incidents\/(\d+)\/(acknowledge|investigating|notes|escalate|assign|resolve|reopen)$/.exec(path);
  if (method === 'POST' && actionMatch) {
    const id = Number(actionMatch[1]);
    const action = actionMatch[2];
    const detail = fixtureIncidentDetails[id];
    if (!detail) return envelope(ERROR_CODES.NOT_FOUND, 'Not found, or outside your assigned area.', 404);
    const closed = detail.status === 'resolved' || detail.status === 'closed' || detail.status === 'false_positive';
    // `IncidentService.reopen()` accepts only `resolved` and `closed`, so a false positive is a
    // final decision from a handset exactly as it is from the console.
    const reopenable = detail.status === 'resolved' || detail.status === 'closed';
    if (action !== 'notes' && action !== 'reopen' && closed) {
      // §6.3 conflict rules, reproduced faithfully. `reopen` on an open incident
      // is the other half: the route refuses it with `not_resolved`.
      return envelope(ERROR_CODES.INCIDENT_NOT_ACTIONABLE, 'This incident is already closed.', 409);
    }
    if (action === 'reopen' && !reopenable) {
      return envelope(ERROR_CODES.NOT_RESOLVED, 'Only a resolved or closed incident can be reopened.', 409);
    }
    const ts = new Date().toISOString();
    // The route tests `body.note.strip()`, so a note of spaces alone is refused.
    const note = typeof body.note === 'string' && body.note.trim() ? body.note : null;
    const done = (): Response => json<IncidentActionResponse>({ ...detail });

    switch (action) {
      case 'acknowledge': {
        if (detail.acknowledged_by === fixtureUser.id) {
          return json<IncidentActionResponse>({ ...detail, already_acknowledged: true });
        }
        detail.acknowledged_by = fixtureUser.id;
        detail.acknowledgements = [
          ...detail.acknowledgements,
          {
            user_id: fixtureUser.id,
            display_name: fixtureUser.display_name,
            // `acknowledge` hardcodes the source; the console writes the same row with its own.
            source: 'mobile',
            note,
            acknowledged_at: ts,
          },
        ];
        if (detail.status === 'open') detail.status = 'investigating';
        // An acknowledgement with no owner yet claims the incident.
        if (detail.assigned_to === null) {
          detail.assigned_to = fixtureUser.id;
          detail.assigned_to_name = fixtureUser.display_name;
        }
        pushActivity(detail, 'acknowledged', note, ts);
        return json<IncidentActionResponse>({ ...detail, already_acknowledged: false });
      }
      case 'investigating': {
        if (detail.status === 'open') detail.status = 'investigating';
        pushActivity(detail, 'investigation_note', note, ts);
        return done();
      }
      case 'notes': {
        if (!note) return envelope(ERROR_CODES.NOTE_REQUIRED, 'A note requires text.', 422);
        pushActivity(detail, 'note', note, ts);
        return done();
      }
      case 'escalate': {
        const reason = typeof body.reason === 'string' ? body.reason : null;
        if (!reason) return envelope(ERROR_CODES.VALIDATION_FAILED, 'escalate requires a reason.', 422);
        // Only two people exist in the fixture. A role nobody holds answers the
        // way the service answers when the escalation ladder is empty, so the
        // 409 branch is reachable here and not merely described.
        const role = typeof body.to_role === 'string' ? body.to_role : 'security_supervisor';
        if (typeof body.to_user_id !== 'number' && role !== 'security_supervisor') {
          return envelope(ERROR_CODES.ESCALATION_TARGET_UNAVAILABLE, 'No one in that role can receive this escalation.', 409);
        }
        const target = fixtureSiti;
        detail.escalated_to = target.id;
        detail.escalated_to_name = target.display_name;
        pushActivity(detail, 'escalated', reason, ts);
        return done();
      }
      case 'assign': {
        const userId = typeof body.user_id === 'number' ? body.user_id : null;
        if (userId === null) return envelope(ERROR_CODES.VALIDATION_FAILED, 'assign requires a user_id.', 422);
        detail.assigned_to = userId;
        detail.assigned_to_name = userId === fixtureUser.id ? fixtureUser.display_name : fixtureSiti.display_name;
        if (detail.status === 'open') detail.status = 'assigned';
        pushActivity(detail, 'assigned', null, ts);
        return done();
      }
      case 'resolve': {
        if (typeof body.outcome !== 'string' || typeof body.resolution !== 'string') {
          return envelope(ERROR_CODES.VALIDATION_FAILED, 'resolve requires an outcome and a resolution.', 422);
        }
        // A resolve on an already-resolved incident is accepted, not refused: `resolve()` has no
        // terminal-state guard, so the newest wording wins and the shift is paged again.
        detail.status = body.false_positive === true ? 'false_positive' : 'resolved';
        detail.outcome = body.outcome;
        detail.resolution = body.resolution;
        detail.resolved_at = ts;
        pushActivity(detail, 'resolved', body.resolution, ts);
        return done();
      }
      case 'reopen': {
        if (typeof body.reason !== 'string') {
          return envelope(ERROR_CODES.VALIDATION_FAILED, 'reopen requires a reason.', 422);
        }
        // `reopen()` lands on `investigating` and clears the verdict; the earlier resolution
        // stays only in the history as the `resolved` action.
        detail.status = 'investigating';
        detail.resolved_at = null;
        detail.outcome = null;
        detail.resolution = null;
        pushActivity(detail, 'reopened', body.reason, ts);
        return done();
      }
      default:
        return envelope(ERROR_CODES.UNKNOWN, 'Unknown action.', 422);
    }
  }

  // -------------------------------------------------------------- profile (§8)
  if (method === 'GET' && path === '/profile') return json(fixtureProfile);
  if (method === 'GET' && path === '/profile/preferences') return json(fixturePreferences);
  if (method === 'PUT' && path === '/profile/preferences') {
    const forced = fixturePreferences.forced;
    const incoming = body as never as typeof fixturePreferences;
    // The same two vocabularies the profile router validates with Pydantic. A fixture that
    // accepted anything would let a screen ship a picker whose real answer is a 422.
    if (incoming.min_severity !== undefined && !SEVERITY_ORDER.includes(incoming.min_severity)) {
      return envelope(ERROR_CODES.VALIDATION_FAILED, `Unknown severity '${incoming.min_severity}'.`, 422);
    }
    if (incoming.sound !== undefined && !PREFERENCE_SOUNDS.includes(incoming.sound)) {
      return envelope(ERROR_CODES.VALIDATION_FAILED, `sound must be one of ${PREFERENCE_SOUNDS.join(', ')}.`, 422);
    }
    // §8.2: forced items cannot be switched off, so the store ignores them.
    const merged = { ...fixturePreferences, ...incoming, forced };
    for (const f of forced) {
      if (f === 'critical') merged.min_severity = 'critical';
      if (f.startsWith('incident.')) merged.kinds = { ...merged.kinds, [f]: true };
    }
    merged.updated_at = new Date().toISOString();
    Object.assign(fixturePreferences, merged);
    return json(fixturePreferences);
  }

  // -------------------------------------------------------------- evidence (§7)
  const assetMatch = /^\/evidence\/(\d+)$/.exec(path);
  if (method === 'GET' && assetMatch) {
    const assetId = Number(assetMatch[1]);
    for (const incidentId of Object.keys(fixtureIncidentDetails)) {
      const asset = fixtureEvidence(Number(incidentId)).find((a) => a.id === assetId);
      if (asset) {
        return json({
          id: asset.id,
          kind: asset.kind,
          content_type: asset.content_type,
          byte_size: asset.byte_size,
          sha256: asset.sha256,
          captured_at: asset.captured_at,
          expires_at: asset.expires_at,
          state: asset.state,
          incident_id: Number(incidentId),
          camera_id: fixtureIncidentDetails[Number(incidentId)].camera_id,
        });
      }
    }
    return envelope(ERROR_CODES.NOT_FOUND, 'No such evidence asset.', 404);
  }

  return envelope(ERROR_CODES.NOT_FOUND, `Fixture transport has no route for ${method} ${path}.`, 404);
};
