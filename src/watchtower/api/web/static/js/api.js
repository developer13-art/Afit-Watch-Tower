/**
 * AFIT WATCH TOWER - the single HTTP layer.
 *
 * Every request the console makes goes through `request()` below, which is also the only
 * place in the whole frontend that calls `fetch`. That matters because the backend rejects
 * any cookie-authenticated write that does not carry the dashboard header
 * (`X-Watchtower-Client: dashboard`) with 403 `csrf_check_failed`.
 *
 * It also normalises the two different error shapes the backend produces:
 *   * 401 from `current_principal` is a bare string detail ("session_expired",
 *     "invalid_credentials", "authentication_required");
 *   * everything else is {"code", "message", "field"}.
 */

export const CSRF_HEADER = 'X-Watchtower-Client';
export const CSRF_HEADER_VALUE = 'dashboard';
export const SESSION_NOTICE_KEY = 'watchtower.session_notice';

const LOGIN_PATH = '/api/auth/login';
const WRITE_METHODS = new Set(['POST', 'PATCH', 'PUT', 'DELETE']);

export class ApiError extends Error {
  constructor(status, code, message, field) {
    super(message || code || `Request failed (HTTP ${status}).`);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || `http_${status}`;
    this.message = message || this.message;
    this.field = field || null;
  }

  /** Operator-facing sentence; never a bare stack or generic "failed". */
  get display() {
    return this.message;
  }
}

/** Reads and clears the "why were you bounced to the login page" note. */
export function takeSessionNotice() {
  try {
    const value = sessionStorage.getItem(SESSION_NOTICE_KEY);
    if (value) sessionStorage.removeItem(SESSION_NOTICE_KEY);
    return value;
  } catch {
    return null;
  }
}

function rememberSessionNotice(text) {
  try {
    sessionStorage.setItem(SESSION_NOTICE_KEY, text);
  } catch {
    /* private mode: the redirect still works, only the explanation is lost */
  }
}

function onLoginPage() {
  return typeof window !== 'undefined' && window.location.pathname.startsWith('/login');
}

/**
 * A 401 means the cookie is missing, expired or revoked. The dashboard bounces to the login
 * page with an explanation; the login page itself keeps the 401 as a normal "bad password".
 */
function handleUnauthorized(error, { silent }) {
  if (silent || onLoginPage()) return;
  const expired = error.code === 'session_expired' || error.code === 'authentication_required';
  rememberSessionNotice(
    expired
      ? 'Your session expired. Sign in again to continue.'
      : 'You are signed out. Sign in again to continue.'
  );
  window.location.replace('/login');
}

function buildUrl(path, query) {
  const params = new URLSearchParams();
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      params.set(key, String(value));
    }
  }
  const qs = params.toString();
  return qs ? `${path}?${qs}` : path;
}

async function request(path, options = {}) {
  const {
    method = 'GET',
    body,
    query,
    signal,
    keepalive = false,
    silent = false,
    raw = false,
  } = options;

  const upper = method.toUpperCase();
  const headers = {};
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  // The backend only demands the header for cookie-authenticated writes, and sending it on
  // writes unconditionally is what keeps every one of them safe.
  if (WRITE_METHODS.has(upper)) headers[CSRF_HEADER] = CSRF_HEADER_VALUE;

  const init = {
    method: upper,
    headers,
    credentials: 'same-origin',
    // Only the live-session release on page unload asks for this, and it sends no body, so
    // the browser's keepalive body cap can never reject it.
    keepalive,
  };
  if (signal) init.signal = signal;
  if (body !== undefined) init.body = JSON.stringify(body);

  let response;
  try {
    response = await fetch(buildUrl(path, query), init);
  } catch (networkError) {
    if (networkError && networkError.name === 'AbortError') throw networkError;
    throw new ApiError(0, 'network_error', 'The WATCH TOWER server could not be reached.');
  }

  if (raw) {
    if (!response.ok) throw await toError(response);
    return response;
  }

  if (response.status === 204) return null;

  let payload = null;
  const text = await response.text();
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = null;
    }
  }

  if (!response.ok) {
    const error = errorFromPayload(response.status, payload);
    if (response.status === 401) handleUnauthorized(error, { silent });
    throw error;
  }

  if (payload === null && text) {
    throw new ApiError(response.status, 'unexpected_response', 'The server returned a response this console cannot read.');
  }
  return payload;
}

function errorFromPayload(status, payload) {
  const detail = payload && payload.detail;
  if (Array.isArray(detail)) {
    // FastAPI request-model validation answers with a list of {loc, msg}; it is the shape a
    // rejected body (a short password, a missing camera name) arrives in, so it is unpacked
    // into the same field-aware error the routers raise deliberately.
    const first = detail[0] || {};
    const path = Array.isArray(first.loc) ? first.loc.filter((part) => part !== 'body').join('.') : null;
    const suffix = detail.length > 1 ? ` (${detail.length} fields need attention)` : '';
    return new ApiError(
      status,
      first.type || 'validation_error',
      `${first.msg || 'The submitted values were not accepted.'}${suffix}`,
      path || null
    );
  }
  if (detail && typeof detail === 'object') {
    return new ApiError(status, detail.code, detail.message, detail.field);
  }
  if (typeof detail === 'string') {
    // 401 carries a bare code string; a few 404s do too.
    const sentence =
      detail === 'session_expired'
        ? 'Your session has expired.'
        : detail === 'authentication_required'
          ? 'You must sign in.'
          : detail === 'invalid_credentials'
            ? 'Incorrect username or password.'
            : sentenceFor(detail, status);
    return new ApiError(status, detail, sentence, null);
  }
  return new ApiError(status, `http_${status}`, sentenceFor(null, status));
}

function sentenceFor(rawText, status) {
  if (rawText) return rawText;
  if (status === 403) return 'Your role does not permit this action.';
  if (status === 404) return 'The requested record does not exist.';
  if (status === 409) return 'This conflicts with the current state of the record.';
  if (status === 423) return 'This account is temporarily locked.';
  if (status === 503) return 'The service is at capacity or temporarily unavailable.';
  return `The request could not be completed (HTTP ${status}).`;
}

async function toError(response) {
  let payload = null;
  try {
    payload = await response.json();
  } catch {
    payload = null;
  }
  return errorFromPayload(response.status, payload);
}

const id = (value) => encodeURIComponent(String(value));

/** Every endpoint the console knows about, cross-checked against the backend routers. */
export const api = {
  auth: {
    // `silent` keeps a wrong password on the login page instead of bouncing to it.
    login: (username, password) =>
      request(LOGIN_PATH, { method: 'POST', body: { username, password }, silent: true }),
    logout: () =>
      request('/api/auth/logout', { method: 'POST', silent: true, keepalive: true }),
    me: () => request('/api/auth/me'),
    // `silent` because a mistyped current password is a form error the operator should read in
    // place, not a session failure that bounces the tab to the login page.
    changePassword: (currentPassword, newPassword) =>
      request('/api/auth/password', {
        method: 'POST',
        body: { current_password: currentPassword, new_password: newPassword },
        silent: true,
      }),
  },

  cameras: {
    list: () => request('/api/cameras'),
    overview: () => request('/api/cameras/summary/overview'),
    groups: () => request('/api/cameras/groups'),
    policies: () => request('/api/cameras/policies'),
    testDraft: (payload, signal) =>
      request('/api/cameras/test-draft', { method: 'POST', body: payload, signal }),
    create: (payload) => request('/api/cameras', { method: 'POST', body: payload }),
    get: (cameraId) => request(`/api/cameras/${id(cameraId)}`),
    test: (cameraId) => request(`/api/cameras/${id(cameraId)}/test`, { method: 'POST' }),
    activate: (cameraId) => request(`/api/cameras/${id(cameraId)}/activate`, { method: 'POST' }),
    disable: (cameraId) => request(`/api/cameras/${id(cameraId)}/disable`, { method: 'POST' }),
    update: (cameraId, patch) =>
      request(`/api/cameras/${id(cameraId)}`, { method: 'PATCH', body: patch }),
    health: (cameraId, limit = 50) =>
      request(`/api/cameras/${id(cameraId)}/health`, { query: { limit } }),
    refresh: (cameraId) => request(`/api/cameras/${id(cameraId)}/refresh`, { method: 'POST' }),
  },

  live: {
    open: (cameraId) => request('/api/live/sessions', { method: 'POST', body: { camera_id: cameraId } }),
    state: (token) => request(`/api/live/sessions/${id(token)}/state`),
    release: (token) =>
      request(`/api/live/sessions/${id(token)}`, { method: 'DELETE', silent: true, keepalive: true }),
    // URLs for <img src> and <a href>: GETs, so no CSRF header is required and the
    // session cookie travels automatically as same-origin.
    mjpegUrl: (token) => `/api/live/sessions/${id(token)}/mjpeg`,
    snapshotUrl: (token) => `/api/live/sessions/${id(token)}/snapshot`,
  },

  events: {
    pending: (onlyNew = true, limit = 100) =>
      request('/api/events', { query: { only_new: onlyNew, limit } }),
    review: (eventId, decision, note) =>
      request(`/api/events/${id(eventId)}/review`, { method: 'POST', body: { decision, note } }),
  },

  incidents: {
    list: (filters) => request('/api/incidents', { query: filters }),
    create: (payload) => request('/api/incidents', { method: 'POST', body: payload }),
    get: (incidentId) => request(`/api/incidents/${id(incidentId)}`),
    assign: (incidentId, assigneeId) =>
      request(`/api/incidents/${id(incidentId)}/assign`, {
        method: 'POST',
        body: { assignee_id: assigneeId },
      }),
    escalate: (incidentId, toUserId, note) =>
      request(`/api/incidents/${id(incidentId)}/escalate`, {
        method: 'POST',
        body: { to_user_id: toUserId, note },
      }),
    note: (incidentId, text) =>
      request(`/api/incidents/${id(incidentId)}/notes`, { method: 'POST', body: { text } }),
    resolve: (incidentId, payload) =>
      request(`/api/incidents/${id(incidentId)}/resolve`, { method: 'POST', body: payload }),
    reopen: (incidentId, reason) =>
      request(`/api/incidents/${id(incidentId)}/reopen`, {
        method: 'POST',
        body: { reason },
      }),
    evidenceUrl: (assetId, asExport = false) =>
      `/api/evidence/${id(assetId)}${asExport ? '?export=true' : ''}`,
  },

  notifications: {
    inbox: (unreadOnly = true, limit = 100) =>
      request('/api/notifications', { query: { unread_only: unreadOnly, limit } }),
    read: (notificationId) =>
      request(`/api/notifications/${id(notificationId)}/read`, { method: 'POST' }),
    acknowledge: (notificationId) =>
      request(`/api/notifications/${id(notificationId)}/acknowledge`, { method: 'POST' }),
  },

  admin: {
    users: () => request('/api/admin/users'),
    createUser: (payload) => request('/api/admin/users', { method: 'POST', body: payload }),
    grantRole: (userId, roleCode, cameraGroupId) =>
      request(`/api/admin/users/${id(userId)}/roles`, {
        method: 'POST',
        body: { role_code: roleCode, camera_group_id: cameraGroupId },
      }),
    revokeRole: (userId, roleCode, cameraGroupId) =>
      request(`/api/admin/users/${id(userId)}/roles`, {
        method: 'DELETE',
        query: { role_code: roleCode, camera_group_id: cameraGroupId },
      }),
    setActive: (userId, isActive) =>
      request(`/api/admin/users/${id(userId)}`, {
        method: 'PATCH',
        query: { is_active: isActive },
      }),
    effectivePermissions: (userId) =>
      request(`/api/admin/users/${id(userId)}/effective-permissions`, { method: 'POST' }),
    roles: () => request('/api/admin/roles'),
    permissions: () => request('/api/admin/permissions'),
    roleDefinitions: () => request('/api/admin/role-definitions'),
    createGroup: (payload) => request('/api/admin/groups', { method: 'POST', body: payload }),
    policies: () => request('/api/admin/policies'),
    upsertPolicy: (payload) => request('/api/admin/policies', { method: 'POST', body: payload }),
    notificationSettings: () => request('/api/admin/notification-settings'),
    retention: () => request('/api/admin/retention'),
    purgeRetention: () => request('/api/admin/retention/purge', { method: 'POST' }),
    audit: (filters) => request('/api/admin/audit', { query: filters }),
    operationsReport: (window) => request('/api/admin/reports/operations', {
      query: { since: window && window.since, until: window && window.until },
    }),
    system: () => request('/api/admin/system'),
  },
};

export { request };
