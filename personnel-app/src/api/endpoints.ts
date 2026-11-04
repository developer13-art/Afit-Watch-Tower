/**
 * Endpoint wrappers — one function per route the cloud service actually exposes, so a screen
 * cannot call an endpoint that does not exist and cannot hand-build a query string.
 *
 * Paths, bodies and response types are transcribed from
 * `src/watchtower/cloud/routers/{auth,devices,dashboard,notifications,incidents,evidence,profile}.py`.
 * Where the server uses different names for the same idea (incidents filter by `since`/`until`,
 * notifications by `from`/`to`), the wrapper keeps them separate rather than unifying them,
 * because a shared helper would silently send a parameter the route ignores.
 */
import { apiClient } from './client';
import { ApiError } from './errors';
import { env } from '../config/env';
import { ERROR_CODES } from '../types/api';
import type {
  ActivityListResponse,
  AssignRequest,
  AuthMeResponse,
  DeviceForgetResponse,
  DeviceListResponse,
  DeviceRegistrationRequest,
  DeviceRegistrationResponse,
  EscalateRequest,
  EvidenceListResponse,
  EvidenceMetadata,
  IncidentActionResponse,
  IncidentDetail,
  IncidentListQuery,
  IncidentListResponse,
  LoginRequest,
  LoginResponse,
  LogoutResponse,
  MarkAllReadResponse,
  MarkReadResponse,
  NoteRequest,
  NotificationListQuery,
  NotificationListResponse,
  NotificationPreferencesResponse,
  OpenReportResponse,
  PasswordChangeResponse,
  PreferencesCheckResponse,
  ProfileResponse,
  PushTokenRotationResponse,
  ReopenRequest,
  ResolveRequest,
  UpdatePreferencesRequest,
} from '../types/api';

// ------------------------------------------------------------------ auth

export const authApi = {
  login: (body: LoginRequest) =>
    apiClient().request<LoginResponse>('/auth/login', { method: 'POST', body, auth: false }),
  me: () => apiClient().request<AuthMeResponse>('/auth/me'),
  changePassword: (body: {
    current_password: string;
    new_password: string;
    keep_other_sessions?: boolean;
  }) => apiClient().request<PasswordChangeResponse>('/auth/password', { method: 'POST', body }),
  /**
   * Direct logout call. `SessionProvider` goes through `ApiClient.logout()` instead, because
   * that is the one path that also writes the local token store; this exists for the profile
   * screen's "sign out everywhere" flow, which needs the server's answer.
   */
  logout: (body: { forget_device: boolean; refresh_token?: string }) =>
    apiClient().request<LogoutResponse>('/auth/logout', { method: 'POST', body }),
};

// ------------------------------------------------------------------ devices

export const devicesApi = {
  register: (body: DeviceRegistrationRequest) =>
    apiClient().request<DeviceRegistrationResponse>('/devices', { method: 'POST', body }),
  list: () => apiClient().request<DeviceListResponse>('/devices'),
  /** The path parameter is the installation id, not the numeric row id. */
  revoke: (installationId: string) =>
    apiClient().request<DeviceForgetResponse>(
      `/devices/${encodeURIComponent(installationId)}`,
      { method: 'DELETE' },
    ),
  /**
   * FCM rotated the registration token while the operator was signed in. `POST /devices` would
   * also work, but the dedicated route refuses an unknown installation id instead of forking a
   * second device row, which is the difference between a rotated token and a ghost handset.
   */
  rotatePushToken: (installationId: string, body: DeviceRegistrationRequest) =>
    apiClient().request<PushTokenRotationResponse>(
      `/devices/${encodeURIComponent(installationId)}/push-token`,
      { method: 'POST', body },
    ),
};

// ------------------------------------------------------------------ dashboard

export const dashboardApi = {
  summary: () =>
    apiClient().request<import('../types/api').DashboardSummary>('/dashboard/summary'),
};

// ------------------------------------------------------------------ notifications

export const notificationsApi = {
  list: (query: NotificationListQuery = {}) =>
    apiClient().request<NotificationListResponse>('/notifications', { query }),
  markRead: (id: number) =>
    apiClient().request<MarkReadResponse>(`/notifications/${id}/read`, {
      method: 'POST',
      body: {},
    }),
  markAllRead: (before?: string) =>
    apiClient().request<MarkAllReadResponse>('/notifications/read-all', {
      method: 'POST',
      body: before ? { before } : {},
    }),
  /** Reported when the incident actually renders, not on tap. */
  reportOpen: (id: number) =>
    apiClient().request<OpenReportResponse>(`/notifications/${id}/open`, {
      method: 'POST',
      body: {},
    }),
};

// ------------------------------------------------------------------ incidents

export const incidentsApi = {
  list: (query: IncidentListQuery = {}) =>
    apiClient().request<IncidentListResponse>('/incidents', { query }),
  detail: (id: number) => apiClient().request<IncidentDetail>(`/incidents/${id}`),
  activity: (id: number, cursor?: string, limit?: number) =>
    apiClient().request<ActivityListResponse>(`/incidents/${id}/activity`, {
      query: { cursor, limit },
    }),
  acknowledge: (id: number, note?: string) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/acknowledge`, {
      method: 'POST',
      body: note ? { note } : {},
    }),
  investigating: (id: number, note?: string) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/investigating`, {
      method: 'POST',
      body: note ? { note } : {},
    }),
  note: (id: number, body: NoteRequest) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/notes`, {
      method: 'POST',
      body,
    }),
  /** `reason` is required and becomes the activity note; there is no separate note field. */
  escalate: (id: number, body: EscalateRequest) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/escalate`, {
      method: 'POST',
      body,
    }),
  assign: (id: number, body: AssignRequest) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/assign`, {
      method: 'POST',
      body,
    }),
  /** `false_positive: true` moves the incident to the `false_positive` status. */
  resolve: (id: number, body: ResolveRequest) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/resolve`, {
      method: 'POST',
      body,
    }),
  reopen: (id: number, body: ReopenRequest) =>
    apiClient().request<IncidentActionResponse>(`/incidents/${id}/reopen`, {
      method: 'POST',
      body,
    }),
  /** "Would this account have been paged for this?" — the profile screen's own diagnostics. */
  preferencesCheck: (id: number) =>
    apiClient().request<PreferencesCheckResponse>(`/incidents/${id}/preferences-check`),
};

// ------------------------------------------------------------------ evidence

export const evidenceApi = {
  list: (incidentId: number) =>
    apiClient().request<EvidenceListResponse>(`/incidents/${incidentId}/evidence`),
  metadata: (assetId: number) =>
    apiClient().request<EvidenceMetadata>(`/evidence/${assetId}`),
  /**
   * The signed `url` from the list response is a link to `GET /evidence/{id}/content`, which
   * authorises from the query-string token. It must be fetched with the bare `fetch` — no
   * bearer header, no refresh cycle — because attaching our Authorization header to a signed
   * URL would hand the session token to whatever host serves the bytes.
   */
  assetUrlIsSigned: (url: string) => /[?&](token|signature|X-Amz-Signature)=/i.test(url),
  /**
   * `POST /evidence/{id}/export` needs `evidence.export`, which the server checks separately
   * from a view, and answers with the bytes plus an `attachment` disposition. Raw so the body
   * is not parsed as JSON; the audit row for the export is written by that call.
   */
  export: async (assetId: number): Promise<{ blob: Blob; filename: string | null }> => {
    const res = await apiClient().request<Response>(`/evidence/${assetId}/export`, {
      method: 'POST',
      raw: true,
    });
    const disposition = res.headers.get('content-disposition') ?? '';
    const match = /filename="?([^";]+)"?/i.exec(disposition);
    return { blob: await res.blob(), filename: match ? match[1] : null };
  },
};

// ------------------------------------------------------------------ profile

export const profileApi = {
  get: () => apiClient().request<ProfileResponse>('/profile'),
  preferences: () =>
    apiClient().request<NotificationPreferencesResponse>('/profile/preferences'),
  savePreferences: (body: UpdatePreferencesRequest) =>
    apiClient().request<NotificationPreferencesResponse>('/profile/preferences', {
      method: 'PUT',
      body,
    }),
};

// ------------------------------------------------------------------ service probe

/** `cloud/app.py::healthz()`. A 503 carries this same body, so it is read rather than thrown away. */
export interface ServiceHealth {
  status: 'ok' | 'degraded';
  service: string;
  protocol_version: string;
  database: 'ok' | 'unavailable';
  /** `enabled` means an installed sender that loaded its credentials — not that a handset received one. */
  push: 'enabled' | 'disabled';
  ingest: 'enabled' | 'disabled';
  live_channel: 'enabled' | 'disabled';
  uptime_seconds: number;
  time: string;
  database_detail?: string;
}

export const healthApi = {
  /**
   * `/healthz` sits at the service root, outside the `/api/v1` base the session client prefixes,
   * and answers without a token — which is the whole reason it is a plain fetch here. Nothing is
   * attached to it: a health probe that carries a bearer token is a token leak in an access log.
   */
  check: async (): Promise<ServiceHealth> => {
    const response = await fetch(`${env.apiOrigin}/healthz`, {
      headers: { accept: 'application/json' },
      cache: 'no-store',
    });
    const body = (await response.json().catch(() => null)) as ServiceHealth | null;
    if (!body || typeof body.status !== 'string') {
      throw new ApiError({
        code: ERROR_CODES.UNKNOWN,
        message: 'The service answered the health probe without a body this app understands.',
        status: response.status,
        kind: response.ok ? 'parse' : 'http',
      });
    }
    return body;
  },
};
