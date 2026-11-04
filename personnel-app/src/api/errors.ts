/**
 * Error normalisation (contract §1).
 *
 * Every failure that reaches a component is an `ApiError` carrying the
 * server's `{ code, message, request_id }` triple, or a faithful client-side
 * synthesis of it when the server never answered. Screens never branch on raw
 * HTTP numbers or on `Error.message`, so a changed wording cannot break the UI.
 */
import { ERROR_CODES } from '../types/api';

export type ApiErrorKind =
  /** Server answered with a non-2xx status. */
  | 'http'
  /** fetch() threw before a response: DNS, TLS, CORS, airplane mode. */
  | 'network'
  /** The request was aborted by our own timeout. */
  | 'timeout'
  /** The browser/WebView reported offline before we even tried. */
  | 'offline'
  /** A 2xx body that is not JSON, or JSON that violates the error envelope. */
  | 'parse';

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly requestId: string | null;
  readonly kind: ApiErrorKind;
  readonly retryAfterSeconds: number | null;
  /** Raw envelope, kept for the debug sheet. */
  readonly body: unknown;

  constructor(init: {
    code: string;
    message: string;
    status?: number;
    requestId?: string | null;
    kind?: ApiErrorKind;
    retryAfterSeconds?: number | null;
    body?: unknown;
    cause?: unknown;
  }) {
    super(init.message, init.cause === undefined ? undefined : { cause: init.cause });
    this.name = 'ApiError';
    this.code = init.code;
    this.status = init.status ?? 0;
    this.requestId = init.requestId ?? null;
    this.kind = init.kind ?? 'http';
    this.retryAfterSeconds = init.retryAfterSeconds ?? null;
    this.body = init.body ?? null;
  }

  get isUnauthorized(): boolean {
    return this.status === 401 || this.code === ERROR_CODES.AUTHENTICATION_REQUIRED;
  }

  get isForbidden(): boolean {
    return this.status === 403 || this.code === ERROR_CODES.FORBIDDEN;
  }

  /** §1 — 404 also means "you may not know this exists". */
  get isNotFound(): boolean {
    return this.status === 404;
  }

  get isConflict(): boolean {
    return this.status === 409 || this.code.startsWith('incident_');
  }

  get isGone(): boolean {
    return this.status === 410;
  }

  get isRateLimited(): boolean {
    return this.status === 429 || this.code === ERROR_CODES.RATE_LIMITED;
  }

  get isConnectivity(): boolean {
    return this.kind === 'network' || this.kind === 'offline' || this.kind === 'timeout';
  }

  /** Short, human, institutional. Never leaks a stack or a URL. */
  get userMessage(): string {
    if (this.kind === 'offline') return 'This device is offline. Reconnect and retry.';
    if (this.kind === 'timeout') return 'The server did not answer in time.';
    if (this.kind === 'network') return `Cannot reach the WATCH TOWER service at ${this.requestId ?? 'unknown'} — check the network.`;
    if (this.kind === 'parse') return 'The service returned an unexpected response.';
    return this.message || describeCode(this.code);
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message,
      status: this.status,
      request_id: this.requestId,
      kind: this.kind,
    };
  }
}

/**
 * Fallback code when a non-2xx body carried no envelope — a gateway page, an empty body, a
 * proxy that replaced ours. Where the server has its own word for the status, this returns that
 * word; where a status alone does not identify one refusal (`409` is four different codes in
 * the incident service), it returns `unknown_error` and lets `ApiError.status` carry the truth.
 */
export function codeForStatus(status: number): string {
  switch (status) {
    case 401:
      return ERROR_CODES.AUTHENTICATION_REQUIRED;
    case 403:
      return ERROR_CODES.FORBIDDEN;
    case 404:
      return ERROR_CODES.NOT_FOUND;
    case 410:
      return ERROR_CODES.EVIDENCE_EXPIRED;
    case 415:
      return ERROR_CODES.EVIDENCE_TYPE_UNSUPPORTED;
    case 416:
      return ERROR_CODES.RANGE_UNSATISFIABLE;
    case 422:
      return ERROR_CODES.VALIDATION_FAILED;
    case 429:
      return ERROR_CODES.RATE_LIMITED;
    case 500:
      return ERROR_CODES.INTERNAL_ERROR;
    case 503:
      return ERROR_CODES.STORAGE_UNAVAILABLE;
    default:
      // Not a status the service produces for a well-formed request, so the app cannot name it.
      return ERROR_CODES.UNKNOWN;
  }
}

/**
 * Operator-facing text for the codes `cloud/routers/*` actually returns.
 *
 * Every case here is a `CloudError(...)` in the service. A code the server never sends is worse
 * than no code at all: it makes the app explain a situation that cannot happen, and hides the
 * one that does — which is why `evidence_unavailable` says "still arriving" instead of
 * "permission denied", and `password_change_required` sends the operator to the change-password
 * screen instead of reporting a failed sign-in.
 */
export function describeCode(code: string): string {
  switch (code) {
    // ---- auth
    case ERROR_CODES.INVALID_CREDENTIALS:
      return 'Username or password is incorrect.';
    case ERROR_CODES.ACCOUNT_LOCKED:
      return 'This account is temporarily locked after repeated failed sign-ins. Wait a few minutes, then try again.';
    case ERROR_CODES.REFRESH_REUSED:
      return 'A replayed session token was detected, so this device’s whole session family was revoked. Sign in again.';
    case ERROR_CODES.INVALID_REFRESH:
    case ERROR_CODES.SESSION_REVOKED:
      return 'This session is no longer recognised by the service. Sign in again.';
    case ERROR_CODES.REFRESH_EXPIRED:
      return 'This session has expired. Sign in again.';
    case ERROR_CODES.ACCESS_EXPIRED:
    case ERROR_CODES.INVALID_TOKEN:
      return 'The session token is not valid for this request.';
    case ERROR_CODES.CURRENT_PASSWORD_INCORRECT:
      return 'The current password you entered is not correct.';
    case ERROR_CODES.PASSWORD_CHANGE_REQUIRED:
      return 'A temporary password is in use. Choose a new one before continuing.';
    case ERROR_CODES.AUTHENTICATION_REQUIRED:
      return 'Not signed in, or the session expired.';
    case ERROR_CODES.FORBIDDEN:
      return 'You do not have permission for this action.';
    case ERROR_CODES.NOT_FOUND:
      return 'Not found, or outside your assigned area.';
    // ---- incidents
    case ERROR_CODES.INCIDENT_NOT_ACTIONABLE:
      return 'This incident is resolved or closed; reopen it before acknowledging.';
    case ERROR_CODES.ALREADY_RESOLVED:
      return 'This incident has already been resolved.';
    case ERROR_CODES.NOT_RESOLVED:
      return 'This incident is not resolved, so it cannot be reopened as closed.';
    case ERROR_CODES.INVALID_STATE:
      return 'This action does not apply to the incident in its current state.';
    case ERROR_CODES.INVALID_DECISION:
      return 'That review decision is not one the service accepts.';
    case ERROR_CODES.NOTE_REQUIRED:
      return 'A note is required for this action.';
    case ERROR_CODES.ESCALATION_TARGET_UNAVAILABLE:
      return 'The colleague or role this incident was being escalated to cannot receive it.';
    case ERROR_CODES.UNKNOWN_ROLE:
    case ERROR_CODES.ROLE_REQUIRED:
      return 'The escalation target is not a role the service recognises.';
    case ERROR_CODES.INCIDENT_UNAVAILABLE:
      return 'This incident is not available for the action you attempted.';
    // ---- query validation
    case ERROR_CODES.STATUS_INVALID:
      return 'One of the status filters is not a recognised incident status.';
    case ERROR_CODES.SEVERITY_INVALID:
      return 'One of the severity filters is not a recognised severity.';
    case ERROR_CODES.CAMERA_ID_INVALID:
      return 'The camera filter must be a camera identifier.';
    case ERROR_CODES.CURSOR_INVALID:
      return 'The continuation marker is not recognised. Reload the list.';
    // ---- devices
    case ERROR_CODES.INSTALLATION_ID_REQUIRED:
    case ERROR_CODES.INSTALLATION_ID_INVALID:
      return 'This handset could not be identified, so it cannot be registered for alerts.';
    case ERROR_CODES.PLATFORM_UNSUPPORTED:
      return 'This platform is not accepted by the notification service.';
    case ERROR_CODES.PUSH_TOKEN_REQUIRED:
      return 'No notification token was available for this handset yet.';
    case ERROR_CODES.SELF_DEACTIVATION:
      return 'You cannot disable the account you are signed in with.';
    // ---- evidence
    case ERROR_CODES.EVIDENCE_EXPIRED:
      return 'This evidence is past its retention date and can no longer be opened.';
    case ERROR_CODES.EVIDENCE_UNAVAILABLE:
      return 'The bytes for this evidence have not reached the cloud service yet.';
    case ERROR_CODES.EVIDENCE_TOKEN_INVALID:
      return 'This evidence link is no longer valid. Refetch the links.';
    case ERROR_CODES.EVIDENCE_TYPE_UNSUPPORTED:
      return 'This evidence cannot be displayed on the device.';
    case ERROR_CODES.EVIDENCE_INTEGRITY_FAILED:
      return 'This evidence did not pass its integrity check and has not been shown.';
    case ERROR_CODES.RANGE_INVALID:
    case ERROR_CODES.RANGE_UNSATISFIABLE:
      return 'The video could not be seeked to that position. Retry from the start.';
    case ERROR_CODES.TOO_MANY_EVIDENCE_READS:
      return 'Evidence has been opened too many times in a minute. Wait, then retry.';
    case ERROR_CODES.TOO_MANY_LOGIN_ATTEMPTS:
    case ERROR_CODES.TOO_MANY_REFRESH_ATTEMPTS:
      return 'Too many sign-in attempts from this device. Wait a moment and retry.';
    case ERROR_CODES.TOO_MANY_PASSWORD_ATTEMPTS:
      return 'Too many password attempts. Wait fifteen minutes and try again.';
    case ERROR_CODES.TOO_MANY_ACTIONS:
      return 'Incident actions have been recorded too quickly. Wait, then retry.';
    case ERROR_CODES.STORAGE_UNAVAILABLE:
      return 'The evidence store is not reachable right now. The incident itself is unaffected.';
    case ERROR_CODES.RATE_LIMITED:
      return 'Too many requests. Wait a moment and retry.';
    case ERROR_CODES.INTERNAL_ERROR:
      return 'The service failed to complete this request. Report the reference code below.';
    case ERROR_CODES.VALIDATION_FAILED:
    case ERROR_CODES.INVALID_JSON:
      return 'Some input is invalid.';
    case ERROR_CODES.NETWORK_OFFLINE:
      return 'This device is offline.';
    case ERROR_CODES.NETWORK_TIMEOUT:
      return 'The service did not answer in time.';
    default:
      return 'The request failed.';
  }
}

interface RawErrorEnvelope {
  error?: { code?: unknown; message?: unknown; request_id?: unknown };
  detail?: unknown;
}

/**
 * Turn a Response into an ApiError. Tolerates: JSON envelope, FastAPI-style
 * `detail`, an HTML error page from a proxy, and an empty body.
 */
export async function errorFromResponse(res: Response, requestId: string): Promise<ApiError> {
  const headerRequestId = res.headers.get('x-request-id') ?? res.headers.get('X-Request-Id');
  let code = codeForStatus(res.status);
  let message = '';
  let parsed: unknown = null;

  try {
    const text = await res.text();
    if (text) {
      try {
        const json = JSON.parse(text) as RawErrorEnvelope & { code?: unknown; request_id?: unknown; message?: unknown };
        parsed = json;
        if (json.error && typeof json.error === 'object') {
          if (typeof json.error.code === 'string') code = json.error.code;
          if (typeof json.error.message === 'string') message = json.error.message;
          if (typeof json.error.request_id === 'string') requestId = json.error.request_id;
        } else if (typeof json.code === 'string') {
          code = json.code;
          if (typeof json.request_id === 'string') requestId = json.request_id;
          if (typeof json.message === 'string') message = json.message;
        } else if (typeof json.detail === 'string') {
          message = json.detail;
        } else if (Array.isArray(json.detail) && json.detail.length > 0) {
          message = 'Validation failed.';
        }
      } catch {
        // Not JSON (proxy page, gateway HTML). Deliberately do not surface it.
        message = '';
      }
    }
  } catch {
    /* body unreadable */
  }

  const retryAfter = Number(res.headers.get('retry-after') ?? '');

  return new ApiError({
    code,
    message: message || describeCode(code),
    status: res.status,
    requestId: headerRequestId || requestId,
    kind: 'http',
    retryAfterSeconds: Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : null,
    body: parsed,
  });
}

export function networkError(err: unknown, requestId: string, aborted: boolean, offline: boolean): ApiError {
  if (offline) {
    return new ApiError({
      code: ERROR_CODES.NETWORK_OFFLINE,
      message: describeCode(ERROR_CODES.NETWORK_OFFLINE),
      requestId,
      kind: 'offline',
      cause: err,
    });
  }
  if (aborted) {
    return new ApiError({
      code: ERROR_CODES.NETWORK_TIMEOUT,
      message: describeCode(ERROR_CODES.NETWORK_TIMEOUT),
      requestId,
      kind: 'timeout',
      cause: err,
    });
  }
  return new ApiError({
    code: ERROR_CODES.NETWORK_OFFLINE,
    message: describeCode(ERROR_CODES.NETWORK_OFFLINE),
    requestId,
    kind: 'network',
    cause: err,
  });
}

export function isApiError(err: unknown): err is ApiError {
  return err instanceof ApiError;
}

export function asApiError(err: unknown, fallbackRequestId = ''): ApiError {
  if (isApiError(err)) return err;
  return new ApiError({
    code: ERROR_CODES.UNKNOWN,
    message: err instanceof Error ? err.message : String(err),
    requestId: fallbackRequestId,
    kind: 'parse',
    cause: err,
  });
}
