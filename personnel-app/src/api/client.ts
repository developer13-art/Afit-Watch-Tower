/**
 * The API client. One file, one responsibility: talk to
 * `docs/mobile-api-contract.md` correctly and honestly.
 *
 * Behaviours implemented here and nowhere else:
 *   - bearer injection from the in-memory access token (§2)
 *   - single-flight refresh on 401, with the concurrent-request queue
 *     collapsing onto one refresh and every queued request retried once after
 *     the rotation (§2.2)
 *   - forced logout when the refresh token is rejected — the reuse-detection
 *     path where the server killed the whole token family (§2.2)
 *   - request-id propagation in both directions (§1)
 *   - typed error normalisation into `{ error: { code, message, request_id } }`
 *   - per-request timeout
 *   - offline detection reported as its own error kind, not as a 500
 */
import { env } from '../config/env';
import { ERROR_CODES } from '../types/api';
import type { LoginResponse, LogoutResponse, RefreshResponse } from '../types/api';
import { ApiError, asApiError, errorFromResponse, networkError } from './errors';
import type { TokenStore } from '../storage/tokenStore';

export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE';

export type QueryValue = string | number | boolean | null | undefined | Array<string | number>;

export interface RequestOptions {
  method?: HttpMethod;
  /** JSON body. Omit for no body. */
  body?: unknown;
  query?: Record<string, QueryValue> | object;
  /** Attach the bearer token. Default true. */
  auth?: boolean;
  /** Retry once after a refresh when the server answers 401. Default true. */
  retryOn401?: boolean;
  timeoutMs?: number;
  headers?: Record<string, string>;
  signal?: AbortSignal;
  /** Return the raw Response (evidence streaming). */
  raw?: boolean;
}

export interface SessionTokens {
  accessToken: string;
  refreshToken: string;
  accessExpiresAt: number;
}

export type LogoutReason = 'refresh_reuse' | 'revoked' | 'no_session' | 'explicit';

export interface ClientEvents {
  onTokensChanged?: (tokens: SessionTokens) => void;
  onForceLogout?: (reason: LogoutReason, error?: ApiError) => void;
  onConnectivity?: (online: boolean) => void;
}

export interface ApiClientDeps {
  store: TokenStore;
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  events?: ClientEvents;
  now?: () => number;
  /**
   * This handset's installation id. Sent as `x-installation-id` on every
   * authenticated call, because the server retires *this* device when the
   * operator signs out with "forget this device" - without the header that
   * instruction has no subject and the handset stays pageable.
   */
  installationId?: string;
}

const REFRESH_SKEW_MS = 30_000;

function newRequestId(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return `req_${c.randomUUID().slice(0, 8)}`;
  return `req_${Math.random().toString(16).slice(2, 10)}`;
}

export class ApiClient {
  readonly baseUrl: string;

  private readonly store: TokenStore;
  private readonly fetchImpl: typeof fetch;
  private readonly events: ClientEvents;
  private readonly now: () => number;

  private accessToken: string | null = null;
  private accessExpiresAt = 0;
  private refreshToken: string | null = null;
  private installationId: string | null = null;
  /** Hydrated flag: the first read from the secure store is async. */
  private hydrated = false;
  private hydrating: Promise<void> | null = null;

  /** Single-flight refresh: concurrent 401s share one token exchange. */
  private refreshInFlight: Promise<string | null> | null = null;

  private online = true;
  private listenersBound = false;

  constructor(deps: ApiClientDeps) {
    this.store = deps.store;
    this.baseUrl = (deps.baseUrl ?? env.apiUrl).replace(/\/+$/, '');
    this.fetchImpl = deps.fetchImpl ?? ((...args) => fetch(...args));
    this.events = deps.events ?? {};
    this.now = deps.now ?? (() => Date.now());
    this.online = readOnline();
    this.installationId = deps.installationId ?? null;
    this.bindConnectivity();
  }

  /** Set once the installation id has been read from secure storage. */
  setInstallationId(installationId: string | null): void {
    this.installationId = installationId;
  }

  // -------------------------------------------------------------- session state

  get isOnline(): boolean {
    return this.online;
  }

  get hasSession(): boolean {
    return Boolean(this.refreshToken);
  }

  get accessTokenValue(): string | null {
    return this.accessToken;
  }

  /**
   * Read the persisted refresh-token family. Called on cold start before
   * /auth/me. Returns the stored session, or null when nothing survived.
   */
  async hydrate(): Promise<boolean> {
    if (this.hydrated) return this.hasSession;
    if (!this.hydrating) {
      this.hydrating = (async () => {
        try {
          const stored = await this.store.read();
          if (stored) {
            this.refreshToken = stored.refreshToken;
            this.accessToken = stored.accessToken;
            this.accessExpiresAt = stored.accessExpiresAt ?? 0;
          }
        } catch {
          /* unreadable store is equivalent to no session */
        } finally {
          this.hydrated = true;
          this.hydrating = null;
        }
      })();
    }
    await this.hydrating;
    return this.hasSession;
  }

  /** After /auth/login: install the pair and persist the refresh token. */
  async installSession(login: LoginResponse): Promise<void> {
    await this.persist({
      accessToken: login.access_token,
      refreshToken: login.refresh_token,
      accessExpiresAt: this.now() + login.expires_in * 1000,
    });
  }

  async persist(tokens: SessionTokens): Promise<void> {
    this.accessToken = tokens.accessToken;
    this.accessExpiresAt = tokens.accessExpiresAt;
    this.refreshToken = tokens.refreshToken;
    await this.store.write({
      refreshToken: tokens.refreshToken,
      accessToken: tokens.accessToken,
      accessExpiresAt: tokens.accessExpiresAt,
    });
    this.events.onTokensChanged?.(tokens);
  }

  /**
   * Clear local material. `forgetDevice` is the caller's decision and is sent
   * to the server separately (§2.3) — this method only scrubs the client.
   */
  async clearSession(): Promise<void> {
    this.accessToken = null;
    this.accessExpiresAt = 0;
    this.refreshToken = null;
    this.hydrated = false;
    await this.store.clear();
  }

  // -------------------------------------------------------------- request core

  urlFor(path: string, query?: Record<string, QueryValue> | object): string {
    const normalised = path.startsWith('/') ? path : `/${path}`;
    const url = new URL(`${this.baseUrl}${normalised}`);
    if (query) {
      const entries = Object.entries(query as Record<string, QueryValue>);
      for (const [key, value] of entries) {
        if (value === null || value === undefined) continue;
        if (Array.isArray(value)) {
          // §5.1/§6.1 — repeatable query parameters.
          for (const item of value) url.searchParams.append(key, String(item));
        } else {
          url.searchParams.set(key, String(value));
        }
      }
    }
    return url.toString();
  }

  /**
   * Perform a request. `T` is the parsed JSON shape from the contract.
   * Throws `ApiError` for every failure mode, including transport failures.
   */
  async request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const method = options.method ?? 'GET';
    const wantsAuth = options.auth !== false;
    const requestId = newRequestId();

    await this.hydrate();

    let res = await this.dispatch<T>(method, path, options, wantsAuth, requestId, false);

    // Reactive 401: proactive expiry did not catch it (clock skew, server-side
    // revocation, a token that expired mid-flight). Refresh once, retry once.
    if (res.error instanceof ApiError && res.error.status === 401 && wantsAuth && options.retryOn401 !== false) {
      const fresh = await this.refreshNow();
      if (fresh) {
        res = await this.dispatch<T>(method, path, options, wantsAuth, newRequestId(), true);
      }
    }

    if (res.error) throw res.error;
    return res.value as T;
  }

  private async dispatch<T>(
    method: HttpMethod,
    path: string,
    options: RequestOptions,
    wantsAuth: boolean,
    requestId: string,
    isRetry: boolean,
  ): Promise<{ value?: T; error?: ApiError }> {
    const url = this.urlFor(path, options.query);
    const headers: Record<string, string> = {
      accept: 'application/json',
      'x-request-id': requestId,
      ...options.headers,
    };

    if (wantsAuth) {
      if (this.installationId) headers['x-installation-id'] = this.installationId;
      const token = isRetry ? this.accessToken : await this.ensureAccessToken();
      if (!token) {
        return {
          error: new ApiError({
            code: ERROR_CODES.AUTHENTICATION_REQUIRED,
            message: 'No active session for this device.',
            status: 401,
            requestId,
            kind: 'http',
          }),
        };
      }
      headers.authorization = `Bearer ${token}`;
    }

    let body: BodyInit | undefined;
    if (options.body !== undefined && method !== 'GET') {
      headers['content-type'] = 'application/json; charset=utf-8';
      body = JSON.stringify(options.body);
    }

    const timeoutMs = options.timeoutMs ?? (isAuthPath(path) ? env.authTimeoutMs : env.apiTimeoutMs);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    const abortFromCaller = () => controller.abort();
    if (options.signal) {
      if (options.signal.aborted) controller.abort();
      else options.signal.addEventListener('abort', abortFromCaller, { once: true });
    }

    let res: Response;
    try {
      res = await this.fetchImpl(url, {
        method,
        headers,
        body,
        signal: controller.signal,
        credentials: 'omit', // §11: bearer tokens only, no cookies on this surface.
      });
    } catch (err) {
      clearTimeout(timer);
      const aborted = controller.signal.aborted;
      const offline = !readOnline();
      if (offline) this.emitConnectivity(false);
      return { error: networkError(err, requestId, aborted, offline) };
    } finally {
      clearTimeout(timer);
      if (options.signal) options.signal.removeEventListener('abort', abortFromCaller);
    }

    if (res.status === 0) {
      return {
        error: new ApiError({
          code: ERROR_CODES.NETWORK_OFFLINE,
          message: 'No network response.',
          requestId,
          kind: 'network',
        }),
      };
    }

    if (!res.ok) {
      const error = await errorFromResponse(res, requestId);
      // Proven observation: a 401/403 on a bearer-authenticated call means the
      // session is no longer accepted. The caller decides whether to refresh.
      if (error.status === 401 && wantsAuth && !isRetry) {
        this.markAccessStale();
      }
      return { error };
    }

    if (options.raw) return { value: res as unknown as T };

    if (res.status === 204) return { value: undefined as T };

    const contentType = res.headers.get('content-type') ?? '';
    if (contentType.includes('application/json') || contentType === '') {
      try {
        // `res.json()` typing is erased here on purpose: the contract fixes the
        // shape, and a mismatch is a server defect, not a client-side union.
        return { value: (await res.json()) as T };
      } catch (err) {
        return {
          error: new ApiError({
            code: ERROR_CODES.INVALID_RESPONSE,
            message: 'The service returned a malformed response.',
            requestId,
            kind: 'parse',
            cause: err,
          }),
        };
      }
    }
    return { value: (await res.text()) as unknown as T };
  }

  // -------------------------------------------------------------- token lifecycle

  /** Access token, refreshed proactively a hair before expiry. */
  private async ensureAccessToken(): Promise<string | null> {
    if (this.accessToken && this.accessExpiresAt - REFRESH_SKEW_MS > this.now()) return this.accessToken;
    if (!this.refreshToken) return null;
    return this.refreshNow();
  }

  /**
   * Single-flight refresh. Every concurrent caller receives the same promise,
   * so ten simultaneous 401s produce one `/auth/refresh` and one rotation.
   */
  refreshNow(): Promise<string | null> {
    if (this.refreshInFlight) return this.refreshInFlight;
    this.refreshInFlight = this.performRefresh().finally(() => {
      this.refreshInFlight = null;
    });
    return this.refreshInFlight;
  }

  private async performRefresh(): Promise<string | null> {
    if (!this.refreshToken) {
      this.forceLogout('no_session');
      return null;
    }

    const presentedToken = this.refreshToken;
    let parsed: RefreshResponse;
    try {
      parsed = await this.rawJson<RefreshResponse>('/auth/refresh', {
        method: 'POST',
        body: { refresh_token: presentedToken },
      });
    } catch (err) {
      const apiError = asApiError(err);
      if (apiError.code === ERROR_CODES.REFRESH_REUSED) {
        // The server's own reuse detection: this family was killed because a token that had
        // already been rotated was presented again. Retry would only repeat the offence.
        await this.clearSession();
        this.forceLogout('refresh_reuse', apiError);
        return null;
      }
      if (apiError.status === 401) {
        // Expired, revoked, or the account was disabled. The session is over, but calling it a
        // replay would be a false security alarm to the operator.
        await this.clearSession();
        this.forceLogout('revoked', apiError);
        return null;
      }
      if (apiError.isConnectivity) {
        // Transient: keep the session, let the caller surface offline state.
        return null;
      }
      // 5xx / unknown: do not destroy a working session over a server fault.
      return null;
    }

    // Rotate. Persist BEFORE publishing so a crash cannot leave the client
    // holding a token the server already invalidated.
    await this.persist({
      accessToken: parsed.access_token,
      refreshToken: parsed.refresh_token,
      accessExpiresAt: this.now() + parsed.expires_in * 1000,
    });
    return parsed.access_token;
  }

  /** A refresh/login exchange must never recurse into the refresh path. */
  private async rawJson<T>(path: string, options: RequestOptions): Promise<T> {
    return this.request<T>(path, { ...options, auth: false, retryOn401: false });
  }

  /**
   * Login. Kept on the client so the token pair and the installation id are
   * written by exactly one code path.
   *
   * §2.1: `device` is optional at login and may be sent later to /devices. The
   * app sends it when it already knows the push token, so a reinstall of a
   * known account re-registers the device in one round-trip.
   */
  async login(
    username: string,
    password: string,
    device?: import('../types/api').DeviceDescriptor,
  ): Promise<LoginResponse> {
    const res = await this.rawJson<LoginResponse>('/auth/login', {
      method: 'POST',
      body: device ? { username, password, device } : { username, password },
    });
    await this.persist({
      accessToken: res.access_token,
      refreshToken: res.refresh_token,
      accessExpiresAt: this.now() + res.expires_in * 1000,
    });
    return res;
  }

  /**
   * Sign out, and report what the server actually agreed to forget.
   *
   * The body names the *session* (the refresh token, so the whole family is revoked rather
   * than only this access token) and the *decision* (`forget_device`). The handset itself is
   * identified by the `x-installation-id` header this client attaches, because the server only
   * deactivates a device it can attribute to the caller. A registration token never belongs in
   * a logout body — it is a bearer capability, and a body has a longer life in logs than a
   * header does.
   */
  async logout(options: { forgetDevice: boolean }): Promise<LogoutResponse> {
    // Read the store first: without hydration `this.refreshToken` is still null here, and the
    // body would name no session — the family stays alive on a device its owner just forgot.
    await this.hydrate();
    const body: { refresh_token?: string; forget_device: boolean } = {
      forget_device: options.forgetDevice,
    };
    if (this.refreshToken) body.refresh_token = this.refreshToken;
    let result: LogoutResponse = { signed_out: false, device_forgotten: false };
    try {
      result = await this.request<LogoutResponse>('/auth/logout', { method: 'POST', body });
    } finally {
      // The local session is destroyed even if the server call fails: an
      // offline logout still has to log the operator out of the device.
      await this.clearSession();
    }
    return result;
  }

  private markAccessStale(): void {
    this.accessExpiresAt = 0;
  }

  private forceLogout(reason: LogoutReason, error?: ApiError): void {
    this.accessToken = null;
    this.accessExpiresAt = 0;
    this.refreshToken = null;
    this.events.onForceLogout?.(reason, error);
  }

  // -------------------------------------------------------------- connectivity

  private emitConnectivity(online: boolean): void {
    if (this.online !== online) {
      this.online = online;
      this.events.onConnectivity?.(online);
    }
  }

  private bindConnectivity(): void {
    if (this.listenersBound) return;
    if (typeof window === 'undefined' || typeof window.addEventListener !== 'function') return;
    this.listenersBound = true;
    window.addEventListener('online', () => {
      this.online = true;
      this.events.onConnectivity?.(true);
    });
    window.addEventListener('offline', () => {
      this.emitConnectivity(false);
    });
  }

  /** Used by tests and by the fixture transport. */
  get tokenStore(): TokenStore {
    return this.store;
  }
}

function readOnline(): boolean {
  if (typeof navigator === 'undefined') return true;
  return navigator.onLine !== false;
}

function isAuthPath(path: string): boolean {
  return path.startsWith('/auth/');
}

/** Shared singleton, installed by `bootstrap()`. */
let singleton: ApiClient | null = null;

export function setApiClient(client: ApiClient | null): void {
  singleton = client;
}

export function apiClient(): ApiClient {
  if (!singleton) throw new Error('ApiClient not initialised — call bootstrap() before use.');
  return singleton;
}

export function tryApiClient(): ApiClient | null {
  return singleton;
}
