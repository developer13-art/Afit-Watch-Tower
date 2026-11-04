/**
 * The client behaviours that exist nowhere else in the app: bearer and installation headers,
 * single-flight refresh, the reuse path that ends the session, and what a logout body carries.
 *
 * These are the rules a screen cannot re-derive and a fixture transport cannot prove, because the
 * fixture answers the request rather than the caller. The fetch here is a recorder: every test
 * asserts on the calls the client actually made, not on the data it returned.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { ApiClient } from './client';
import { ApiError } from './errors';
import { ERROR_CODES } from '../types/api';
import type { LoginResponse, RefreshResponse } from '../types/api';
import type { StoredSession, TokenStore, TokenWrite } from '../storage/tokenStore';

class MemoryStore implements TokenStore {
  readonly kind = 'memory' as const;
  readonly persistent = false;
  session: StoredSession | null = null;
  installationId: string | null = null;

  async read(): Promise<StoredSession | null> {
    return this.session;
  }
  async write(value: TokenWrite): Promise<void> {
    this.session = { ...value };
  }
  async clear(): Promise<void> {
    this.session = null;
  }
  async readInstallationId(): Promise<string | null> {
    return this.installationId;
  }
  async writeInstallationId(value: string): Promise<void> {
    this.installationId = value;
  }
  async clearInstallationId(): Promise<void> {
    this.installationId = null;
  }
  describe() {
    return { kind: 'memory' as const, persistent: false, hardwareBacked: false, warning: null };
  }
}

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: unknown;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function errorBody(code: string, message = 'refused'): Response {
  return jsonResponse({ error: { code, message, request_id: 'req_test' } }, code === 'not_found' ? 404 : 401);
}

/**
 * A client whose access token is already stale, so every call goes through the refresh path
 * unless the test says otherwise.
 */
function build(options: {
  routes: (call: Call) => Response;
  expiresIn?: number;
  events?: import('./client').ClientEvents;
  now?: () => number;
}): { client: ApiClient; store: MemoryStore; calls: Call[] } {
  const store = new MemoryStore();
  const calls: Call[] = [];
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: (init?.method ?? 'GET').toUpperCase(),
      headers: Object.fromEntries(
        Object.entries((init?.headers ?? {}) as Record<string, string>).map(([k, v]) => [k.toLowerCase(), v]),
      ),
      body: typeof init?.body === 'string' ? JSON.parse(init.body) : undefined,
    };
    calls.push(call);
    return options.routes(call);
  }) as unknown as typeof fetch;

  const client = new ApiClient({
    store,
    baseUrl: 'https://cloud.test/api/v1',
    fetchImpl,
    events: options.events,
    now: options.now ?? (() => 1_700_000_000_000),
    installationId: 'installation-1',
  });
  const login: LoginResponse = {
    access_token: 'access-1',
    refresh_token: 'refresh-1',
    expires_in: options.expiresIn ?? 900,
    refresh_expires_in: 2_592_000,
    token_type: 'Bearer',
    user: { id: 1, username: 'op', display_name: 'Op', roles: [], permissions: [] } as never,
  };
  store.session = {
    refreshToken: login.refresh_token,
    accessToken: login.access_token,
    accessExpiresAt: 1_700_000_000_000 + login.expires_in * 1000,
  };
  return { client, store, calls };
}

beforeEach(() => {
  vi.restoreAllMocks();
});

describe('headers', () => {
  it('sends the bearer token, the installation id and no cookies', async () => {
    const { client, calls } = build({
      routes: () => jsonResponse({ items: [], next_cursor: null }),
    });
    await client.request('/incidents');
    expect(calls).toHaveLength(1);
    expect(calls[0].headers.authorization).toBe('Bearer access-1');
    expect(calls[0].headers['x-installation-id']).toBe('installation-1');
    expect(calls[0].headers['x-request-id']).toMatch(/^req_/);
    expect(calls[0].url).toBe('https://cloud.test/api/v1/incidents');
  });

  it('answers a missing session locally instead of calling the service', async () => {
    const { client, calls } = build({ routes: () => jsonResponse({}) });
    await client.clearSession();
    await expect(client.request('/incidents')).rejects.toMatchObject({
      status: 401,
      code: ERROR_CODES.AUTHENTICATION_REQUIRED,
    });
    // A request that cannot be authorised is not sent: it would only be a 401 and a log line.
    expect(calls).toHaveLength(0);
  });

  it('repeats a filter that is a list rather than joining it', async () => {
    const { client } = build({ routes: () => jsonResponse({ items: [], next_cursor: null }) });
    const url = client.urlFor('/incidents', { status: ['open', 'investigating'], q: null });
    expect(new URL(url).searchParams.getAll('status')).toEqual(['open', 'investigating']);
    expect(url).not.toContain('q=');
  });
});

describe('token lifecycle', () => {
  it('rotates an expired access token once, however many calls arrive together', async () => {
    const refreshes: number[] = [];
    const { client, calls, store } = build({
      expiresIn: 1,
      routes: (call) => {
        if (call.url.endsWith('/auth/refresh')) {
          refreshes.push(calls.length);
          const body: RefreshResponse = {
            access_token: 'access-2',
            refresh_token: 'refresh-2',
            expires_in: 900,
            refresh_expires_in: 2_592_000,
            token_type: 'Bearer',
          };
          return jsonResponse(body);
        }
        return jsonResponse({ items: [], next_cursor: null });
      },
    });

    await Promise.all([
      client.request('/incidents'),
      client.request('/notifications'),
      client.request('/profile'),
    ]);

    expect(refreshes).toHaveLength(1);
    // Persisted before anything else could read it: the old refresh token is already invalid.
    expect(store.session?.refreshToken).toBe('refresh-2');
    const data = calls.filter((call) => !call.url.endsWith('/auth/refresh'));
    expect(data.map((call) => call.headers.authorization)).toEqual([
      'Bearer access-2',
      'Bearer access-2',
      'Bearer access-2',
    ]);
  });

  it('refreshes and retries once when the server rejects a token that looked live', async () => {
    const { client, calls } = build({
      routes: (call) => {
        if (call.url.endsWith('/auth/refresh')) {
          return jsonResponse({
            access_token: 'access-2',
            refresh_token: 'refresh-2',
            expires_in: 900,
            refresh_expires_in: 2_592_000,
            token_type: 'Bearer',
          });
        }
        // The server has already stopped accepting `access-1`, and says so with a 401.
        return call.headers.authorization === 'Bearer access-1'
          ? errorBody(ERROR_CODES.ACCESS_EXPIRED)
          : jsonResponse({ items: [], next_cursor: null });
      },
    });

    await expect(client.request('/incidents')).resolves.toEqual({ items: [], next_cursor: null });
    const incidents = calls.filter((call) => call.url.endsWith('/incidents'));
    expect(incidents).toHaveLength(2);
    expect(incidents[1].headers.authorization).toBe('Bearer access-2');
  });

  it('treats a refused refresh-token replay as the end of the session, not a retry', async () => {
    const forceLogout = vi.fn();
    const { client, store, calls } = build({
      expiresIn: 1,
      events: { onForceLogout: forceLogout },
      routes: (call) =>
        call.url.endsWith('/auth/refresh')
          ? jsonResponse(
              { error: { code: ERROR_CODES.REFRESH_REUSED, message: 'That token was already spent.' } },
              401,
            )
          : jsonResponse({}),
    });

    await expect(client.request('/incidents')).rejects.toBeInstanceOf(ApiError);
    expect(forceLogout).toHaveBeenCalledWith('refresh_reuse', expect.objectContaining({
      code: ERROR_CODES.REFRESH_REUSED,
    }));
    // The family is dead server-side; keeping either half locally would only invite a second
    // reuse detection, so the client stores nothing.
    expect(store.session).toBeNull();
    expect(client.hasSession).toBe(false);
    // Exactly one refresh attempt: retrying a reuse is repeating the offence.
    expect(calls.filter((call) => call.url.endsWith('/auth/refresh'))).toHaveLength(1);
  });

  it('keeps the session when the refresh endpoint itself fails', async () => {
    const forceLogout = vi.fn();
    const { client, store } = build({
      expiresIn: 1,
      events: { onForceLogout: forceLogout },
      routes: (call) =>
        call.url.endsWith('/auth/refresh')
          ? jsonResponse({ error: { code: ERROR_CODES.INTERNAL_ERROR, message: 'boom' } }, 500)
          : jsonResponse({ items: [] }),
    });

    await expect(client.request('/incidents')).rejects.toMatchObject({ status: 401 });
    // A server outage is not evidence that this handset's session is bad.
    expect(forceLogout).not.toHaveBeenCalled();
    expect(store.session?.refreshToken).toBe('refresh-1');
  });
});

describe('logout', () => {
  it('names the session and the decision, and identifies the handset by header', async () => {
    const { client, calls, store } = build({
      routes: () => jsonResponse({ signed_out: true, device_forgotten: true }),
    });

    const result = await client.logout({ forgetDevice: true });

    expect(result).toEqual({ signed_out: true, device_forgotten: true });
    const call = calls.find((item) => item.url.endsWith('/auth/logout'));
    expect(call?.body).toEqual({ forget_device: true, refresh_token: 'refresh-1' });
    expect(call?.headers['x-installation-id']).toBe('installation-1');
    expect(store.session).toBeNull();
  });

  it('clears the local session even when the service is unreachable', async () => {
    const { client, store } = build({
      routes: () => {
        throw new TypeError('offline');
      },
    });

    await expect(client.logout({ forgetDevice: false })).rejects.toBeInstanceOf(ApiError);
    // Signing out on a handset with no signal still signs the operator out.
    expect(store.session).toBeNull();
  });
});
