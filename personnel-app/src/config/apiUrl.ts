/**
 * The cloud API endpoint, resolved from build-time configuration only.
 *
 * This module holds no `import.meta.env` reads so the rules below can be tested as a pure
 * function; `config/env.ts` feeds it the substituted literals.
 *
 * There is deliberately no default host. The previous version fell back to `http://localhost:8080`
 * and Vite also reads `.env.local` when it builds for production, so a handset was shipped with
 * the developer's own machine as its server - a phone cannot resolve that, and the login screen
 * reported it as "cannot reach the service". An unconfigured build now says so instead of guessing.
 */

export type ApiConfigState = 'ready' | 'unconfigured' | 'insecure' | 'local';

export interface ApiConfigInput {
  /** `VITE_API_URL` - the full API base including the version prefix, when given. Wins over the origin. */
  apiUrl?: string;
  /** `VITE_API_BASE_URL` - the origin alone; this module appends the contract's `/api/v1`. */
  apiBaseUrl?: string;
  /** True in `vite dev`, false in every `vite build`. */
  isDev: boolean;
}

export interface ApiConfig {
  state: ApiConfigState;
  /** Absolute API base, or the empty string when nothing usable was configured. */
  apiUrl: string;
  /** One sentence for the operator: what is wrong and what to do about it. */
  reason: string;
  /**
   * True when this build must not send a real person's credentials anywhere. A development build
   * pointed at a loopback server is a labelled local path and keeps working; the same endpoint in
   * a production build is a misconfiguration and is refused.
   */
  blocksSignIn: boolean;
  /** Origin only, for the HTTPS deep-link form. Empty when unconfigured. */
  apiOrigin: string;
}

/** The version prefix the contract puts on every route (§1). */
const API_PATH = '/api/v1';

/** `[::1]` is how `URL` reports an IPv6 loopback; a bare `::1` fails to parse as a URL at all. */
const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]', '0.0.0.0']);

function isLoopback(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(host)) return true;
  if (host.endsWith('.localhost')) return true;
  if (host.startsWith('127.')) return true;
  return false;
}

/**
 * RFC 1918 and the carrier NAT range. A control-room LAN address reaches a phone only while that
 * phone is on the campus Wi-Fi, so it is a local address in every practical sense and is never a
 * production endpoint; the contract's §0 HTTPS rule and the "no public exposure of the monitoring
 * computer" rule both point the same way.
 */
function isPrivateAddress(hostname: string): boolean {
  const host = hostname.toLowerCase();
  if (/^10\./.test(host)) return true;
  if (/^192\.168\./.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host)) return true;
  return false;
}

function originOf(url: URL): string {
  return url.origin;
}

function trimSlash(value: string): string {
  return value.replace(/\/+$/, '');
}

/**
 * `VITE_API_URL` is the full base and wins; `VITE_API_BASE_URL` is the origin and gets the contract's
 * version prefix. An origin that already carries the prefix is left alone - pasting the full URL into
 * the wrong key is the likelier mistake, and `.../api/v1/api/v1` fails as a confusing 404 rather than
 * telling anybody what happened.
 */
function pickConfiguredBase(apiUrl?: string, apiBaseUrl?: string): string {
  const full = (apiUrl ?? '').trim();
  if (full) return trimSlash(full);
  const origin = (apiBaseUrl ?? '').trim();
  if (!origin) return '';
  const base = trimSlash(origin);
  return base.toLowerCase().endsWith(API_PATH) ? base : `${base}${API_PATH}`;
}

export function resolveApiConfig({ apiUrl, apiBaseUrl, isDev }: ApiConfigInput): ApiConfig {
  const refused = (state: ApiConfigState, apiUrl: string, reason: string, blocksSignIn: boolean): ApiConfig => ({
    state,
    apiUrl,
    reason,
    blocksSignIn,
    apiOrigin: apiUrl ? safeOrigin(apiUrl) : '',
  });

  const configured = pickConfiguredBase(apiUrl, apiBaseUrl);
  if (!configured) {
    return refused(
      'unconfigured',
      '',
      'No cloud API endpoint is configured. Set VITE_API_URL (full base, including /api/v1) or ' +
        'VITE_API_BASE_URL (origin only) to the HTTPS address of the deployed cloud service.',
      true,
    );
  }

  let parsed: URL;
  try {
    parsed = new URL(configured);
  } catch {
    return refused(
      'unconfigured',
      '',
      `"${configured}" is not a full URL. Give the endpoint including its scheme, e.g. https://<cloud-host>/api/v1.`,
      true,
    );
  }

  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return refused(
      'unconfigured',
      '',
      `The endpoint scheme "${parsed.protocol}" is not http or https, so nothing can be sent to it.`,
      true,
    );
  }

  const host = parsed.hostname;
  if (isLoopback(host) || isPrivateAddress(host)) {
    // A dev build against the developer's own machine is the documented local path, so it keeps
    // working - loudly. In a packaged build the same address is a mistake that would ship.
    const who = isLoopback(host) ? `a loopback address (${host})` : `a private network address (${host})`;
    return refused(
      'local',
      configured,
      `The endpoint is ${who}, which only this computer or this LAN can reach. It is a development ` +
        'address, never the production mobile API: a phone on a mobile network cannot resolve it.',
      !isDev,
    );
  }

  if (parsed.protocol === 'http:') {
    return refused(
      'insecure',
      configured,
      `The endpoint is plain HTTP (${host}). Contract §0 requires HTTPS with a valid certificate, ` +
        'so a personnel password would cross the network in clear text.',
      !isDev,
    );
  }

  return { state: 'ready', apiUrl: configured, reason: '', blocksSignIn: false, apiOrigin: originOf(parsed) };
}

function safeOrigin(value: string): string {
  try {
    return new URL(value).origin;
  } catch {
    return '';
  }
}
