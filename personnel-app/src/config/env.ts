/**
 * Runtime environment resolution.
 *
 * Everything here is baked into the bundle at build time by Vite. Treat every
 * value as public. If a value should not appear in a JavaScript file, it does
 * not belong in this app at all (see .env.example HARD RULES).
 */

import { resolveApiConfig, type ApiConfig } from './apiUrl';

const raw = import.meta.env as unknown as Record<string, string | boolean | undefined>;

function str(key: string, fallback = ''): string {
  const v = raw[key];
  return typeof v === 'string' && v.length > 0 ? v : fallback;
}

function int(key: string, fallback: number): number {
  const v = Number(str(key, ''));
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

/**
 * Fixtures require BOTH Vite DEV mode and an explicit opt-in.
 *
 * IMPORTANT: this expression reads `import.meta.env.DEV` directly so Vite can
 * substitute the literal at build time. `vite build` replaces it with `false`,
 * the `&&` short-circuits, and the fixture module is dropped from the bundle.
 * Indirecting this through `raw[...]` would defeat the substitution and ship
 * fixture data in production — `npm run verify:fixtures` fails loudly if that
 * ever happens again.
 */
export const FIXTURES_ENABLED = import.meta.env.DEV && import.meta.env.VITE_USE_FIXTURES === '1';

/** `import.meta.env.DEV` is `false` in every production build. */
export const IS_DEV = import.meta.env.DEV === true;

function trimSlash(v: string): string {
  return v.replace(/\/+$/, '');
}

/**
 * The single place the endpoint is decided. There is no fallback host: an unset configuration
 * resolves to `state: 'unconfigured'` with an empty URL, and the screens say so. Both keys are
 * handed over raw - `apiUrl.ts` owns the `/api/v1` rule and the safety classification.
 */
export const apiConfig: ApiConfig = resolveApiConfig({
  apiUrl: str('VITE_API_URL'),
  apiBaseUrl: str('VITE_API_BASE_URL'),
  isDev: import.meta.env.DEV === true,
});

export interface AppEnv {
  /** Contract §1: base URL is `https://<cloud-host>/api/v1`. */
  apiUrl: string;
  /** Origin only — used to build the HTTPS deep-link form (§12). */
  apiOrigin: string;
  appEnv: string;
  androidAppId: string;
  apiTimeoutMs: number;
  authTimeoutMs: number;
  /** Foreground cadence for re-reading the queue and the notification list. 0 disables it. */
  alertPollMs: number;
  fixturesEnabled: boolean;
  isProductionBuild: boolean;
  /** Custom scheme for `watchtower://incidents/{id}` (§12). */
  deepLinkScheme: string;
  /** Contract §10.8: the authenticated live channel. Absolute URL, no cursor. */
  liveFeedUrl: string;
  /**
   * The live channel is a delivery *accelerator*, not the delivery mechanism: the foreground poll
   * stays on even when this is true, so switching it off costs latency and nothing else. Fixtures
   * force it off because the fake transport has no stream to serve.
   */
  liveFeedEnabled: boolean;
}

function resolveLiveFeedUrl(apiUrl: string): string {
  const explicit = str('VITE_LIVE_FEED_URL');
  if (explicit) return trimSlash(explicit);
  if (!apiUrl) return '';
  return `${trimSlash(apiUrl)}/events/stream`;
}

/**
 * The package version, injected by `vite.config.ts` from `package.json`. A literal here would be
 * a second place to forget on release day, and the About screen is read by someone troubleshooting
 * a handset — a wrong version there is worse than no version.
 */
export const APP_VERSION: string = typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : '0.0.0-dev';

export const env: AppEnv = {
  apiUrl: apiConfig.apiUrl,
  apiOrigin: apiConfig.apiOrigin,
  appEnv: str('VITE_APP_ENV', import.meta.env.DEV ? 'development' : 'production'),
  androidAppId: str('VITE_ANDROID_APP_ID', 'com.afit.watchtower.personnel'),
  apiTimeoutMs: int('VITE_API_TIMEOUT_MS', 12_000),
  authTimeoutMs: int('VITE_AUTH_TIMEOUT_MS', 15_000),
  alertPollMs: Math.max(0, int('VITE_ALERT_POLL_SECONDS', 20)) * 1000,
  fixturesEnabled: FIXTURES_ENABLED,
  isProductionBuild: !import.meta.env.DEV,
  deepLinkScheme: 'watchtower',
  liveFeedUrl: resolveLiveFeedUrl(apiConfig.apiUrl),
  // A stream needs an endpoint to hold one open, so it follows the same rule as the poll.
  liveFeedEnabled: str('VITE_LIVE_FEED', '1') !== '0' && !FIXTURES_ENABLED && apiConfig.apiUrl.length > 0,
};

/** True when the app is talking to a non-TLS host — surfaced in the UI. */
export const isInsecureApiHost = (): boolean => {
  if (env.fixturesEnabled) return false;
  return apiConfig.state === 'insecure' || apiConfig.state === 'local';
};

export const firebaseWebConfig = () => {
  const apiKey = str('VITE_FIREBASE_API_KEY');
  const projectId = str('VITE_FIREBASE_PROJECT_ID');
  if (!apiKey || !projectId) return null;
  return {
    apiKey,
    authDomain: str('VITE_FIREBASE_AUTH_DOMAIN'),
    projectId,
    storageBucket: str('VITE_FIREBASE_STORAGE_BUCKET'),
    messagingSenderId: str('VITE_FIREBASE_MESSAGING_SENDER_ID'),
    appId: str('VITE_FIREBASE_APP_ID'),
  };
};
