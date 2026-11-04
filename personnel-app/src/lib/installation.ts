/**
 * Installation identity.
 *
 * Contract §0/§3: the app owns an opaque `installation_id` UUID. It is not a
 * secret (it is sent in cleartext to /devices), but it is stable per install,
 * binds the refresh-token family (§2.2) and is the idempotency key for device
 * rows — so it is generated once and persisted.
 *
 * Storage: the secure store on native (it is device-bound identity), plain
 * `localStorage` on web where it is explicitly *not* treated as a secret.
 */
import { env } from '../config/env';

const KEY = 'watchtower.installation_id';

function randomUuid(): string {
  const c = globalThis.crypto;
  if (c && typeof c.randomUUID === 'function') return c.randomUUID();
  if (c && typeof c.getRandomValues === 'function') {
    const b = c.getRandomValues(new Uint8Array(16));
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const hex = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  // Last resort for a JS engine without crypto: still opaque, still unique
  // enough for a single device. Never used for tokens.
  let out = '';
  for (let i = 0; i < 36; i += 1) {
    out += i === 8 || i === 13 || i === 18 || i === 23 ? '-' : Math.floor(Math.random() * 16).toString(16);
  }
  return out;
}

export interface AppInfo {
  model: string;
  osVersion: string;
  appVersion: string;
  platform: string;
}

let cached: string | null = null;

export interface InstallationIdStore {
  read(): Promise<string | null>;
  write(value: string): Promise<void>;
}

/**
 * The store is injected rather than imported so the secure-store adapters
 * stay free of identity concerns (and so tests can supply a Map-backed one).
 */
export async function getInstallationId(store: InstallationIdStore): Promise<string> {
  if (cached) return cached;
  const existing = await store.read();
  if (existing && /^[0-9a-f-]{32,36}$/i.test(existing)) {
    cached = existing;
    return existing;
  }
  const fresh = randomUuid();
  cached = fresh;
  await store.write(fresh);
  return fresh;
}

/** Reset only on explicit logout-with-forget-device. */
export function resetInstallationIdCache(): void {
  cached = null;
}

export const installationKeyForEnv = `${KEY}:${env.androidAppId}`;
