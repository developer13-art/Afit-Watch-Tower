/**
 * Keystore/Keychain-backed token store for the Capacitor build.
 *
 * Uses `capacitor-secure-storage-plugin`, which writes into the Android
 * `EncryptedSharedPreferences` protected by an AES-256 key held in the Android
 * Keystore (StrongBox when available) and into the iOS Keychain. The key never
 * leaves secure hardware and is non-exportable, so a rooted-device file dump
 * does not yield the refresh token.
 *
 * Failure posture: if the plugin is unavailable we DO NOT fall back to
 * `localStorage`. `createTokenStore()` catches the failure and degrades to the
 * web/session adapter, which visibly reports the downgrade.
 */
import { SecureStoragePlugin } from 'capacitor-secure-storage-plugin';
import type { StoredSession, StoreDescriptor, TokenStore, TokenStoreKind, TokenWrite } from './tokenStore';

const K_REFRESH = 'wt.refresh_token';
const K_ACCESS = 'wt.access_token';
const K_ACCESS_EXP = 'wt.access_expires_at';
const K_INSTALL = 'wt.installation_id';

async function read(key: string): Promise<string | null> {
  try {
    const res = await SecureStoragePlugin.get({ key });
    return res.value ?? null;
  } catch {
    // The plugin throws `key does not exist` on a miss. That is not an error.
    return null;
  }
}

async function write(key: string, value: string): Promise<void> {
  await SecureStoragePlugin.set({ key, value });
}

async function remove(key: string): Promise<void> {
  try {
    await SecureStoragePlugin.remove({ key });
  } catch {
    /* missing key is already the desired state */
  }
}

export class NativeSecureTokenStore implements TokenStore {
  readonly kind: TokenStoreKind = 'native-secure';
  readonly persistent = true;

  /** Probe the plugin. A throw here means the native bridge is absent. */
  static async create(): Promise<NativeSecureTokenStore> {
    const store = new NativeSecureTokenStore();
    await store.assertUsable();
    return store;
  }

  async assertUsable(): Promise<void> {
    // Round-trip on a dedicated probe key: proves the Keystore-backed file is
    // actually writable, not merely importable.
    const probe = `wt.probe.${Date.now()}`;
    await SecureStoragePlugin.set({ key: probe, value: 'ok' });
    const back = await SecureStoragePlugin.get({ key: probe });
    await SecureStoragePlugin.remove({ key: probe });
    if (back.value !== 'ok') throw new Error('Secure storage probe failed');
  }

  async read(): Promise<StoredSession | null> {
    const refresh = await read(K_REFRESH);
    if (!refresh) return null;
    const access = await read(K_ACCESS);
    const rawExp = await read(K_ACCESS_EXP);
    const parsedExp = rawExp ? Number(rawExp) : NaN;
    return {
      refreshToken: refresh,
      accessToken: access,
      accessExpiresAt: Number.isFinite(parsedExp) ? parsedExp : null,
    };
  }

  async write(session: TokenWrite): Promise<void> {
    await write(K_REFRESH, session.refreshToken);
    await write(K_ACCESS, session.accessToken);
    await write(K_ACCESS_EXP, String(session.accessExpiresAt));
  }

  async clear(): Promise<void> {
    await remove(K_REFRESH);
    await remove(K_ACCESS);
    await remove(K_ACCESS_EXP);
  }

  async readInstallationId(): Promise<string | null> {
    return read(K_INSTALL);
  }

  async writeInstallationId(value: string): Promise<void> {
    await write(K_INSTALL, value);
  }

  async clearInstallationId(): Promise<void> {
    await remove(K_INSTALL);
  }

  describe(): StoreDescriptor {
    return {
      kind: 'native-secure',
      persistent: true,
      hardwareBacked: true,
      warning: null,
    };
  }
}
