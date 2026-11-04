/**
 * Adapter selection.
 *
 * Native build  -> Keystore/Keychain (`NativeSecureTokenStore`).
 * Web build     -> tab-session (`WebSessionTokenStore`) with a visible warning.
 * Neither works -> memory (`MemoryTokenStore`), also warned.
 *
 * `localStorage` is never a token destination. The only `localStorage` use in
 * this app is the non-secret installation identifier, and it is confined to
 * `WebSessionTokenStore`.
 */
import { Capacitor } from '@capacitor/core';
import { NativeSecureTokenStore } from './nativeSecureTokenStore';
import { MemoryTokenStore, WebSessionTokenStore } from './webTokenStore';
import type { TokenStore } from './tokenStore';

export type TokenStoreKind = 'native-secure' | 'web-session' | 'memory';

export interface TokenStoreSetup {
  store: TokenStore;
  /** Populated when the platform could not offer hardware-backed storage. */
  notice: string | null;
}

let instance: TokenStore | null = null;
let notice: string | null = null;

export function isNativePlatform(): boolean {
  try {
    return Capacitor.isNativePlatform();
  } catch {
    return false;
  }
}

export async function createTokenStore(): Promise<TokenStoreSetup> {
  if (instance) return { store: instance, notice };

  if (isNativePlatform()) {
    try {
      instance = await NativeSecureTokenStore.create();
      notice = null;
      return { store: instance, notice };
    } catch (err) {
      // Explicit, loud degradation. The plugin is present in package.json;
      // reaching here means the native bridge failed at runtime.
      const fallback = new WebSessionTokenStore();
      instance = fallback;
      notice =
        `Android Keystore storage was unavailable (${err instanceof Error ? err.message : 'unknown error'}). ` +
        `${fallback.describe().warning}`;
      return { store: instance, notice };
    }
  }

  const web = new WebSessionTokenStore();
  instance = web;
  notice = web.describe().warning;
  return { store: instance, notice };
}

/** Test seam and cold-start reset. */
export function setTokenStoreForTests(store: TokenStore | null, storeNotice: string | null = null): void {
  instance = store;
  notice = storeNotice;
}

export function getTokenStoreSync(): TokenStore {
  return instance ?? new MemoryTokenStore();
}
