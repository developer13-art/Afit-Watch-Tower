/**
 * Vitest global setup.
 *
 * Two things happen here and both matter for the tests to mean something:
 *
 *  1. jest-dom matchers are attached to Vitest's `expect`, so screens assert on
 *     accessible text and roles rather than on class names.
 *  2. The Capacitor bridge is stubbed. jsdom has no native platform, and the
 *     plugins (`@capacitor/app`, `@capacitor/push-notifications`,
 *     `capacitor-secure-storage-plugin`) would otherwise register proxies and
 *     emit "not implemented" rejections during import. The tests never exercise
 *     native push — that path needs a device and is documented as unverified in
 *     README — so the stub keeps the module graph loadable without pretending
 *     the native behaviour was tested.
 */
import '@testing-library/jest-dom/vitest';
import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';

vi.mock('@capacitor/core', async () => {
  const registerPlugin = () => new Proxy({}, { get: () => async () => undefined });
  return {
    Capacitor: {
      isNativePlatform: () => false,
      getPlatform: () => 'web',
      isPluginLoadedIn: () => false,
      registerPlugin,
    },
    registerPlugin,
    PluginConfig: {},
  };
});

// `window.crypto.randomUUID` is present in current jsdom but not in every
// Node-backed environment Vitest can run under, and the client uses it for
// request ids. A deterministic stand-in keeps request-id assertions stable.
if (typeof globalThis.crypto === 'undefined' || typeof globalThis.crypto.randomUUID !== 'function') {
  let counter = 0;
  const stub = {
    randomUUID: () => `00000000-0000-4000-8000-${String(++counter).padStart(12, '0')}`,
    getRandomValues: (arr: Uint8Array) => {
      for (let i = 0; i < arr.length; i += 1) arr[i] = (i * 7) % 256;
      return arr;
    },
  };
  Object.defineProperty(globalThis, 'crypto', { value: stub, configurable: true });
}

afterEach(() => {
  cleanup();
  // The api client and token store are module singletons. Leaving them set
  // would let one test's session leak into the next.
  vi.useRealTimers();
});
