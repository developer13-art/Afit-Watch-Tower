/**
 * Composition root for the networking layer.
 *
 * Exactly one place decides: which token store adapter is live, whether the
 * fixture transport is installed, and which callbacks the session provider
 * subscribes to. Everything else receives the client.
 */
import { ApiClient, setApiClient } from './api/client';
import type { ClientEvents } from './api/client';
import { env } from './config/env';
import { createTokenStore } from './storage';
import type { TokenStore } from './storage/tokenStore';
import { getInstallationId, resetInstallationIdCache } from './lib/installation';

/**
 * Late-bound event handlers. The client is constructed before React mounts, so
 * `SessionProvider` assigns these in an effect rather than passing them to the
 * constructor.
 */
export const clientEvents: ClientEvents = {};

export interface BootstrappedApp {
  client: ApiClient;
  store: TokenStore;
  /** Hardware-backed storage notice for the security banner. */
  storageNotice: string | null;
  installationId: string;
  fixturesActive: boolean;
}

let bootstrapped: BootstrappedApp | null = null;

export async function bootstrap(): Promise<BootstrappedApp> {
  if (bootstrapped) return bootstrapped;

  const { store, notice } = await createTokenStore();

  // The fixture transport is reachable only through this single branch.
  //
  // The condition is written with `import.meta.env.DEV` INLINE rather than via
  // `env.fixturesEnabled`: Vite substitutes the literal `false` at build time,
  // so `vite build` sees `if (false && ...)` and drops the dynamic import from
  // the bundle entirely. A production build therefore contains no fixture data
  // at all — verified by `npm run verify:fixtures`.
  let fetchImpl: typeof fetch | undefined;
  if (import.meta.env.DEV && import.meta.env.VITE_USE_FIXTURES === '1') {
    const { fixtureFetch } = await import('./devfixtures/transport');
    fetchImpl = fixtureFetch;
  }

  const client = new ApiClient({
    store,
    baseUrl: env.apiUrl,
    fetchImpl,
    events: {
      onForceLogout: (reason, error) => clientEvents.onForceLogout?.(reason, error),
      onTokensChanged: (tokens) => clientEvents.onTokensChanged?.(tokens),
      onConnectivity: (online) => clientEvents.onConnectivity?.(online),
    },
  });

  setApiClient(client);

  const installationId = await getInstallationId({
    read: () => store.readInstallationId(),
    write: (v) => store.writeInstallationId(v),
  });
  // The server needs this on every authenticated call to be able to retire
  // *this* handset at sign-out; without it "forget this device" is a no-op.
  client.setInstallationId(installationId);

  bootstrapped = {
    client,
    store,
    storageNotice: notice,
    installationId,
    fixturesActive: env.fixturesEnabled,
  };
  return bootstrapped;
}

/** Used by tests to build an isolated client over an in-memory store. */
export function resetBootstrap(): void {
  setApiClient(null);
  bootstrapped = null;
  resetInstallationIdCache();
}
