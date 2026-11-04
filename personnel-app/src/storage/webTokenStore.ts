/**
 * Web token store: tab-session scoped, never `localStorage`.
 *
 * The browser has no equivalent of the Android Keystore available to a plain
 * web bundle. So instead of pretending otherwise:
 *
 *   - the refresh token lives in `sessionStorage`, which is discarded when the
 *     tab closes and is not shared between tabs;
 *   - if `sessionStorage` is unavailable or throws (private mode, quota), the
 *     token lives in module memory only and a reload signs the user out;
 *   - `describe()` always reports the downgrade, and the app renders that as a
 *     visible warning banner. The web target is a debugging/admin convenience,
 *     not the production delivery path.
 *
 * There is no code path in this file that touches `localStorage`.
 */
import type { StoredSession, StoreDescriptor, TokenStore, TokenStoreKind, TokenWrite } from './tokenStore';

const S_REFRESH = 'wt.session.refresh_token';
const S_ACCESS = 'wt.session.access_token';
const S_ACCESS_EXP = 'wt.session.access_expires_at';

/**
 * Non-secret device identity is allowed in `localStorage` on web: it is a
 * public identifier sent to /devices in cleartext, not a credential. Keeping
 * it separate stops a tab reload from minting a fresh installation and orphans
 * a refresh-token family server-side.
 */
const ID_KEY = 'wt.installation_id';

interface Kv {
  get(k: string): string | null;
  set(k: string, v: string): void;
  del(k: string): void;
}

function makeSessionBackend(): { kv: Kv; label: string } {
  try {
    const probe = `${S_ACCESS}.probe`;
    window.sessionStorage.setItem(probe, '1');
    window.sessionStorage.removeItem(probe);
    return {
      label: 'sessionStorage',
      kv: {
        get: (k) => window.sessionStorage.getItem(k),
        set: (k, v) => void window.sessionStorage.setItem(k, v),
        del: (k) => void window.sessionStorage.removeItem(k),
      },
    };
  } catch {
    const mem = new Map<string, string>();
    return {
      label: 'memory',
      kv: {
        get: (k) => mem.get(k) ?? null,
        set: (k, v) => void mem.set(k, v),
        del: (k) => void mem.delete(k),
      },
    };
  }
}

export class WebSessionTokenStore implements TokenStore {
  readonly kind: TokenStoreKind = 'web-session';
  /** A refresh token does not survive the tab; that is the point. */
  readonly persistent = false;

  private readonly backend = makeSessionBackend();
  private readonly memory: Kv;

  constructor(memory?: Kv) {
    this.memory = memory ?? this.backend.kv;
  }

  private get store(): Kv {
    return this.backend.label === 'sessionStorage' ? this.backend.kv : this.memory;
  }

  async read(): Promise<StoredSession | null> {
    const refresh = this.store.get(S_REFRESH);
    if (!refresh) return null;
    const rawExp = this.store.get(S_ACCESS_EXP);
    const parsedExp = rawExp ? Number(rawExp) : NaN;
    return {
      refreshToken: refresh,
      accessToken: this.store.get(S_ACCESS),
      accessExpiresAt: Number.isFinite(parsedExp) ? parsedExp : null,
    };
  }

  async write(session: TokenWrite): Promise<void> {
    // CONTRACT §2.1: "never in localStorage". `sessionStorage` is tab-scoped,
    // which is the strongest guarantee available to a non-native bundle, and it
    // is paired with a mandatory visible warning.
    this.store.set(S_REFRESH, session.refreshToken);
    this.store.set(S_ACCESS, session.accessToken);
    this.store.set(S_ACCESS_EXP, String(session.accessExpiresAt));
  }

  async clear(): Promise<void> {
    this.store.del(S_REFRESH);
    this.store.del(S_ACCESS);
    this.store.del(S_ACCESS_EXP);
  }

  async readInstallationId(): Promise<string | null> {
    try {
      return window.localStorage.getItem(ID_KEY);
    } catch {
      return this.memory.get(ID_KEY);
    }
  }

  async writeInstallationId(value: string): Promise<void> {
    try {
      window.localStorage.setItem(ID_KEY, value);
    } catch {
      this.memory.set(ID_KEY, value);
    }
  }

  async clearInstallationId(): Promise<void> {
    try {
      window.localStorage.removeItem(ID_KEY);
    } catch {
      this.memory.del(ID_KEY);
    }
  }

  describe(): StoreDescriptor {
    return {
      kind: 'web-session',
      persistent: false,
      hardwareBacked: false,
      warning:
        this.backend.label === 'sessionStorage'
          ? 'Running in a browser: the session token is kept in tab memory (sessionStorage), not in the device Keystore. Closing the tab signs you out. Use the Android build for duty.'
          : 'Running in a browser with storage blocked: the session exists in memory only and is lost on refresh. Use the Android build for duty.',
    };
  }
}

/** Absolute last resort: memory only. Never persists anything. */
export class MemoryTokenStore implements TokenStore {
  readonly kind: TokenStoreKind = 'memory';
  readonly persistent = false;
  private session: StoredSession | null = null;
  private installationId: string | null = null;

  async read(): Promise<StoredSession | null> {
    return this.session;
  }

  async write(session: TokenWrite): Promise<void> {
    this.session = {
      refreshToken: session.refreshToken,
      accessToken: session.accessToken,
      accessExpiresAt: session.accessExpiresAt,
    };
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

  describe(): StoreDescriptor {
    return {
      kind: 'memory',
      persistent: false,
      hardwareBacked: false,
      warning:
        'Secure storage is unavailable on this platform. The session lives in memory only: reloading the page signs you out, and push registration cannot survive a restart.',
    };
  }
}
