/**
 * Token storage contract.
 *
 * Non-negotiable rules this interface exists to enforce:
 *   1. A refresh token never enters `localStorage`. Not "preferably not" — never.
 *   2. The native implementation is Keystore/Keychain-backed.
 *   3. The web implementation is tab-session scoped and announces that fact to
 *      the UI. There is no silent downgrade path: `describe()` returns the
 *      warning that a banner renders.
 *   4. If neither is available, memory-only. A refresh loses the session and the
 *      user signs in again. That is the intended failure mode.
 */

export type TokenStoreKind = 'native-secure' | 'web-session' | 'memory';

export interface TokenWrite {
  refreshToken: string;
  accessToken: string;
  /** Epoch ms when the access token stops being usable. */
  accessExpiresAt: number;
}

export interface TokenStore {
  readonly kind: TokenStoreKind;
  /** True when a value survives an app restart. */
  readonly persistent: boolean;
  read(): Promise<StoredSession | null>;
  write(session: TokenWrite): Promise<void>;
  /** Rotate only the pair produced by /auth/refresh. */
  clear(): Promise<void>;
  /** Non-secret device identity, same backing as the tokens. */
  readInstallationId(): Promise<string | null>;
  writeInstallationId(value: string): Promise<void>;
  clearInstallationId(): Promise<void>;
  /** Human explanation for the security banner. */
  describe(): StoreDescriptor;
}

export interface StoredSession {
  refreshToken: string;
  accessToken: string | null;
  accessExpiresAt: number | null;
}

export interface StoreDescriptor {
  kind: TokenStoreKind;
  persistent: boolean;
  /** Hardware-backed (Keystore/Keychain). */
  hardwareBacked: boolean;
  /** null when there is nothing to warn about. */
  warning: string | null;
}
