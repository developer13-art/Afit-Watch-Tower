/**
 * Auth session state machine.
 *
 * Pure reducer, no side effects, so it can be unit-tested without a DOM. The
 * provider performs the I/O (cold start, login, logout) and dispatches.
 *
 * Invariants:
 *   - `must_change_password` from the server forces `password_required`, and no
 *     screen other than the password screen may render in that state (§2.1).
 *   - A held deep-link destination survives logout/login transitions in memory
 *     only (§12 — never persisted, because it names an incident).
 *   - The permission set is only ever read from `/auth/me` (§2.5).
 */
import type { ApiError } from '../api/errors';
import type { AuthMeResponse } from '../types/api';
import type { LogoutReason } from '../api/client';

export type SessionStatus =
  /** Cold start: reading the secure store and validating /auth/me. */
  | 'booting'
  | 'anonymous'
  | 'authenticated'
  /** Authenticated but the account still carries the default password (§2.1). */
  | 'password_required'
  /** Cold start failed for a non-auth reason (server fault, network). */
  | 'boot_error';

export interface PushState {
  /** `unsupported` covers the web build and devices without Google Play services. */
  permission: 'unknown' | 'unsupported' | 'prompt' | 'granted' | 'denied';
  token: string | null;
  /** Registration error text from the native plugin, shown verbatim. */
  registrationError: string | null;
  /** Last successful `POST /devices` outcome for this installation. */
  registered: boolean;
  registering: boolean;
}

export interface SessionState {
  status: SessionStatus;
  user: AuthMeResponse | null;
  /** Set when the login form must show an error; cleared on any retry. */
  loginError: ApiError | null;
  loggingIn: boolean;
  /** Incident route the user was aiming at before signing in (§12). */
  pendingDestination: string | null;
  online: boolean;
  /** Security-posture notice from the token store adapter. */
  storageWarning: string | null;
  push: PushState;
  /** Reason recorded when the server terminated the session. */
  lastLogoutReason: LogoutReason | null;
  /** Bumped whenever the server returned a fresh permission set, to refetch screens. */
  revision: number;
}

export const initialSessionState: SessionState = {
  status: 'booting',
  user: null,
  loginError: null,
  loggingIn: false,
  pendingDestination: null,
  online: true,
  storageWarning: null,
  push: { permission: 'unknown', token: null, registrationError: null, registered: false, registering: false },
  lastLogoutReason: null,
  revision: 0,
};

export type SessionAction =
  | { type: 'BOOT_START' }
  | { type: 'BOOT_ANONYMOUS' }
  | { type: 'BOOT_ERROR'; error: ApiError }
  | { type: 'LOGIN_START' }
  | { type: 'LOGIN_FAILED'; error: ApiError }
  | { type: 'LOGIN_CLEARED' }
  | { type: 'AUTHENTICATED'; user: AuthMeResponse }
  | { type: 'USER_PATCHED'; patch: Partial<AuthMeResponse> }
  | { type: 'PASSWORD_CHANGE_COMPLETE' }
  | { type: 'LOGOUT'; reason: LogoutReason }
  | { type: 'HOLD_DESTINATION'; destination: string | null }
  | { type: 'CONSUME_DESTINATION' }
  | { type: 'CONNECTIVITY'; online: boolean }
  | { type: 'STORAGE_WARNING'; warning: string | null }
  | { type: 'PUSH_PATCH'; patch: Partial<PushState> };

function statusForUser(user: AuthMeResponse): SessionStatus {
  return user.must_change_password ? 'password_required' : 'authenticated';
}

export function sessionReducer(state: SessionState, action: SessionAction): SessionState {
  switch (action.type) {
    case 'BOOT_START':
      return { ...state, status: 'booting' };

    case 'BOOT_ANONYMOUS':
      return {
        ...state,
        status: 'anonymous',
        user: null,
        loginError: null,
        lastLogoutReason: null,
      };

    case 'BOOT_ERROR':
      // A cold-start network failure must not masquerade as "not signed in":
      // the operator sees a retry, not a login form they cannot use.
      return { ...state, status: 'boot_error', loginError: action.error };

    case 'LOGIN_START':
      return { ...state, loggingIn: true, loginError: null };

    case 'LOGIN_FAILED':
      return { ...state, loggingIn: false, loginError: action.error, status: 'anonymous' };

    case 'LOGIN_CLEARED':
      return { ...state, loginError: null };

    case 'AUTHENTICATED':
      return {
        ...state,
        status: statusForUser(action.user),
        user: action.user,
        loginError: null,
        loggingIn: false,
        lastLogoutReason: null,
        revision: state.revision + 1,
      };

    case 'USER_PATCHED': {
      if (!state.user) return state;
      const user = { ...state.user, ...action.patch };
      return {
        ...state,
        user,
        status: statusForUser(user),
        revision: state.revision + 1,
      };
    }

    case 'PASSWORD_CHANGE_COMPLETE': {
      if (!state.user) return { ...state, status: 'anonymous' };
      const user = { ...state.user, must_change_password: false };
      return { ...state, user, status: 'authenticated', revision: state.revision + 1 };
    }

    case 'LOGOUT':
      return {
        ...initialSessionState,
        // The held destination is deliberately preserved through an implicit
        // logout so a tapped push still lands after re-login (§12), but only
        // when the session was terminated against the user's will.
        pendingDestination: action.reason === 'refresh_reuse' ? null : state.pendingDestination,
        online: state.online,
        storageWarning: state.storageWarning,
        push: state.push,
        status: 'anonymous',
        lastLogoutReason: action.reason,
      };

    case 'HOLD_DESTINATION':
      return { ...state, pendingDestination: action.destination };

    case 'CONSUME_DESTINATION':
      return { ...state, pendingDestination: null };

    case 'CONNECTIVITY':
      return { ...state, online: action.online };

    case 'STORAGE_WARNING':
      return { ...state, storageWarning: action.warning };

    case 'PUSH_PATCH':
      return { ...state, push: { ...state.push, ...action.patch } };

    default:
      return state;
  }
}

/** Guards used by the router. */
export const session = {
  isAuthenticated: (s: SessionState) => s.status === 'authenticated',
  needsPasswordChange: (s: SessionState) => s.status === 'password_required',
  /** True while the cold start is still resolving. */
  isBooting: (s: SessionState) => s.status === 'booting',
  canRenderApp: (s: SessionState) => s.status === 'authenticated',
};
