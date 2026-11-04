/**
 * Session provider: the only component allowed to change auth state.
 *
 * Cold start sequence (§2.5):
 *   1. build the client + read the Keystore-backed refresh family
 *   2. if a refresh token exists, GET /auth/me (the client transparently
 *      refreshes the expired access token first)
 *   3. authenticated / password_required / anonymous / boot_error
 *
 * Push wiring starts only for an authenticated session: registering a device
 * for an anonymous caller would create an orphan row server-side.
 */
import { createContext, useCallback, useContext, useEffect, useMemo, useReducer, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { App } from '@capacitor/app';
import type { PushNotificationSchema } from '@capacitor/push-notifications';
import { ApiError } from '../api/errors';
import { authApi, notificationsApi } from '../api/endpoints';
import { bootstrap, clientEvents } from '../bootstrap';
import type { BootstrappedApp } from '../bootstrap';
import { env } from '../config/env';
import { useLiveFeed } from '../hooks/useLiveFeed';
import { initialSessionState, session, sessionReducer } from './session';
import type { SessionState } from './session';
import { ERROR_CODES } from '../types/api';
import type { AuthMeResponse, LiveStatus, NotificationItem } from '../types/api';
import { readDeviceInfo } from '../platform';
import { hasPermission } from './permissions';
import {
  checkPushPermission,
  registerForPush,
  reportDevice,
  requestPushPermission,
} from '../push/pushRuntime';
import type { PushHandle } from '../push/pushRuntime';

export interface ForegroundAlert {
  id: string;
  title: string;
  body: string;
  severity: string;
  incidentId: number | null;
  notificationId: number | null;
}

export interface SessionContextValue {
  state: SessionState;
  app: BootstrappedApp | null;
  /** True once bootstrap finished, whether or not a session exists. */
  ready: boolean;
  login: (username: string, password: string) => Promise<{ ok: boolean; error?: ApiError }>;
  logout: (options?: { forgetDevice?: boolean }) => Promise<void>;
  changePassword: (current: string, next: string) => Promise<{ ok: boolean; error?: ApiError }>;
  refreshMe: () => Promise<AuthMeResponse | null>;
  holdDestination: (destination: string | null) => void;
  consumeDestination: () => string | null;
  can: (permission: string) => boolean;
  retryBoot: () => void;
  /** Unread badge, maintained by the notification centre and pushed alerts. */
  unreadCount: number;
  setUnreadCount: (n: number) => void;
  foregroundAlerts: ForegroundAlert[];
  dismissForegroundAlert: (id: string) => void;
  /** Ask the OS for notification permission and start registration. */
  enablePush: () => Promise<boolean>;
  /** Contract §10.8 live channel state, for the shell's connection notice. */
  liveStatus: LiveStatus;
  liveDetail: string | null;
  /** Bumped by a live `notification` frame; the queue, the badge and the dashboard read on it. */
  notificationRevision: number;
  /** Bumped by a live `incident_activity` frame; the incident list and the open incident read on it. */
  activityRevision: number;
}

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(sessionReducer, initialSessionState);
  const [app, setApp] = useState<BootstrappedApp | null>(null);
  const [ready, setReady] = useState(false);
  const [bootNonce, setBootNonce] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);
  const [foregroundAlerts, setForegroundAlerts] = useState<ForegroundAlert[]>([]);
  const navigate = useNavigate();

  const pushHandle = useRef<PushHandle | null>(null);
  const statusRef = useRef(state.status);
  statusRef.current = state.status;
  const installationRef = useRef<string>('');

  // ------------------------------------------------------------------ live channel
  // Two counters, not one: a new alert touches the queue and the badge, an officer's action on an
  // incident touches the incident list and whatever incident is open. Screens that refreshed on both
  // would re-read half the API for every frame.
  const [notificationRevision, setNotificationRevision] = useState(0);
  const [activityRevision, setActivityRevision] = useState(0);

  const onLiveNotification = useCallback((item: NotificationItem) => {
    setUnreadCount((n) => n + 1);
    // A deterministic alert id is the dedupe: the foreground poll and the live feed both can
    // deliver the same row, and the officer must not see the same alert twice.
    setForegroundAlerts((prev) =>
      prev.some((alert) => alert.id === `live-${item.id}`)
        ? prev
        : [
            ...prev,
            {
              id: `live-${item.id}`,
              title: item.title,
              body: item.body,
              severity: item.severity,
              incidentId: item.incident_id,
              notificationId: item.id,
            },
          ],
    );
    setNotificationRevision((n) => n + 1);
  }, []);

  const onLiveActivity = useCallback(() => {
    setActivityRevision((n) => n + 1);
  }, []);

  const live = useLiveFeed(app?.client ?? null, {
    enabled: state.status === 'authenticated' && env.liveFeedEnabled,
    installationId: app?.installationId ?? '',
  }, { onNotification: onLiveNotification, onActivity: onLiveActivity });

  // ------------------------------------------------------------------ events
  useEffect(() => {
    clientEvents.onForceLogout = (reason, error) => {
      pushHandle.current?.stop();
      pushHandle.current = null;
      dispatch({ type: 'LOGOUT', reason });
      if (reason === 'refresh_reuse') {
        setForegroundAlerts((prev) => [
          ...prev,
          {
            id: `reuse-${Date.now()}`,
            title: 'Session revoked',
            body:
              error?.message ||
              'This device’s session family was invalidated after a replayed refresh token was detected. Sign in again.',
            severity: 'critical',
            incidentId: null,
            notificationId: null,
          },
        ]);
      }
      navigate('/login', { replace: true });
    };
    clientEvents.onConnectivity = (online) => dispatch({ type: 'CONNECTIVITY', online });
    return () => {
      clientEvents.onForceLogout = undefined;
      clientEvents.onConnectivity = undefined;
    };
  }, [navigate]);

  // ------------------------------------------------------------------ cold start
  const boot = useCallback(async () => {
    dispatch({ type: 'BOOT_START' });
    setReady(false);
    let booted: BootstrappedApp;
    try {
      booted = await bootstrap();
      installationRef.current = booted.installationId;
      setApp(booted);
      dispatch({ type: 'STORAGE_WARNING', warning: booted.storageNotice });
      dispatch({ type: 'CONNECTIVITY', online: booted.client.isOnline });
    } catch (err) {
      dispatch({
        type: 'BOOT_ERROR',
        error:
          err instanceof ApiError
            ? err
            : new ApiError({
                code: ERROR_CODES.UNKNOWN,
                message: 'Secure storage could not be opened on this device.',
                kind: 'parse',
              }),
      });
      setReady(true);
      return;
    }

    try {
      const hasSession = await booted.client.hydrate();
      if (!hasSession) {
        dispatch({ type: 'BOOT_ANONYMOUS' });
        return;
      }
      const me = await authApi.me();
      dispatch({ type: 'AUTHENTICATED', user: me });
    } catch (err) {
      const apiError =
        err instanceof ApiError
          ? err
          : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Cold start failed.', kind: 'parse' });
      if (apiError.status === 401 || apiError.code === ERROR_CODES.AUTHENTICATION_REQUIRED) {
        // The family is gone (expired, revoked, or already reuse-detected —
        // the client fired onForceLogout for us in that case).
        await booted.client.clearSession();
        dispatch({ type: 'BOOT_ANONYMOUS' });
      } else {
        // Connectivity or server fault: show a retry, not a login form.
        dispatch({ type: 'BOOT_ERROR', error: apiError });
      }
    } finally {
      setReady(true);
    }
  }, []);

  useEffect(() => {
    void boot();
  }, [boot, bootNonce]);

  // ------------------------------------------------------------------ actions
  const login = useCallback(async (username: string, password: string) => {
    dispatch({ type: 'LOGIN_START' });
    try {
      const booted = await bootstrap();
      installationRef.current = booted.installationId;
      const info = readDeviceInfo();
      const res = await booted.client.login(username, password, {
        installation_id: booted.installationId,
        platform: info.platform,
        model: info.model,
        os_version: info.osVersion,
        app_version: info.appVersion,
      });
      // §2.5: /auth/me is the only place the permission set is read from, so
      // the login body's copy is discarded in favour of a fresh read.
      const me = await authApi.me().catch(() => res.user as AuthMeResponse);
      dispatch({ type: 'AUTHENTICATED', user: me });
      return { ok: true } as const;
    } catch (err) {
      const apiError =
        err instanceof ApiError
          ? err
          : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Sign-in failed.', kind: 'parse' });
      dispatch({ type: 'LOGIN_FAILED', error: apiError });
      return { ok: false, error: apiError } as const;
    }
  }, []);

  const logout = useCallback(
    async (options?: { forgetDevice?: boolean }) => {
      const forgetDevice = options?.forgetDevice ?? false;
      const booted = app ?? (await bootstrap());
      let deviceForgotten = false;
      try {
        const result = await booted.client.logout({ forgetDevice });
        deviceForgotten = Boolean(result.device_forgotten);
      } catch {
        // Offline logout still has to clear the device.
        await booted.client.clearSession();
      }
      pushHandle.current?.stop();
      pushHandle.current = null;
      setUnreadCount(0);
      setForegroundAlerts([]);
      dispatch({ type: 'LOGOUT', reason: 'explicit' });
      if (forgetDevice && !deviceForgotten) {
        dispatch({
          type: 'PUSH_PATCH',
          patch: {
            registrationError:
              'You were signed out, but this handset could not be forgotten. If the device is lost or shared, remove it from Profile > Devices once you are back online.',
          },
        });
      }
      navigate('/login', { replace: true });
    },
    [app, navigate],
  );

  const changePassword = useCallback(async (current: string, next: string) => {
    try {
      await authApi.changePassword({ current_password: current, new_password: next });
      dispatch({ type: 'PASSWORD_CHANGE_COMPLETE' });
      return { ok: true } as const;
    } catch (err) {
      return {
        ok: false,
        error:
          err instanceof ApiError
            ? err
            : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Could not change the password.', kind: 'parse' }),
      } as const;
    }
  }, []);

  const refreshMe = useCallback(async () => {
    try {
      const me = await authApi.me();
      dispatch({ type: 'AUTHENTICATED', user: me });
      return me;
    } catch {
      return null;
    }
  }, []);

  const holdDestination = useCallback((destination: string | null) => {
    dispatch({ type: 'HOLD_DESTINATION', destination });
  }, []);

  const destinationRef = useRef<string | null>(null);
  destinationRef.current = state.pendingDestination;

  const consumeDestination = useCallback(() => {
    const d = destinationRef.current;
    dispatch({ type: 'CONSUME_DESTINATION' });
    return d;
  }, []);

  const can = useCallback((permission: string) => hasPermission(state.user, permission), [state.user]);

  // ------------------------------------------------------------------ push
  const pushHandlers = useMemo(
    () => ({
      onToken: async (token: string) => {
        dispatch({ type: 'PUSH_PATCH', patch: { token, registering: true, registrationError: null } });
        try {
          const info = readDeviceInfo();
          await reportDevice({
            installationId: installationRef.current,
            pushToken: token,
            model: info.model,
            osVersion: info.osVersion,
            appVersion: info.appVersion,
          });
          dispatch({ type: 'PUSH_PATCH', patch: { registered: true, registering: false } });
        } catch (err) {
          dispatch({
            type: 'PUSH_PATCH',
            patch: {
              registered: false,
              registering: false,
              registrationError:
                err instanceof ApiError
                  ? err.userMessage
                  : 'The device could not be registered with the notification service.',
            },
          });
        }
      },
      onPermission: (granted: boolean) =>
        dispatch({ type: 'PUSH_PATCH', patch: { permission: granted ? 'granted' : 'denied' } }),
      onForeground: (notification: PushNotificationSchema) => {
        const data = (notification.data ?? {}) as Record<string, unknown>;
        const rawIncident = data.incident_id;
        const incidentId = rawIncident != null && Number.isSafeInteger(Number(rawIncident)) ? Number(rawIncident) : null;
        const rawNotification = data.notification_id;
        const notificationId =
          rawNotification != null && Number.isSafeInteger(Number(rawNotification)) ? Number(rawNotification) : null;
        setUnreadCount((n) => n + 1);
        setForegroundAlerts((prev) => [
          ...prev,
          {
            id: `fg-${Date.now()}-${Math.random().toString(16).slice(2, 6)}`,
            title: notification.title ?? 'WATCH TOWER alert',
            body: notification.body ?? '',
            severity: typeof data.severity === 'string' ? data.severity : 'medium',
            incidentId,
            notificationId,
          },
        ]);
      },
      onOpen: (link: { route: string }, notificationId: number | null) => {
        if (notificationId) void reportOpenBestEffort(notificationId);
        if (statusRef.current === 'authenticated') {
          navigate(link.route);
        } else {
          // §12 — hold the destination in memory, sign in, then restore it.
          dispatch({ type: 'HOLD_DESTINATION', destination: link.route });
          navigate('/login');
        }
      },
      onError: (message: string) =>
        dispatch({ type: 'PUSH_PATCH', patch: { registrationError: message || null, registering: false } }),
    }),
    [navigate],
  );

  /** Reflect the real OS permission without prompting. */
  useEffect(() => {
    if (env.fixturesEnabled) {
      dispatch({ type: 'PUSH_PATCH', patch: { permission: 'unsupported' } });
      return;
    }
    let cancelled = false;
    void checkPushPermission().then((p) => {
      if (!cancelled) dispatch({ type: 'PUSH_PATCH', patch: { permission: p } });
    });
    return () => {
      cancelled = true;
    };
  }, []);

  /** Start delivery once the session is real and permission already granted. */
  useEffect(() => {
    if (state.status !== 'authenticated' || env.fixturesEnabled) return;
    if (state.push.permission !== 'granted') return;
    let stopped = false;
    void registerForPush(pushHandlers).then((handle) => {
      if (stopped) {
        handle.stop();
        return;
      }
      pushHandle.current?.stop();
      pushHandle.current = handle;
    });
    return () => {
      stopped = true;
    };
  }, [state.status, state.push.permission, pushHandlers]);

  const enablePush = useCallback(async () => {
    if (env.fixturesEnabled) return false;
    dispatch({ type: 'PUSH_PATCH', patch: { registering: true } });
    let granted = false;
    try {
      granted = await requestPushPermission();
    } catch {
      granted = false;
    }
    if (!granted) {
      dispatch({ type: 'PUSH_PATCH', patch: { permission: 'denied', registering: false } });
      return false;
    }
    dispatch({ type: 'PUSH_PATCH', patch: { permission: 'granted', registering: false } });
    pushHandle.current?.stop();
    pushHandle.current = await registerForPush(pushHandlers);
    return true;
  }, [pushHandlers]);

  // Android hardware back button: leave the app from the tab roots.
  useEffect(() => {
    const handle = App.addListener('backButton', ({ canGoBack }) => {
      if (!canGoBack) void App.exitApp();
    });
    return () => {
      void handle.then((h) => h.remove()).catch(() => undefined);
    };
  }, []);

  const dismissForegroundAlert = useCallback((id: string) => {
    setForegroundAlerts((prev) => prev.filter((a) => a.id !== id));
  }, []);

  const value = useMemo<SessionContextValue>(
    () => ({
      state,
      app,
      ready,
      login,
      logout,
      changePassword,
      refreshMe,
      holdDestination,
      consumeDestination,
      can,
      retryBoot: () => setBootNonce((n) => n + 1),
      unreadCount,
      setUnreadCount,
      foregroundAlerts,
      dismissForegroundAlert,
      enablePush,
      liveStatus: live.status,
      liveDetail: live.detail,
      notificationRevision,
      activityRevision,
    }),
    [
      state,
      app,
      ready,
      login,
      logout,
      changePassword,
      refreshMe,
      holdDestination,
      consumeDestination,
      can,
      bootNonce,
      unreadCount,
      foregroundAlerts,
      dismissForegroundAlert,
      enablePush,
      live.status,
      live.detail,
      notificationRevision,
      activityRevision,
    ],
  );

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

/** §5.3 is telemetry: an open report must never block navigation. */
async function reportOpenBestEffort(notificationId: number): Promise<void> {
  try {
    await notificationsApi.reportOpen(notificationId);
  } catch {
    /* a failed telemetry write is not the operator's problem */
  }
}

export function useSession(): SessionContextValue {
  const ctx = useContext(SessionContext);
  if (!ctx) throw new Error('useSession must be used inside <SessionProvider>.');
  return ctx;
}

export { session };
