/**
 * Push registration and delivery handling.
 *
 * Honest scope statement, encoded in the states this module can produce:
 *   - On the Android build this uses `@capacitor/push-notifications`; the FCM
 *     token arrives on the `registration` event and is re-sent whenever it
 *     arrives again, because FCM tokens rotate.
 *   - On the web build there is no FCM. The module reports the failure to the
 *     UI instead of showing a fake "notifications enabled" state.
 *   - Deliverability additionally requires the client's real
 *     `android/app/google-services.json`. Without it, `register()` emits
 *     `registrationError`, whose text is surfaced verbatim.
 */
import { App } from '@capacitor/app';
import { PushNotifications } from '@capacitor/push-notifications';
import type { PushNotificationSchema } from '@capacitor/push-notifications';
import type { PluginListenerHandle } from '@capacitor/core';
import { devicesApi } from '../api/endpoints';
import { ALL_CHANNELS, isNativePlatform } from '../platform';
import { parseDeepLink } from './deeplink';
import type { ParsedIncidentLink } from './deeplink';

export interface PushHandlers {
  /** Token issued or rotated — the app must re-POST /devices (§3.1). */
  onToken: (token: string) => Promise<void> | void;
  /** Permission result from the OS prompt. */
  onPermission: (granted: boolean) => void;
  /** A notification arrived while the app was in the foreground. */
  onForeground: (notification: PushNotificationSchema) => void;
  /** The user tapped a notification or followed a deep link. */
  onOpen: (link: ParsedIncidentLink, notificationId: number | null) => void;
  /** Registration failed — text is shown as-is. */
  onError: (message: string) => void;
}

export interface PushHandle {
  stop: () => void;
}

let channelPromise: Promise<void> | null = null;

/**
 * Android 8+ requires a channel per importance band before a notification can
 * be posted. The cloud sets `channel_id` in the Android payload; if the channel
 * does not exist Android drops the notification silently, which is the single
 * most common cause of "push does not work" reports.
 */
async function ensureChannels(): Promise<void> {
  if (!isNativePlatform()) return;
  if (!channelPromise) {
    channelPromise = (async () => {
      for (const c of ALL_CHANNELS) {
        try {
          await PushNotifications.createChannel({
            id: c.id,
            name: c.name,
            description: c.description,
            importance: c.importance,
            visibility: 1 as const,
            lights: true,
            vibration: true,
          });
        } catch {
          // Channels are immutable after first creation on some OEM builds; a
          // failure here must not block registration.
        }
      }
    })();
  }
  return channelPromise;
}

export async function checkPushPermission(): Promise<'granted' | 'denied' | 'prompt' | 'unsupported'> {
  if (!isNativePlatform()) return 'unsupported';
  try {
    const status = await PushNotifications.checkPermissions();
    return status.receive === 'granted' ? 'granted' : status.receive === 'prompt' ? 'prompt' : 'denied';
  } catch {
    return 'unsupported';
  }
}

export async function requestPushPermission(): Promise<boolean> {
  if (!isNativePlatform()) return false;
  const status = await PushNotifications.checkPermissions();
  if (status.receive === 'granted') return true;
  const requested = await PushNotifications.requestPermissions();
  return requested.receive === 'granted';
}

/**
 * Extract the deep link from a push payload.
 *
 * §12: the payload carries `incident_id`, `notification_id`, `severity`,
 * `title`, `camera_name` and `deep_link` — nothing else is trusted, and a link
 * that does not parse to an incident id is rejected rather than followed.
 */
function linkFromPayload(data: Record<string, unknown> | undefined | null): { link: ParsedIncidentLink | null; notificationId: number | null } {
  const candidates = [data?.deep_link, data?.link, data?.click_action];
  let notificationId: number | null = null;
  const rawId = data?.notification_id ?? data?.notificationId;
  if (rawId !== undefined && rawId !== null && rawId !== '') {
    const n = Number(rawId);
    if (Number.isSafeInteger(n) && n > 0) notificationId = n;
  }
  for (const candidate of candidates) {
    const parsed = parseDeepLink(typeof candidate === 'string' ? candidate : undefined);
    if (parsed && parsed.kind === 'incident') return { link: parsed, notificationId };
  }
  return { link: null, notificationId };
}

export async function registerForPush(handlers: PushHandlers): Promise<PushHandle> {
  if (!isNativePlatform()) {
    handlers.onPermission(false);
    handlers.onError('This build is running in a browser, so the device cannot receive FCM push. Use the Android app for duty alerts.');
    return { stop: () => {} };
  }

  await ensureChannels();

  const handles: PluginListenerHandle[] = [];

  // `registration` is both the first-token event and the rotation event: the
  // bundled plugin's Android `MessagingService.onNewToken()` re-emits the
  // `registration` event (verified in
  // node_modules/@capacitor/push-notifications/android/.../PushNotificationsPlugin.java,
  // `EVENT_TOKEN_CHANGE = "registration"`). There is no separate
  // `pushNotificationToken` event in @capacitor/push-notifications 8, so the
  // rotation requirement in the brief is satisfied here rather than by an
  // event name that does not exist. If a Firebase-specific plugin is added
  // later that emits `pushNotificationToken`, wire it to the same handler.
  handles.push(
    await PushNotifications.addListener('registration', async (token) => {
      await handlers.onToken(token.value);
    }),
  );

  handles.push(
    await PushNotifications.addListener('registrationError', (error) => {
      handlers.onError(error.error || 'Push registration failed.');
    }),
  );

  handles.push(
    await PushNotifications.addListener('pushNotificationReceived', (notification) => {
      handlers.onForeground(notification);
    }),
  );

  handles.push(
    await PushNotifications.addListener('pushNotificationActionPerformed', (action) => {
      const { link, notificationId } = linkFromPayload(action.notification?.data);
      if (link) handlers.onOpen(link, notificationId);
    }),
  );

  // Cold start via a link: the app was not running when the tap happened.
  try {
    const launch = await App.getLaunchUrl();
    if (launch?.url) {
      const parsed = parseDeepLink(launch.url);
      if (parsed && parsed.kind === 'incident') handlers.onOpen(parsed, null);
    }
  } catch {
    /* getLaunchUrl is unsupported on some emulator images */
  }

  try {
    handles.push(await App.addListener('appUrlOpen', ({ url }) => {
      const parsed = parseDeepLink(url);
      if (parsed && parsed.kind === 'incident') handlers.onOpen(parsed, null);
      else if (parsed) handlers.onError(`Received an unrecognised link: ${parsed.source}`);
    }));
  } catch {
    // `appUrlOpen` is the Capacitor event for an incoming VIEW intent. If it
    // is unavailable the same intent still reaches `getLaunchUrl` above.
  }

  try {
    await PushNotifications.register();
  } catch (err) {
    handlers.onError(err instanceof Error ? err.message : 'Push registration threw.');
  }

  return {
    stop: () => {
      for (const h of handles) void h.remove();
    },
  };
}

/**
 * `POST /devices` with the current identity. §3.1 — idempotent on
 * installation_id, and a changed token overwrites the previous one.
 */
export async function reportDevice(input: {
  installationId: string;
  pushToken: string | null;
  model: string;
  osVersion: string;
  appVersion: string;
  platform?: string;
}): Promise<void> {
  await devicesApi.register({
    installation_id: input.installationId,
    platform: (input.platform ?? 'android') as 'android',
    push_provider: 'fcm',
    push_token: input.pushToken,
    model: input.model,
    os_version: input.osVersion,
    app_version: input.appVersion,
  });
}

export function notificationIdFromPayload(payload: Record<string, unknown> | undefined | null): number | null {
  const { notificationId } = linkFromPayload(payload);
  return notificationId;
}
