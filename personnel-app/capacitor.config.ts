import type { CapacitorConfig } from '@capacitor/cli';

/**
 * AFIT WATCH TOWER — Capacitor configuration.
 *
 * `appId` must match `android/app/build.gradle` applicationId and the
 * `package_name` inside the client-provided `android/app/google-services.json`.
 * A mismatch produces a push registration that succeeds locally and is
 * silently undeliverable from the cloud, because the cloud sends to the
 * Firebase project the token belongs to.
 *
 * `appendOrigin`/`hostname` are left at Capacitor defaults on purpose. With `androidScheme:
 * 'https'` above, the WebView's own origin is `https://localhost`, and its `fetch` calls are
 * cross-origin requests that the API answers through CORS. So the cloud service's
 * `CLOUD_ALLOWED_ORIGINS` must list `https://localhost` (and `http://localhost`, the origin under
 * the default scheme) or every request from the packaged app is refused at the preflight. The
 * bearer token is still what authenticates the person; the origin list only decides which pages
 * the browser engine lets read a response.
 */
const config: CapacitorConfig = {
  appId: 'com.afit.watchtower.personnel',
  appName: 'AFIT WATCH TOWER',
  webDir: 'dist',
  backgroundColor: '#080b11',
  server: {
    androidScheme: 'https',
    // Cleartext is deliberately NOT enabled. The contract is HTTPS-only (§0) and
    // a debugging exception belongs in a debug-only manifest, not here.
  },
  android: {
    allowMixedContent: false,
    captureInput: false,
    webContentsDebuggingEnabled: false,
    // Deep-link scheme handled by the intent filters added to
    // android/app/src/main/AndroidManifest.xml (see README §Deep links).
  },
  plugins: {
    PushNotifications: {
      // Foreground presentation only. Android posts through the per-severity
      // channels created at runtime in src/push/pushRuntime.ts; the cloud sends
      // the matching `channel_id` in the Android notification payload.
      presentationOptions: ['badge', 'sound', 'alert'],
    },
    SplashScreen: {
      launchShowDuration: 600,
      backgroundColor: '#080b11',
      showSpinner: false,
    },
  },
};

export default config;
