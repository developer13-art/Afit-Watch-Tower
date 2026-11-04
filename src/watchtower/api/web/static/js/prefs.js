/**
 * Console preferences, stored in this browser only.
 *
 * There is no server-side console preference store, so nothing here changes what the backend
 * does or what another operator sees. The personnel mobile app has its own alert preferences,
 * which are stored on the server and are edited on that app's settings screen.
 */

const KEY = 'watchtower.console.preferences';

const DEFAULTS = {
  refreshMs: 20000,
  sound: false,
  desktop: false,
};

function read() {
  try {
    const raw = window.localStorage.getItem(KEY);
    if (!raw) return { ...DEFAULTS };
    const stored = JSON.parse(raw);
    return {
      refreshMs: Number.isFinite(stored.refreshMs) ? Math.min(Math.max(stored.refreshMs, 5000), 300000) : DEFAULTS.refreshMs,
      sound: stored.sound === true,
      desktop: stored.desktop === true,
    };
  } catch {
    return { ...DEFAULTS };
  }
}

export const prefs = read();

export function setPref(key, value) {
  prefs[key] = value;
  try {
    window.localStorage.setItem(KEY, JSON.stringify(prefs));
  } catch {
    /* private mode or a full store: the setting still applies for this session */
  }
}
