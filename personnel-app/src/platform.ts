/**
 * Platform capability surface.
 *
 * Kept separate from `storage/` so UI and push code can ask "are we native?"
 * without importing a token adapter as a side effect.
 */
import { Capacitor } from '@capacitor/core';
import { ALL_CHANNELS } from './lib/severity';

export { ALL_CHANNELS };

export function isNativePlatform(): boolean {
  try {
    return Capacitor.isNativePlatform();
  } catch {
    return false;
  }
}

export function platformName(): 'android' | 'ios' | 'web' {
  if (!isNativePlatform()) return 'web';
  const p = Capacitor.getPlatform();
  return p === 'android' || p === 'ios' ? p : 'web';
}

export interface DeviceInfo {
  model: string;
  osVersion: string;
  platform: string;
  appVersion: string;
}

/**
 * Best-effort device description for `POST /devices` (§3.1).
 * `userAgent` on the WebView contains "Android <version>; <model> Build/…".
 * Parsing it is deliberately forgiving: a wrong `model` string is cosmetic, a
 * missing registration is not.
 */
export function readDeviceInfo(appVersion = '1.0.0'): DeviceInfo {
  const ua = typeof navigator === 'undefined' ? '' : navigator.userAgent;
  const androidMatch = /Android\s+([\d.]+)/i.exec(ua);
  const modelMatch = /Android\s+[\d.]+;\s*([^;)]+?)(?:\s+Build\/[^;)]*)?[;)]/i.exec(ua);
  return {
    platform: platformName(),
    osVersion: androidMatch ? androidMatch[1] : (Capacitor.getPlatform() === 'web' ? 'web' : 'unknown'),
    model: modelMatch ? modelMatch[1].trim() : 'unknown-device',
    appVersion,
  };
}
