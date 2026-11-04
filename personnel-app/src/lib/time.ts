/** RFC 3339 timestamps in, human strings out. All display is local-time aware. */

export function parseTs(value: string | null | undefined): Date | null {
  if (!value) return null;
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

export function formatDateTime(value: string | null | undefined): string {
  const d = parseTs(value);
  if (!d) return '—';
  return d.toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZoneName: 'short',
  });
}

export function formatDate(value: string | null | undefined): string {
  const d = parseTs(value);
  if (!d) return '—';
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
}

export function formatTime(value: string | null | undefined): string {
  const d = parseTs(value);
  if (!d) return '—';
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
}

/** Short relative label for list rows: "4m ago", "2h ago", "12 Mar". */
export function timeAgo(value: string | null | undefined, now: Date = new Date()): string {
  const d = parseTs(value);
  if (!d) return '—';
  const seconds = Math.round((now.getTime() - d.getTime()) / 1000);
  if (seconds < 0) return formatDateTime(value);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.round(hours / 24);
  if (days < 7) return `${days}d ago`;
  return formatDate(value);
}

/** True when a signed asset URL is past its expiry (with a 20s clock skew margin). */
export function isExpired(expiresAt: string | null | undefined, now = new Date()): boolean {
  const d = parseTs(expiresAt);
  if (!d) return false;
  return d.getTime() - 20_000 <= now.getTime();
}

/** Local-time `YYYY-MM-DDTHH:MM` for `from`/`to` query parameters. */
export function toQueryTimestamp(dateValue: string, endOfDay = false): string | undefined {
  if (!dateValue) return undefined;
  const d = new Date(dateValue);
  if (Number.isNaN(d.getTime())) return undefined;
  if (endOfDay) d.setHours(23, 59, 59, 999);
  return d.toISOString();
}

export function nowIso(): string {
  return new Date().toISOString();
}

/** HH:mm validation for quiet hours (§8.2). */
export function isValidHhmm(value: string): boolean {
  return /^([01]\d|2[0-3]):[0-5]\d$/.test(value);
}
