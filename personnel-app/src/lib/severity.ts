/**
 * Severity vocabulary (§1).
 *
 * The API only ever sends `low | medium | high | critical`. The UI labels are
 * derived, never stored, and the mapping is defined exactly once so a screen
 * cannot drift.
 *
 *   critical -> "Critical"
 *   high     -> "High"
 *   medium   -> "Warning"
 *   low      -> "Informational"
 */
import type { DetectionSource, EvidenceState, IncidentStatus, Severity } from '../types/api';

export interface SeverityMeta {
  /** API value. */
  value: Severity;
  /** UI label. */
  label: string;
  /** Tailwind classes: text, border, background, solid chip. Reserved palette. */
  fg: string;
  border: string;
  bg: string;
  solid: string;
  solidFg: string;
  /** Ranking used for sorting and for `min_severity` comparisons. */
  rank: number;
  /** Android notification channel the cloud should target for this severity. */
  channelId: string;
  channelImportance: number;
}

export const SEVERITY: Record<Severity, SeverityMeta> = {
  critical: {
    value: 'critical',
    label: 'Critical',
    fg: 'text-sev-critical',
    border: 'border-sev-critical/50',
    bg: 'bg-sev-critical/10',
    solid: 'bg-sev-critical',
    solidFg: 'text-surface-base',
    rank: 4,
    channelId: 'watchtower-critical',
    channelImportance: 4,
  },
  high: {
    value: 'high',
    label: 'High',
    fg: 'text-sev-high',
    border: 'border-sev-high/50',
    bg: 'bg-sev-high/10',
    solid: 'bg-sev-high',
    solidFg: 'text-surface-base',
    rank: 3,
    channelId: 'watchtower-high',
    channelImportance: 4,
  },
  medium: {
    value: 'medium',
    label: 'Warning',
    fg: 'text-sev-medium',
    border: 'border-sev-medium/50',
    bg: 'bg-sev-medium/10',
    solid: 'bg-sev-medium',
    solidFg: 'text-surface-base',
    rank: 2,
    channelId: 'watchtower-warning',
    channelImportance: 3,
  },
  low: {
    value: 'low',
    label: 'Informational',
    fg: 'text-sev-low',
    border: 'border-sev-low/50',
    bg: 'bg-sev-low/15',
    solid: 'bg-sev-low',
    solidFg: 'text-surface-base',
    rank: 1,
    channelId: 'watchtower-informational',
    channelImportance: 2,
  },
};

/** Ordered API values, low → critical. Used by filter pickers. */
export const SEVERITY_ORDER: Severity[] = ['low', 'medium', 'high', 'critical'];

export function severityMeta(value: string | null | undefined): SeverityMeta {
  if (value && (SEVERITY as Record<string, SeverityMeta>)[value]) {
    return SEVERITY[value as Severity];
  }
  // CONTRACT: unknown enum values are rejected by the server (§1), so a
  // non-mapping value here means an older/newer build. Degrade to `low`
  // visually but keep the raw value visible through `severityLabel`.
  return { ...SEVERITY.low, label: 'Unclassified', fg: 'text-ink-muted' };
}

export function severityLabel(value: string | null | undefined): string {
  return severityMeta(value).label;
}

export function severityRank(value: Severity): number {
  return SEVERITY[value].rank;
}

export function isSeverity(value: unknown): value is Severity {
  return typeof value === 'string' && (SEVERITY_ORDER as string[]).includes(value);
}

/** The channel a critical/high alert must use, independent of user preference. */
export const MANDATORY_CHANNEL_IDS = ['watchtower-critical', 'watchtower-high'];

export type ChannelImportance = 0 | 1 | 2 | 3 | 4 | 5;

export const ALL_CHANNELS: Array<{ id: string; name: string; description: string; importance: ChannelImportance }> = [
  {
    id: 'watchtower-critical',
    name: 'Critical — duty alert',
    description: 'Immediate action required. Cannot be silenced.',
    importance: 4,
  },
  {
    id: 'watchtower-high',
    name: 'High priority',
    description: 'Incidents needing acknowledgement.',
    importance: 4,
  },
  {
    id: 'watchtower-warning',
    name: 'Warning',
    description: 'Medium-severity events.',
    importance: 3,
  },
  {
    id: 'watchtower-informational',
    name: 'Informational',
    description: 'Low-severity updates and resolutions.',
    importance: 2,
  },
  {
    id: 'watchtower-camera-health',
    name: 'Camera health',
    description: 'Monitoring coverage problems.',
    importance: 3,
  },
];

/**
 * The alert sounds this build can honour, and only those.
 *
 * `silent` is real: the cloud sends the Android notification with the sound field empty. Anything
 * else means "the channel's own tone", which the officer changes in Android's settings for that
 * severity band. A specific ringtone is not on offer because Android fixes a channel's sound when
 * the channel is created and a push cannot rewrite it — the service would still accept the word
 * `alarm` on a profile saved by an older build, and `soundOptionsFor` keeps such a value visible
 * instead of letting the picker silently save something different over it.
 */
export const SOUND_OPTIONS: Array<{ value: string; label: string }> = [
  { value: 'default', label: 'System default — the channel tone for that severity' },
  { value: 'silent', label: 'Silent — visual only' },
];

/**
 * Everything the service will store, which is wider than what this build offers: `alarm` is still
 * valid on a profile saved by an older release, and a picker must not present it as a 422.
 */
export const PREFERENCE_SOUNDS: string[] = ['alarm', 'default', 'silent'];

export function soundOptionsFor(saved: string): Array<{ value: string; label: string }> {
  if (SOUND_OPTIONS.some((option) => option.value === saved)) return SOUND_OPTIONS;
  return [...SOUND_OPTIONS, { value: saved, label: `Saved setting: ${saved}` }];
}

// ---------------------------------------------------------------- status

export interface StatusMeta {
  label: string;
  fg: string;
  border: string;
  bg: string;
  /** Terminal statuses reject acknowledgement (§6.3 conflict rules). */
  terminal: boolean;
}

export const STATUS: Record<IncidentStatus, StatusMeta> = {
  open: {
    label: 'Open',
    fg: 'text-status-open',
    border: 'border-status-open/50',
    bg: 'bg-status-open/10',
    terminal: false,
  },
  investigating: {
    label: 'Under investigation',
    fg: 'text-status-investigating',
    border: 'border-status-investigating/50',
    bg: 'bg-status-investigating/10',
    terminal: false,
  },
  assigned: {
    label: 'Assigned',
    fg: 'text-status-assigned',
    border: 'border-status-assigned/50',
    bg: 'bg-status-assigned/10',
    terminal: false,
  },
  resolved: {
    label: 'Resolved',
    fg: 'text-status-resolved',
    border: 'border-status-resolved/50',
    bg: 'bg-status-resolved/10',
    terminal: true,
  },
  closed: {
    label: 'Closed',
    fg: 'text-status-closed',
    border: 'border-status-closed/50',
    bg: 'bg-status-closed/10',
    terminal: true,
  },
  false_positive: {
    label: 'False positive',
    fg: 'text-status-false-positive',
    border: 'border-status-false-positive/50',
    bg: 'bg-status-false-positive/10',
    terminal: true,
  },
};

/**
 * The full `IncidentStatus` vocabulary, in the order a duty officer reads a queue.
 *
 * `assigned` and `false_positive` are server states, not display variants: a status filter that
 * omits them quietly hides live incidents, and `/incidents?status=` answers 422 for a value the
 * enum does not contain.
 */
export const STATUS_ORDER: IncidentStatus[] = [
  'open',
  'investigating',
  'assigned',
  'resolved',
  'closed',
  'false_positive',
];

/** States the outbox counts as "still work", matching `views.OPEN_STATUSES`. */
export const ACTIVE_STATUSES: IncidentStatus[] = ['open', 'investigating', 'assigned'];

export function statusMeta(value: string | null | undefined): StatusMeta {
  if (value && (STATUS as Record<string, StatusMeta>)[value]) return STATUS[value as IncidentStatus];
  return { label: value ?? 'Unknown', fg: 'text-ink-muted', border: 'border-surface-line', bg: 'bg-surface-card', terminal: false };
}

// ---------------------------------------------------------------- detection source

export interface DetectionMeta {
  label: string;
  hint: string;
  /** An AI candidate is a candidate. Never rendered as confirmed wrongdoing. */
  isCandidate: boolean;
}

export const DETECTION_SOURCE: Record<DetectionSource, DetectionMeta> = {
  ai_candidate: {
    label: 'AI candidate',
    hint: 'Machine-generated candidate. Not a confirmed threat — a human must judge it.',
    isCandidate: true,
  },
  manual: {
    label: 'Operator reported',
    hint: 'Raised by a person in the monitoring console.',
    isCandidate: false,
  },
};

export function detectionMeta(value: string | null | undefined): DetectionMeta {
  if (value && (DETECTION_SOURCE as Record<string, DetectionMeta>)[value]) {
    return DETECTION_SOURCE[value as DetectionSource];
  }
  return { label: 'Unspecified source', hint: 'The record does not state how it was detected.', isCandidate: false };
}

export function formatConfidence(confidence: number | null | undefined): string {
  if (confidence === null || confidence === undefined || Number.isNaN(confidence)) return 'not stated';
  const pct = Math.round(confidence * 100);
  return `${pct}% model confidence`;
}

// ---------------------------------------------------------------- evidence state

export interface EvidenceStateMeta {
  label: string;
  explanation: string;
  /** Whether a `url` is worth requesting at all. */
  renderable: boolean;
  tone: 'ok' | 'warn' | 'bad' | 'muted';
}

export const EVIDENCE_STATE: Record<EvidenceState, EvidenceStateMeta> = {
  available: {
    label: 'Available',
    explanation: 'Evidence retrieved for this incident.',
    renderable: true,
    tone: 'ok',
  },
  processing: {
    label: 'Still uploading',
    explanation:
      'The monitoring station has not finished transferring this asset. It will become available shortly — this is not a broken link.',
    renderable: false,
    tone: 'warn',
  },
  expired: {
    label: 'Past retention',
    explanation:
      'This asset is beyond its retention date, so the service will not serve it again. This is the asset itself, not the short-lived link — a lapsed link says "Refetch" instead.',
    renderable: false,
    tone: 'bad',
  },
  deleted: {
    label: 'Deleted',
    explanation: 'The asset was removed by the evidence retention policy.',
    renderable: false,
    tone: 'bad',
  },
  unavailable: {
    label: 'Unavailable',
    explanation: 'The evidence exists but cannot be served right now.',
    renderable: false,
    tone: 'bad',
  },
};

export function evidenceStateMeta(value: string | null | undefined): EvidenceStateMeta {
  if (value && (EVIDENCE_STATE as Record<string, EvidenceStateMeta>)[value]) {
    return EVIDENCE_STATE[value as EvidenceState];
  }
  return EVIDENCE_STATE.unavailable;
}

// ---------------------------------------------------------------- activity

/**
 * The `action` strings `IncidentService` writes into `incident_actions`, verbatim from
 * `src/watchtower/services/incidents.py`. They are not prefixed with `incident.` — the mobile
 * history is the same table the console reads, so the app must not expect a namespace.
 */
const ACTIVITY_ACTION: Record<string, string> = {
  created: 'Incident opened',
  created_from_event: 'Opened from a candidate event',
  acknowledged: 'Acknowledged',
  assigned: 'Assigned',
  escalated: 'Escalated',
  note: 'Note added',
  investigation_note: 'Marked under investigation',
  resolved: 'Resolved',
  reopened: 'Reopened',
  closed: 'Closed',
  // The review queue writes its decisions into the same table, dotted and unprefixed.
  'event.acknowledge': 'Candidate confirmed',
  'event.dismiss': 'Candidate dismissed',
  'event.escalate': 'Candidate escalated to an incident',
};

/** An action this build does not know still shows its stored vocabulary rather than a guess. */
export function activityActionLabel(action: string): string {
  return ACTIVITY_ACTION[action] ?? action.replace(/[._]/g, ' ');
}
