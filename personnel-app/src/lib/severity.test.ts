/**
 * The display vocabulary, tested against the words the server actually sends.
 *
 * A label mapping is the only place these values become English, so an unmapped server value has
 * to degrade in a way an operator can read rather than crash a screen.
 */
import { describe, expect, it } from 'vitest';

import {
  ACTIVE_STATUSES,
  ALL_CHANNELS,
  DETECTION_SOURCE,
  EVIDENCE_STATE,
  MANDATORY_CHANNEL_IDS,
  PREFERENCE_SOUNDS,
  SEVERITY,
  SEVERITY_ORDER,
  SOUND_OPTIONS,
  STATUS,
  STATUS_ORDER,
  activityActionLabel,
  detectionMeta,
  evidenceStateMeta,
  formatConfidence,
  severityLabel,
  severityMeta,
  soundOptionsFor,
  statusMeta,
} from './severity';

describe('severity', () => {
  it('orders the four values the API may send, low first', () => {
    expect(SEVERITY_ORDER).toEqual(['low', 'medium', 'high', 'critical']);
    expect(SEVERITY.critical.rank).toBeGreaterThan(SEVERITY.high.rank);
    expect(SEVERITY.medium.label).toBe('Warning');
    expect(SEVERITY.low.label).toBe('Informational');
  });

  it('degrades an unknown value without inventing one', () => {
    const meta = severityMeta('catastrophic');
    expect(meta.label).toBe('Unclassified');
    // The raw value still has to reach the screen, or the operator sees a label the server never sent.
    expect(severityLabel('catastrophic')).toBe('Unclassified');
    expect(severityMeta(null).rank).toBe(SEVERITY.low.rank);
  });
});

describe('status', () => {
  it('carries every state the queue can filter on', () => {
    // A filter list that omits a server state hides live incidents; the route answers 422 anyway.
    expect(STATUS_ORDER).toEqual(['open', 'investigating', 'assigned', 'resolved', 'closed', 'false_positive']);
    expect(ACTIVE_STATUSES).toEqual(['open', 'investigating', 'assigned']);
  });

  it('marks exactly the three terminal states', () => {
    for (const value of ['resolved', 'closed', 'false_positive']) {
      expect(statusMeta(value).terminal, value).toBe(true);
    }
    for (const value of ACTIVE_STATUSES) {
      expect(statusMeta(value).terminal, value).toBe(false);
    }
    expect(STATUS.assigned.label).toBe('Assigned');
  });

  it('echoes an unrecognised status instead of claiming a known one', () => {
    const meta = statusMeta('archived');
    expect(meta.label).toBe('archived');
    expect(meta.terminal).toBe(false);
  });
});

describe('activity vocabulary', () => {
  it('names the actions the console state machine writes', () => {
    // `IncidentService` stores bare names; only the notification kinds carry the `incident.` prefix.
    expect(activityActionLabel('created')).toBe('Incident opened');
    expect(activityActionLabel('created_from_event')).toBe('Opened from a candidate event');
    expect(activityActionLabel('acknowledged')).toBe('Acknowledged');
    expect(activityActionLabel('investigation_note')).toBe('Marked under investigation');
    expect(activityActionLabel('reopened')).toBe('Reopened');
    expect(activityActionLabel('closed')).toBe('Closed');
  });

  it('names the review decisions the same table carries', () => {
    expect(activityActionLabel('event.dismiss')).toBe('Candidate dismissed');
    expect(activityActionLabel('event.acknowledge')).toBe('Candidate confirmed');
  });

  it('keeps an unlisted action readable rather than blank', () => {
    // An action from a newer build shows its vocabulary, spaced, so the operator can quote it.
    expect(activityActionLabel('auto.escalated')).toBe('auto escalated');
  });
});

describe('detection source', () => {
  it('never renders a candidate as a conclusion', () => {
    expect(DETECTION_SOURCE.ai_candidate.isCandidate).toBe(true);
    expect(DETECTION_SOURCE.manual.isCandidate).toBe(false);
    expect(detectionMeta('ai_candidate').hint).toMatch(/human/i);
    // The two values `detection_source_for()` can return; anything else means an older build.
    expect(detectionMeta('ml_inference').label).toBe('Unspecified source');
  });

  it('says "not stated" when the detector produced no score', () => {
    expect(formatConfidence(null)).toBe('not stated');
    expect(formatConfidence(undefined)).toBe('not stated');
    expect(formatConfidence(0.834)).toBe('83% model confidence');
  });
});

describe('evidence state', () => {
  it('separates a lapsed link from an asset that is gone for good', () => {
    expect(evidenceStateMeta('expired').label).toBe('Past retention');
    expect(evidenceStateMeta('expired').renderable).toBe(false);
    expect(evidenceStateMeta('processing').renderable).toBe(false);
    expect(evidenceStateMeta('processing').explanation).toMatch(/not a broken link/i);
    expect(Object.keys(EVIDENCE_STATE)).toEqual([
      'available',
      'processing',
      'expired',
      'deleted',
      'unavailable',
    ]);
  });

  it('falls back to unavailable for a state it has never seen', () => {
    expect(evidenceStateMeta('archived')).toBe(EVIDENCE_STATE.unavailable);
  });

  it('only ever renders the available state', () => {
    for (const [value, meta] of Object.entries(EVIDENCE_STATE)) {
      expect(meta.renderable, value).toBe(value === 'available');
    }
  });
});

describe('notification channels', () => {
  it('keeps the mandatory pair pointed at by critical and high', () => {
    expect(SEVERITY.critical.channelId).toBe(MANDATORY_CHANNEL_IDS[0]);
    expect(SEVERITY.high.channelId).toBe(MANDATORY_CHANNEL_IDS[1]);
    expect(ALL_CHANNELS.map((channel) => channel.id)).toContain('watchtower-camera-health');
  });

  it('gives every severity a channel that exists', () => {
    const ids = new Set(ALL_CHANNELS.map((channel) => channel.id));
    for (const value of SEVERITY_ORDER) {
      expect(ids.has(SEVERITY[value].channelId), value).toBe(true);
    }
  });
});

describe('alert sound', () => {
  it('offers only values the profile router will store', () => {
    for (const option of SOUND_OPTIONS) {
      expect(PREFERENCE_SOUNDS, option.value).toContain(option.value);
    }
  });

  it('keeps a value an older build saved selectable instead of overwriting it', () => {
    expect(soundOptionsFor('silent').map((o) => o.value)).toEqual(['default', 'silent']);
    expect(soundOptionsFor('alarm').map((o) => o.value)).toEqual(['default', 'silent', 'alarm']);
  });
});
