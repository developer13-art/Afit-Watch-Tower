/**
 * The fixture transport, tested against the routes it claims to imitate.
 *
 * This file exists because every screen in DEV mode is exercised against these answers. A fixture
 * that returns what the UI wants rather than what `cloud/routers/incidents.py` sends would let a
 * broken screen pass review, so the assertions below are the server's behaviours — the queue/detail
 * split, the conflict codes, the newest-first history — not the app's preferences.
 */
import { describe, expect, it } from 'vitest';

import { fixtureFetch } from './transport';
import { ERROR_CODES } from '../types/api';
import type {
  ActivityListResponse,
  IncidentActionResponse,
  IncidentListResponse,
  NotificationPreferencesResponse,
} from '../types/api';

async function call<T>(path: string, init?: RequestInit): Promise<{ status: number; body: T }> {
  const res = await fixtureFetch(new URL(`https://app.test/api/v1${path}`), init);
  return { status: res.status, body: (await res.json()) as T };
}

function post<T>(path: string, body?: unknown) {
  return call<T>(path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body ?? {}),
  });
}

const DETAIL_ONLY_KEYS = ['summary', 'acknowledgements', 'resolution', 'outcome'] as const;

// The fixture store is a module singleton, so each case works its own incident: 77 is the
// acknowledge scratch, 76 the note scratch, 75 the resolve/reopen scratch, 74 stays untouched.

describe('the queue', () => {
  it('sends summaries, never detail bodies', async () => {
    const { body } = await call<IncidentListResponse>('/incidents');
    expect(body.items.length).toBeGreaterThan(0);
    for (const item of body.items) {
      for (const key of DETAIL_ONLY_KEYS) {
        expect(item, `incident ${item.id}`).not.toHaveProperty(key);
      }
      expect(item).toHaveProperty('detection_source');
    }
  });

  it('labels a candidate event in the queue, not only once opened', async () => {
    const { body } = await call<IncidentListResponse>('/incidents');
    const candidate = body.items.find((item) => item.id === 77);
    expect(candidate?.detection_source).toBe('ai_candidate');
    expect(candidate?.confidence).toBeTypeOf('number');
    const manual = body.items.find((item) => item.id === 74);
    expect(manual?.detection_source).toBe('manual');
    expect(manual?.confidence).toBeNull();
  });

  it('filters on the two parameters the incidents route actually declares', async () => {
    const window = { since: '2000-01-01T00:00:00Z', until: '2100-01-01T00:00:00Z' };
    const honoured = await call<IncidentListResponse>(`/incidents?${new URLSearchParams(window)}`);
    expect(honoured.body.items.length).toBeGreaterThan(0);

    const empty = await call<IncidentListResponse>(
      `/incidents?${new URLSearchParams({ since: '2000-01-01T00:00:00Z', until: '2000-01-02T00:00:00Z' })}`,
    );
    expect(empty.body.items).toEqual([]);

    // `from`/`to` belong to /notifications; a fixture that accepted both would hide a wiring bug.
    const wrongSpelling = await call<IncidentListResponse>(
      `/incidents?${new URLSearchParams({ from: '2000-01-01T00:00:00Z', to: '2100-01-01T00:00:00Z' })}`,
    );
    expect(wrongSpelling.body.items.length).toBe(honoured.body.items.length);
  });

  it('rejects a status the server enum does not contain', async () => {
    const { status, body } = await call<{ error: { code: string } }>('/incidents?status=pending');
    expect(status).toBe(422);
    expect(body.error.code).toBe(ERROR_CODES.STATUS_INVALID);
  });
});

describe('response actions', () => {
  it('refuses to acknowledge an incident that is already resolved', async () => {
    const { status, body } = await post<{ error: { code: string } }>('/incidents/74/acknowledge', {
      note: 'Too late.',
    });
    expect(status).toBe(409);
    expect(body.error.code).toBe(ERROR_CODES.INCIDENT_NOT_ACTIONABLE);
  });

  it('moves an open incident, claims it, and answers with the whole record', async () => {
    const { status, body } = await post<IncidentActionResponse>('/incidents/77/acknowledge', {
      note: 'Walking to the gate now.',
    });
    expect(status).toBe(200);
    expect(body.status).toBe('investigating');
    expect(body.already_acknowledged).toBe(false);
    expect(body.acknowledged_by).not.toBeNull();
    expect(body.assigned_to).not.toBeNull();
    expect(body.assigned_to_name).toBeTruthy();
    // The mobile route records the source it hardcodes, not a UI string.
    expect(body.acknowledgements.at(-1)?.source).toBe('mobile');
  });

  it('says already on the second tap and writes no second history row', async () => {
    await post<IncidentActionResponse>('/incidents/77/acknowledge', {});
    const { body } = await post<IncidentActionResponse>('/incidents/77/acknowledge', {});
    expect(body.already_acknowledged).toBe(true);
    const activity = await call<ActivityListResponse>('/incidents/77/activity');
    expect(activity.body.items.filter((row) => row.action === 'acknowledged')).toHaveLength(1);
  });

  it('refuses an empty note with the code the app branches on', async () => {
    const { status, body } = await post<{ error: { code: string } }>('/incidents/76/notes', {
      note: '   ',
    });
    expect(status).toBe(422);
    expect(body.error.code).toBe(ERROR_CODES.NOTE_REQUIRED);
  });

  it('writes the bare action names the console state machine stores', async () => {
    await post<IncidentActionResponse>('/incidents/76/notes', { note: 'Checked the fence line.' });
    await post<IncidentActionResponse>('/incidents/76/investigating', { note: 'Reviewing footage.' });
    const { body } = await call<ActivityListResponse>('/incidents/76/activity');
    expect(body.items[0].action).toBe('investigation_note');
    expect(body.items.map((row) => row.action)).toContain('note');
    // Only notification kinds carry the `incident.` prefix.
    for (const row of body.items) expect(row.action).not.toMatch(/^incident\./);
  });

  it('resolves, then reopens into investigation with the verdict cleared', async () => {
    const resolved = await post<IncidentActionResponse>('/incidents/75/resolve', {
      outcome: 'handled',
      resolution: 'Escort arrived and the area was cleared.',
    });
    expect(resolved.body.status).toBe('resolved');
    expect(resolved.body.resolved_at).not.toBeNull();

    const reopened = await post<IncidentActionResponse>('/incidents/75/reopen', {
      reason: 'The same person is back at the line.',
    });
    expect(reopened.body.status).toBe('investigating');
    expect(reopened.body.outcome).toBeNull();
    expect(reopened.body.resolved_at).toBeNull();

    const { body } = await call<ActivityListResponse>('/incidents/75/activity');
    expect(body.items.map((row) => row.action)).toEqual(
      expect.arrayContaining(['resolved', 'reopened']),
    );
  });

  it('treats a false positive as final, exactly as the service does', async () => {
    const marked = await post<IncidentActionResponse>('/incidents/75/resolve', {
      outcome: 'false_positive',
      resolution: 'A contractor, escorted.',
      false_positive: true,
    });
    expect(marked.body.status).toBe('false_positive');

    const refused = await post<{ error: { code: string } }>('/incidents/75/reopen', {
      reason: 'It was not a drill.',
    });
    expect(refused.status).toBe(409);
    expect(refused.body.error.code).toBe(ERROR_CODES.NOT_RESOLVED);
  });

  it('names the escalation it reached and the role nobody holds as a conflict', async () => {
    const nobody = await post<{ error: { code: string } }>('/incidents/76/escalate', {
      reason: 'Needs a supervisor on site.',
      to_role: 'technical_operator',
    });
    expect(nobody.status).toBe(409);
    expect(nobody.body.error.code).toBe(ERROR_CODES.ESCALATION_TARGET_UNAVAILABLE);

    const reached = await post<IncidentActionResponse>('/incidents/76/escalate', {
      reason: 'Needs a supervisor on site.',
    });
    expect(reached.body.escalated_to).not.toBeNull();
    expect(reached.body.escalated_to_name).toBeTruthy();
  });
});

describe('history and evidence', () => {
  it('answers newest-first and paginates below the last id', async () => {
    const first = await call<ActivityListResponse>('/incidents/74/activity?limit=1');
    expect(first.body.items).toHaveLength(1);
    expect(first.body.next_cursor).not.toBeNull();
    const second = await call<ActivityListResponse>(
      `/incidents/74/activity?limit=1&cursor=${first.body.next_cursor}`,
    );
    expect(new Date(second.body.items[0].created_at).getTime()).toBeLessThan(
      new Date(first.body.items[0].created_at).getTime(),
    );
  });

  it('serves evidence metadata with the two expiries kept apart', async () => {
    const { body } = await call<{
      incident_id: number;
      items: Array<{ state: string; url: string | null; expires_at: string | null; expires_at_token: string | null }>;
    }>('/incidents/77/evidence');
    expect(body.incident_id).toBe(77);
    expect(body.items.length).toBeGreaterThan(0);
    for (const asset of body.items) {
      expect(asset).not.toHaveProperty('storage_key');
      // `evidence_list()` mints a link only for an asset whose bytes are on disk.
      if (asset.state === 'available') {
        expect(asset.url).not.toBeNull();
        expect(asset.expires_at_token).not.toBeNull();
        // The retention date and the link's expiry are different numbers; conflating them turns a
        // lapsed link into "the evidence is gone".
        expect(asset.expires_at).not.toBe(asset.expires_at_token);
      } else {
        expect(asset.url).toBeNull();
        expect(asset.expires_at_token).toBeNull();
      }
    }
  });
});

describe('notification preferences', () => {
  it('refuses a sound the profile router would reject, and keeps the one it accepts', async () => {
    const current = (await call<NotificationPreferencesResponse>('/profile/preferences')).body;

    // `vibrate` is the value an earlier build of this screen offered. The service answers a PUT
    // carrying it with a 422 from the Pydantic validator, so the fixture has to as well —
    // otherwise a picker whose real save always fails still looks fine in dev mode.
    const refused = await call<{ error: { code: string } }>('/profile/preferences', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...current, sound: 'vibrate' }),
    });
    expect(refused.status).toBe(422);
    expect(refused.body.error.code).toBe(ERROR_CODES.VALIDATION_FAILED);

    const saved = await call<NotificationPreferencesResponse>('/profile/preferences', {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ ...current, sound: 'silent' }),
    });
    expect(saved.status).toBe(200);
    expect(saved.body.sound).toBe('silent');
  });
});

describe('session', () => {
  it('reports what it forgot when the handset asks to be forgotten', async () => {
    const res = await fixtureFetch(new URL('https://app.test/api/v1/auth/logout'), {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-installation-id': 'installation-1' },
      body: JSON.stringify({ forget_device: true, refresh_token: 'refresh-1' }),
    });
    expect(await res.json()).toEqual({ signed_out: true, device_forgotten: true });
  });

  it('answers 404 for a route the service does not have', async () => {
    const res = await fixtureFetch(new URL('https://app.test/api/v1/incidents/999999'));
    expect(res.status).toBe(404);
    expect(((await res.json()) as { error: { code: string } }).error.code).toBe(ERROR_CODES.NOT_FOUND);
  });
});
