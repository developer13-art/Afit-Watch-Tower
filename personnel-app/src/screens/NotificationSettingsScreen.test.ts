import { describe, expect, it } from 'vitest';

import { kindRows } from './NotificationSettingsScreen';

/**
 * `GET /profile/preferences` sends only the kinds an account has overridden, and delivery
 * suppresses a kind only when it is present and `false` — so an empty map means everything is on,
 * not that there is nothing to switch. The first version of the preferences screen read that
 * empty map as an empty list and told a real officer "the server reported no configurable kinds",
 * which is what these guard against.
 */
describe('the alert kind vocabulary', () => {
  it('lists every kind the service recognises when the account has overridden none', () => {
    const rows = kindRows({});
    expect(rows.map((row) => row.kind)).toEqual([
      'incident.created',
      'incident.assigned',
      'incident.escalated',
      'incident.resolved',
      'camera.health',
      'event.new',
    ]);
    expect(rows.every((row) => row.enabled)).toBe(true);
  });

  it('treats a missing kind as enabled and only an explicit false as disabled', () => {
    const rows = kindRows({ 'event.new': false, 'camera.health': true });
    expect(rows.find((row) => row.kind === 'event.new')?.enabled).toBe(false);
    expect(rows.find((row) => row.kind === 'camera.health')?.enabled).toBe(true);
    expect(rows.find((row) => row.kind === 'incident.created')?.enabled).toBe(true);
  });

  it('shows a kind the server added beyond this list instead of dropping it', () => {
    const rows = kindRows({ 'incident.scheduled': false });
    expect(rows.map((row) => row.kind)).toContain('incident.scheduled');
    expect(rows.find((row) => row.kind === 'incident.scheduled')?.enabled).toBe(false);
  });
});
