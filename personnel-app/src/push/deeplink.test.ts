/**
 * Deep-link parsing (contract §12).
 *
 * This function decides which incident record a handset opens after a notification tap, so the
 * cost of a wrong answer is an officer working the wrong incident. Every rejection below is
 * therefore asserted as loudly as the acceptances.
 */
import { describe, expect, it } from 'vitest';

import { buildDeepLink, isSafeNavigationTarget, parseDeepLink } from './deeplink';

describe('the two forms the contract sends', () => {
  it('routes the custom scheme to the incident screen', () => {
    const parsed = parseDeepLink('watchtower://incidents/77');
    expect(parsed).toMatchObject({ kind: 'incident', incidentId: 77, route: '/incidents/77' });
    expect(isSafeNavigationTarget(parsed)).toBe(true);
  });

  it('routes the HTTPS form whatever host the cloud is published on', () => {
    for (const host of ['https://watchtower.example/open/incidents/77', 'https://10.0.0.5:8043/open/incidents/77']) {
      expect(parseDeepLink(host)).toMatchObject({ kind: 'incident', incidentId: 77 });
    }
  });

  it('ignores a query or fragment appended to the https form', () => {
    expect(parseDeepLink('https://watchtower.example/open/incidents/77?src=push#t')).toMatchObject({
      incidentId: 77,
    });
  });

  it('accepts the internal route the app itself stores for a cold start', () => {
    expect(parseDeepLink('/incidents/77')).toMatchObject({ incidentId: 77 });
    expect(parseDeepLink('#/incidents/77')).toMatchObject({ incidentId: 77 });
  });
});

describe('what must never be followed', () => {
  it('rejects an id that is not a plain positive number', () => {
    for (const raw of [
      'watchtower://incidents/abc',
      'watchtower://incidents/-77',
      'watchtower://incidents/77/../99',
      'watchtower://incidents/77665544332211008899',
      'watchtower://incidents/',
    ]) {
      const parsed = parseDeepLink(raw);
      expect(parsed, raw).not.toMatchObject({ kind: 'incident' });
      expect(isSafeNavigationTarget(parsed), raw).toBe(false);
    }
  });

  it('rejects a bare Android click action, which is not a link', () => {
    // The cloud used to send `click_action: "OPEN_INCIDENT"`. Treating that as a destination
    // would be worse than ignoring it, so the parser has to say "unknown" and the runtime has to
    // show the payload rather than navigate.
    expect(parseDeepLink('OPEN_INCIDENT')).toEqual({ kind: 'unknown', source: 'OPEN_INCIDENT' });
    expect(parseDeepLink('  ')).toBeNull();
    expect(parseDeepLink(undefined)).toBeNull();
  });

  it('reports the original text when it cannot classify a link', () => {
    expect(parseDeepLink('https://example.test/somewhere/else')).toEqual({
      kind: 'unknown',
      source: 'https://example.test/somewhere/else',
    });
  });
});

describe('the link the app hands to a caller', () => {
  it('builds both forms from the API origin without doubling a slash', () => {
    expect(buildDeepLink(77, 'https://watchtower.example/api/v1/')).toEqual({
      scheme: 'watchtower://incidents/77',
      https: 'https://watchtower.example/api/v1/open/incidents/77',
    });
  });

  it('round-trips: whatever it builds is what it parses', () => {
    const built = buildDeepLink(77, 'https://watchtower.example/api/v1');
    for (const link of [built.scheme, built.https]) {
      expect(parseDeepLink(link), link).toMatchObject({ kind: 'incident', incidentId: 77 });
    }
  });
});
