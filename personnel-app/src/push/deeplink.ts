/**
 * Deep links (contract §12).
 *
 * Accepted forms:
 *   watchtower://incidents/77
 *   https://<cloud-host>/open/incidents/77
 *
 * Anything else is rejected rather than guessed at — a mis-parsed link would
 * open the wrong incident, which in a security product is a real harm.
 */
export interface ParsedIncidentLink {
  kind: 'incident';
  incidentId: number;
  /** Application route the id maps to. */
  route: string;
  /** Original link, kept for the audit trail / open report. */
  source: string;
}

export type DeepLink = ParsedIncidentLink | { kind: 'unknown'; source: string };

const CUSTOM_SCHEME = /^watchtower:\/\/incidents\/(\d{1,12})\/?$/i;
// The HTTPS form carries the cloud host, which is configuration, not data:
// match the path suffix instead of a fixed origin so a host change cannot
// silently break link handling.
const HTTPS_FORM = /\/open\/incidents\/(\d{1,12})\/?(?:\?[^#]*)?(?:#.*)?$/i;
const INTERNAL_ROUTE = /^#?\/?incidents\/(\d{1,12})$/;

export function parseDeepLink(raw: string | null | undefined): DeepLink | null {
  if (!raw) return null;
  const value = raw.trim();
  if (!value) return null;

  for (const pattern of [CUSTOM_SCHEME, HTTPS_FORM, INTERNAL_ROUTE]) {
    const m = pattern.exec(value);
    if (m) {
      const id = Number(m[1]);
      if (!Number.isSafeInteger(id) || id <= 0) return { kind: 'unknown', source: value };
      return { kind: 'incident', incidentId: id, route: `/incidents/${id}`, source: value };
    }
  }
  return { kind: 'unknown', source: value };
}

/** The link the app emits for a given incident (§12 both forms). */
export function buildDeepLink(incidentId: number, apiOrigin: string): { scheme: string; https: string } {
  return {
    scheme: `watchtower://incidents/${incidentId}`,
    https: `${apiOrigin.replace(/\/+$/, '')}/open/incidents/${incidentId}`,
  };
}

/**
 * The link that must never be followed: anything that is not an incident id
 * inside our own scheme. Used to reject a hostile push payload.
 */
export function isSafeNavigationTarget(link: DeepLink | null): link is ParsedIncidentLink {
  return Boolean(link && link.kind === 'incident');
}
