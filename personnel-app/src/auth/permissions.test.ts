/**
 * Display gating, checked against the grants `security/rbac.py::ROLE_DEFINITIONS` actually gives.
 *
 * This cannot authorise anything — the server decides every action — but a wrong answer here puts
 * a button on screen that only ever 403s, or hides one the operator holds. Both are bugs the
 * operator experiences as the app lying to them.
 */
import { describe, expect, it } from 'vitest';

import {
  ESCALATION_ROLES,
  PERMISSION,
  actionable,
  hasPermission,
  hasAnyPermission,
} from './permissions';
import type { AuthMeResponse } from '../types/api';

function user(permissions: string[]): AuthMeResponse {
  return { permissions } as unknown as AuthMeResponse;
}

/** The exact grant set of `security_operator`, copied from the server's role table. */
const OPERATOR = [
  'camera.list',
  'camera.view_live',
  'event.view',
  'event.review',
  'incident.view',
  'incident.create',
  'incident.acknowledge',
  'evidence.view',
];

/** What `security_supervisor` adds on top of that. */
const SUPERVISOR = [
  ...OPERATOR,
  'health.view',
  'incident.assign',
  'incident.escalate',
  'incident.resolve',
  'evidence.export',
  'report.operational',
];

describe('hasPermission', () => {
  it('reads only what the server sent', () => {
    expect(hasPermission(user(OPERATOR), PERMISSION.incidentAcknowledge)).toBe(true);
    expect(hasPermission(user(OPERATOR), PERMISSION.incidentResolve)).toBe(false);
    expect(hasPermission(null, PERMISSION.incidentView)).toBe(false);
    expect(hasPermission(user([]), PERMISSION.incidentView)).toBe(false);
  });

  it('accepts a wildcard the server might one day send, and invents none', () => {
    expect(hasPermission(user(['incident.*']), PERMISSION.incidentResolve)).toBe(true);
    expect(hasPermission(user(['evidence.view']), PERMISSION.incidentView)).toBe(false);
  });
});

describe('actionable', () => {
  it('lets an operator acknowledge, investigate and note — and nothing else', () => {
    const operator = user(OPERATOR);
    expect(actionable(operator, 'acknowledge')).toBe(true);
    expect(actionable(operator, 'investigating')).toBe(true);
    expect(actionable(operator, 'note')).toBe(true);
    expect(actionable(operator, 'escalate')).toBe(false);
    expect(actionable(operator, 'assign')).toBe(false);
    expect(actionable(operator, 'resolve')).toBe(false);
  });

  it('lets a supervisor run the whole response', () => {
    const supervisor = user(SUPERVISOR);
    for (const action of ['acknowledge', 'investigating', 'note', 'escalate', 'assign', 'resolve'] as const) {
      expect(actionable(supervisor, action), action).toBe(true);
    }
  });

  it('refuses an action name the client does not model', () => {
    // An unknown key must not default to "allowed" and put a button on screen.
    expect(actionable(user(SUPERVISOR), 'delete' as never)).toBe(false);
  });
});

describe('hasAnyPermission', () => {
  it('is true when one of several grants is held', () => {
    expect(hasAnyPermission(user(OPERATOR), [PERMISSION.adminUsers, PERMISSION.incidentView])).toBe(true);
    expect(hasAnyPermission(user(OPERATOR), [PERMISSION.adminUsers])).toBe(false);
  });
});

describe('escalation targets', () => {
  it('offers only ranks that can act on the incident', () => {
    // `technical_operator` holds no incident permission and `security_operator` is the caller's
    // own rank, so neither belongs in the dropdown.
    expect(ESCALATION_ROLES).not.toContain('technical_operator');
    expect(ESCALATION_ROLES).not.toContain('security_operator');
    expect(ESCALATION_ROLES).toContain('security_supervisor');
  });
});
