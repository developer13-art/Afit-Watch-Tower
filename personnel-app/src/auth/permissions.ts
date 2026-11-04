/**
 * Permission helpers.
 *
 * §2.5: permissions are resolved from the database on every request and are
 * never embedded in the access token, so this is a *display* mechanism only.
 * Hiding a button is not authorization — every action still has to handle a
 * 403/409 from the server, and the screens do exactly that.
 *
 * The vocabulary below is §6.3 plus the evidence and health permissions named
 * in §7.2 and §10.
 */
import type { AuthMeResponse } from '../types/api';

/**
 * The permission strings `security/rbac.py::ROLE_DEFINITIONS` grants, and the cloud routes
 * `require_permission(...)`. A name listed here that the service never grants is worse than a
 * missing one: the app would show a button for an action every caller gets refused.
 */
export const PERMISSION = {
  incidentView: 'incident.view',
  incidentCreate: 'incident.create',
  incidentAcknowledge: 'incident.acknowledge',
  incidentEscalate: 'incident.escalate',
  incidentAssign: 'incident.assign',
  incidentResolve: 'incident.resolve',
  evidenceView: 'evidence.view',
  evidenceExport: 'evidence.export',
  eventView: 'event.view',
  eventReview: 'event.review',
  healthView: 'health.view',
  cameraList: 'camera.list',
  reportOperational: 'report.operational',
  auditView: 'audit.view',
  adminUsers: 'admin.users',
  adminPolicies: 'admin.policies',
} as const;

export type PermissionName = (typeof PERMISSION)[keyof typeof PERMISSION];

/**
 * Role codes the escalation dropdown may offer — `ROLE_DEFINITIONS` keys, and the same two rungs
 * the cloud's automatic escalation ladder (`cloud/worker.py::ESCALATION_STAGES`) climbs.
 *
 * `security_operator` is deliberately absent: escalating to the rank you already hold is not an
 * escalation. `technical_operator` owns no incident permission, so a hand-off there would land on
 * someone who cannot act on it.
 */
export const ESCALATION_ROLES = ['security_supervisor', 'system_administrator'] as const;

/** The names the server stores, for the profile screen's role list. */
export const ROLE_NAMES: Record<string, string> = {
  system_administrator: 'System Administrator',
  security_supervisor: 'Security Supervisor',
  security_operator: 'Security Operator',
  technical_operator: 'Technical Operator',
  auditor_read_only: 'Auditor / Read-Only Reviewer',
};

export function hasPermission(user: AuthMeResponse | null | undefined, permission: string): boolean {
  if (!user) return false;
  const granted = user.permissions ?? [];
  // A server that later decides to send a wildcard still grants correctly;
  // the client never invents a permission for itself.
  return granted.includes(permission) || granted.includes('*') || granted.includes(`${permission.split('.')[0]}.*`);
}

export function hasAnyPermission(user: AuthMeResponse | null | undefined, permissions: string[]): boolean {
  return permissions.some((p) => hasPermission(user, p));
}

/**
 * Whether the caller may act on an incident at all, before the server's own
 * status-machine check. `open`/`investigating` only — §6.3 conflict rules.
 */
export function actionable(
  user: AuthMeResponse | null | undefined,
  action: 'acknowledge' | 'escalate' | 'assign' | 'resolve' | 'note' | 'investigating',
): boolean {
  switch (action) {
    case 'acknowledge':
      return hasPermission(user, PERMISSION.incidentAcknowledge);
    case 'investigating':
      // §6.3 — `/investigating` needs incident.view plus ownership of the scope;
      // scope is enforced server-side, so the client checks the view grant.
      return hasPermission(user, PERMISSION.incidentView);
    case 'escalate':
      return hasPermission(user, PERMISSION.incidentEscalate);
    case 'assign':
      return hasPermission(user, PERMISSION.incidentAssign);
    case 'resolve':
      return hasPermission(user, PERMISSION.incidentResolve);
    case 'note':
      return hasPermission(user, PERMISSION.incidentView);
    default:
      return false;
  }
}

/** Human explanation for the "you cannot act on this" state. */
export function missingPermissionHint(action: string): string {
  return `Your account does not hold the permission required to ${action} this incident. Ask an administrator to review your grants in the monitoring console.`;
}
