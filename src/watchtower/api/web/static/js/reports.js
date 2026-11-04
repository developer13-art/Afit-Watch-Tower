/**
 * Reports (proposal sections 18, 21): what the deployment actually measured over a window,
 * and the audit trail behind every number.
 *
 * The report is the page rather than a tab: the design puts the window picker and the figures
 * where the operator lands. The audit log sits underneath it - the same numbers, plus the record
 * of who produced them - and the whole section stays permission-checked per panel, because a
 * reviewer may hold one of these two and not the other.
 */

import { PANEL_PERMISSIONS, renderAudit, renderReports } from './admin.js';
import { gatingNotice, panel, panelSection, render } from './ui.js';

export function mount(host, ctx) {
  const reportNode = host.appendChild(document.createElement('div'));
  const auditNode = host.appendChild(document.createElement('div'));

  const audit = panelSection(auditNode, {
    title: 'Audit log',
    idPrefix: 'wt-rep-audit',
    ariaLabel: 'Audit areas',
    allowed: (permission) => ctx.can(permission),
    empty: 'The audit trail needs the "audit.view" permission, which your role does not grant.',
    items: [
      {
        id: 'audit',
        label: 'Audit log',
        permission: PANEL_PERMISSIONS.audit,
        render: (node) => renderAudit(node, ctx),
      },
    ],
  });

  function drawReport() {
    if (!ctx.can(PANEL_PERMISSIONS.reports)) {
      render(reportNode, panel('Operational report', [
        gatingNotice(PANEL_PERMISSIONS.reports, 'The measured figures are an operations-manager responsibility.'),
      ]));
      return;
    }
    void renderReports(reportNode, ctx);
  }

  drawReport();

  return {
    autoRefreshMs: 0,
    refresh: () => {
      drawReport();
      if (audit.refresh) audit.refresh();
    },
    teardown: null,
  };
}
