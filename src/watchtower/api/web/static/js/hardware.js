/**
 * Hardware (proposal sections 10, 16, 17): what this deployment is running on, how much of
 * its stream capacity is in use, how the cameras are grouped, and where the recordings go.
 */

import {
  PANEL_PERMISSIONS,
  renderDelivery,
  renderGroups,
  renderSystem,
} from './admin.js';
import { panelSection } from './ui.js';

export function mount(host, ctx) {
  return panelSection(host, {
    title: 'Hardware',
    idPrefix: 'wt-hw',
    ariaLabel: 'Hardware areas',
    allowed: (permission) => ctx.can(permission),
    empty: 'Hardware state needs the "audit.view" or "camera.list" permission, neither of which your role grants.',
    items: [
      {
        id: 'system',
        label: 'Server and capacity',
        permission: PANEL_PERMISSIONS.system,
        render: (node) => renderSystem(node, ctx),
      },
      {
        id: 'groups',
        label: 'Camera groups',
        permission: PANEL_PERMISSIONS.groups,
        render: (node) => renderGroups(node, ctx),
      },
      {
        id: 'delivery',
        label: 'Alerting and retention',
        permission: PANEL_PERMISSIONS.delivery,
        render: (node) => renderDelivery(node, ctx),
      },
    ],
  });
}
