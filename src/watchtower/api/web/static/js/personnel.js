/**
 * Personnel (proposal sections 14, 15): the accounts that can sign in, the roles they hold and
 * the camera-group scope each grant carries.
 */

import { PANEL_PERMISSIONS, renderRoles, renderUsers } from './admin.js';
import { panelSection } from './ui.js';

export function mount(host, ctx) {
  return panelSection(host, {
    title: 'Personnel',
    idPrefix: 'wt-pers',
    ariaLabel: 'Personnel areas',
    allowed: (permission) => ctx.can(permission),
    empty: 'Reading the directory needs the "admin.users" permission, which your role does not grant.',
    items: [
      {
        id: 'users',
        label: 'Accounts and grants',
        permission: PANEL_PERMISSIONS.users,
        render: (node) => renderUsers(node, ctx),
      },
      {
        id: 'roles',
        label: 'Roles and permissions',
        permission: PANEL_PERMISSIONS.roles,
        render: (node) => renderRoles(node, ctx),
      },
    ],
  });
}
