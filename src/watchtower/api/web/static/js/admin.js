/**
 * Administration (proposal sections 13.5, 14, 15, 16, 18).
 *
 * The one idea this screen has to explain in the interface itself: a role grant may be
 * institution-wide or scoped to a camera group. An unscoped grant is the wider authority, so
 * the grant UI makes the absence of a group read as "every camera", never as "nothing".
 */

import { ApiError } from './api.js';
import {
  SEVERITY,
  absoluteText,
  busy,
  confirmDialog,
  durationText,
  emptyState,
  field,
  fieldErrorSlot,
  gatingNotice,
  h,
  openDialog,
  panel,
  render,
  selectInput,
  showFieldError,
  statTile,
  statusChip,
  svg,
  textInput,
  timeEl,
} from './ui.js';

export const PANEL_PERMISSIONS = {
  users: 'admin.users',
  roles: 'admin.users',
  groups: 'camera.list',
  policies: 'camera.list',
  delivery: 'admin.policies',
  audit: 'audit.view',
  reports: 'report.operational',
  system: 'audit.view',
};

/*
 * These panels are exported rather than mounted from one Administration section: the console
 * rail presents them under the operator-facing headings the design uses - Personnel, AI
 * Intelligence, Hardware, Reports - and each of those mounts only the panels its own
 * permission allows.
 */
export {
  renderUsers,
  renderRoles,
  renderGroups,
  renderPolicies,
  renderDelivery,
  renderAudit,
  renderReports,
  renderSystem,
};

/* ------------------------------------------------------------------ users and grants */

async function renderUsers(node, ctx) {
  render(node, panel('Users', [emptyState('Loading the user directory...')]));
  let users;
  try {
    users = await ctx.api.admin.users();
  } catch (error) {
    render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    return;
  }

  const reload = () => renderUsers(node, ctx);
  const create = h('button', { type: 'button', class: 'btn primary', text: 'Create user' });
  create.addEventListener('click', () => openCreateUser(ctx, reload));

  const rows = users.map((user) => h('tr', [
    h('td.mono', { text: user.username }),
    h('td', { text: user.display_name }),
    h('td', { text: user.email || '-' }),
    h('td', [statusLine(user)]),
    h('td', [user.last_login_at ? timeEl(user.last_login_at) : h('span.dim', { text: 'never signed in' })]),
    h('td', [grantList(user, ctx, reload)]),
    h('td.actions', [
      (() => {
        const grant = h('button', { type: 'button', class: 'btn small', text: 'Grant role' });
        grant.addEventListener('click', () => openGrantDialog(user, ctx, reload));
        return grant;
      })(),
      (() => {
        const toggle = h('button', { type: 'button', class: 'btn small', text: user.is_active ? 'Disable account' : 'Enable account' });
        toggle.addEventListener('click', () => {
          const action = user.is_active ? 'deactivate' : 'activate';
          confirmDialog({
            title: `${user.is_active ? 'Disable' : 'Enable'} ${user.username}?`,
            message: user.is_active
              ? 'A disabled account cannot sign in and its existing session stops working at the next request. Role grants are kept.'
              : 'Enabling restores sign-in for this account without changing its role grants.',
            confirmLabel: user.is_active ? 'Disable account' : 'Enable account',
            tone: user.is_active ? 'bad' : 'ok',
            onConfirm: () => {
              ctx.api.admin.setActive(user.id, !user.is_active)
                .then((result) => ctx.toast(`${user.username} is now ${result.is_active ? 'active' : 'inactive'} (server confirmed).`, result.is_active ? 'ok' : 'warn'))
                .catch((error) => ctx.toast(describe(error), 'bad'))
                .finally(reload);
            },
          });
          void action;
        });
        return toggle;
      })(),
      (() => {
        const effective = h('button', { type: 'button', class: 'btn small ghost', text: 'Effective permissions' });
        effective.addEventListener('click', () => {
          ctx.api.admin.effectivePermissions(user.id)
            .then((result) => showEffective(user, result))
            .catch((error) => ctx.toast(describe(error), 'bad'));
        });
        return effective;
      })(),
    ]),
  ]));

  render(node, panel(`Users - ${users.length} accounts`, [
    h('p.note', { text: 'A role grant either applies institution-wide (no camera group) or only to cameras inside one group. Institution-wide is the wider authority: it reaches every camera including ones added later.' }),
    h('div.toolbar', [create, h('div.toolbar-spacer'), h('button', { type: 'button', class: 'btn', text: 'Reload' , on: { click: reload } })]),
    h('table.matrix.dense', [
      h('thead', [h('tr', [
        h('th', { text: 'Username' }), h('th', { text: 'Display name' }), h('th', { text: 'Contact' }),
        h('th', { text: 'Account state' }), h('th', { text: 'Last sign-in' }), h('th', { text: 'Role grants' }), h('th', { text: 'Actions' }),
      ])]),
      h('tbody', rows),
    ]),
  ]));
}

function statusLine(user) {
  const parts = [h('span.chip', { class: `tone-${user.is_active ? 'ok' : 'muted'}` }, [
    h('span.chip-shape', { text: user.is_active ? '●' : '■', 'aria-hidden': 'true' }),
    h('span.chip-label', { text: user.is_active ? 'active' : 'disabled' }),
  ])];
  if (user.locked) {
    parts.push(h('span.chip.tone-bad', [
      h('span.chip-shape', { text: '✖', 'aria-hidden': 'true' }),
      h('span.chip-label', { text: 'locked after failed sign-ins' }),
    ]));
  }
  return h('div.chip-stack', parts);
}

function grantList(user, ctx, reload) {
  if (!user.roles.length) {
    return h('span.dim', { text: 'no role granted - this account can sign in but sees nothing' });
  }
  return h('div.chip-stack', user.roles.map((grant) => {
    const scope = grant.camera_group_id === null || grant.camera_group_id === undefined
      ? 'institution-wide'
      : `group: ${groupName(ctx, grant.camera_group_id)}`;
    const chip = h('span.grant', [
      h('strong', { text: grant.role || 'unknown role' }),
      h('span.dim', { text: scope }),
    ]);
    if (ctx.can('admin.users')) {
      const revoke = h('button', { type: 'button', class: 'btn tiny danger', text: 'Revoke' });
      revoke.addEventListener('click', () => {
        confirmDialog({
          title: `Revoke ${grant.role} from ${user.username}?`,
          message: grant.camera_group_id === null
            ? 'This removes the institution-wide grant. If the same role is also granted for a specific group, that narrower grant still applies.'
            : `This removes the grant scoped to ${scope}. Any institution-wide grant for the same role is untouched.`,
          confirmLabel: 'Revoke grant',
          onConfirm: () => {
            ctx.api.admin.revokeRole(user.id, grant.role, grant.camera_group_id ?? undefined)
              .then(() => ctx.toast(`Revoked ${grant.role} (${scope}) from ${user.username}.`, 'warn'))
              .catch((error) => ctx.toast(describe(error), 'bad'))
              .finally(reload);
          },
        });
      });
      chip.append(revoke);
    }
    return chip;
  }));
}

function openGrantDialog(user, ctx, reload) {
  const scope = h('div.create-user');
  const outcome = h('div.outcome-host');
  render(scope, emptyState('Loading the role catalogue...'));
  Promise.all([ctx.api.admin.roles(), ctx.api.cameras.groups()])
    .then(([roles, groups]) => {
      const roleSelect = selectInput(roles.map((role) => ({ value: role.code, label: `${role.name} (${role.code})` })), { id: 'wt-grant-role' });
      const groupSelect = selectInput([
        { value: '', label: 'Institution-wide - every camera, including ones added later' },
        ...groups.map((group) => ({ value: String(group.id), label: `Only ${group.name} (${group.code})` })),
      ], { id: 'wt-grant-group' });

      const save = h('button', { type: 'button', class: 'btn primary', text: 'Grant role' });
      save.addEventListener('click', (event) => {
        busy(event.currentTarget, true, 'Granting');
        ctx.api.admin.grantRole(user.id, roleSelect.value, groupSelect.value === '' ? null : Number(groupSelect.value))
          .then((result) => {
            render(outcome, h('div.outcome.tone-border-ok', [
              h('div.outcome-head', [h('span.outcome-title', { text: 'Grant recorded' })]),
              h('div.outcome-rows', [
                field('Role', result.granted),
                field('Scope', result.scope === null ? 'institution-wide' : `camera group ${result.scope}`),
                field('Account', user.username),
              ]),
              h('p.note', { text: 'The account must sign in again for the new grant to take effect in this console.' }),
            ]));
            reload();
          })
          .catch((error) => render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })))
          .finally(() => busy(event.currentTarget, false));
      });

      render(scope, [
        h('div.form-field', { 'data-field': 'role_code' }, [
          h('label', { for: 'wt-grant-role', text: 'Role' }),
          roleSelect,
          h('span.hint', { text: roles.find((role) => role.code === roleSelect.value)?.description || 'Roles and their permissions are listed on the Roles tab.' }),
          fieldErrorSlot(),
        ]),
        h('div.form-field', { 'data-field': 'camera_group_id' }, [
          h('label', { for: 'wt-grant-group', text: 'Camera group scope' }),
          groupSelect,
          h('span.hint', { text: 'Choosing a group restricts every permission in this role to cameras inside that group. Leaving it institution-wide applies to all cameras.' }),
          fieldErrorSlot(),
        ]),
        h('div.toolbar', [save]),
        outcome,
      ]);
    })
    .catch((error) => render(scope, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })));

  openDialog({
    title: `Grant a role to ${user.display_name}`,
    description: 'Decide whether this authority covers the whole institution or one camera group.',
    width: 'small',
    body: [scope],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
  });
}

function openCreateUser(ctx, reload) {
  const scope = h('div.create-user');
  const outcome = h('div.outcome-host');
  const inputs = {};
  const add = (name, label, props = {}) => {
    const input = textInput({ id: `wt-nu-${name}`, name, type: props.type || 'text', ...props.dom });
    if (props.type === 'password') input.setAttribute('autocomplete', 'new-password');
    scope.querySelector('.nu-grid').append(h('div.form-field', { 'data-field': name }, [
      h('label', { for: `wt-nu-${name}`, text: label }),
      input,
      props.hint ? h('span.hint', { text: props.hint }) : null,
      fieldErrorSlot(),
    ]));
    inputs[name] = input;
  };

  scope.append(h('div.grid-2.nu-grid'));
  add('username', 'Username', { hint: 'Lowercase letters, digits, dot, underscore or hyphen; at least 3 characters.' });
  add('display_name', 'Display name', { hint: 'What appears on incident actions and audit entries.' });
  add('password', 'Initial password', {
    type: 'password',
    hint: 'Minimum 12 characters. The server rejects anything shorter, so set it before submitting.',
  });
  add('email', 'Email (optional)', { dom: { placeholder: 'name@afitelivalara.edu.ng' } });
  add('phone', 'Phone (optional)', { dom: { inputmode: 'tel' } });

  const save = h('button', { type: 'button', class: 'btn primary', text: 'Create user' });
  save.addEventListener('click', (event) => {
    showFieldError(scope, null, null);
    if (inputs.password.value.length < 12) {
      showFieldError(scope, 'password', 'The server requires at least 12 characters. A shorter password is rejected with 400 before any account is made.');
      return;
    }
    busy(event.currentTarget, true, 'Creating');
    ctx.api.admin.createUser({
      username: inputs.username.value.trim(),
      display_name: inputs.display_name.value.trim(),
      password: inputs.password.value,
      email: inputs.email.value.trim() || null,
      phone: inputs.phone.value.trim() || null,
    })
      .then((result) => {
        render(outcome, h('div.outcome.tone-border-ok', [
          h('div.outcome-head', [h('span.outcome-title', { text: 'Account created' })]),
          h('div.outcome-rows', [field('Username', result.username), field('User id', result.id), field('Role grants', 'none yet')]),
          h('p.note.tone-fg-warn', { text: 'A new account has no role grant, so it can sign in but cannot see any record. Grant a role now or the account is inert.' }),
        ]));
        reload();
      })
      .catch((error) => {
        if (error instanceof ApiError && (error.status === 422 || error.field)) showFieldError(scope, error.field || 'password', error.display);
        render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
      })
      .finally(() => busy(event.currentTarget, false));
  });

  scope.append(
    h('p.note', { text: 'Passwords are hashed by the server and never returned. Camera credentials and this password are separate secrets.' }),
    h('div.toolbar', [save]),
    outcome
  );

  openDialog({
    title: 'Create a user account',
    description: 'Accounts are created without a role grant; grant a role immediately afterwards or the person cannot see anything.',
    width: 'wide',
    body: [scope],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
  });
}

function showEffective(user, result) {
  const scoped = Object.entries(result.scopes || {})
    .filter(([, groupId]) => groupId !== null && groupId !== undefined)
    .map(([permission, groupId]) => `${permission}: group ${groupId}`);
  openDialog({
    title: `Effective permissions - ${user.username}`,
    description: 'Resolved from every role grant the account holds right now.',
    width: 'small',
    body: [
      panel('Summary', [
        field('Administrative', result.is_administrative ? 'yes' : 'no'),
        field('Permission count', result.permissions.length),
      ]),
      panel('Permissions', [
        result.permissions.length
          ? h('ul.perm-list', result.permissions.map((permission) => h('li.mono', { text: permission })))
          : emptyState('This account holds no permission and can only sign in.'),
      ]),
      panel('Group-scoped permissions', [
        scoped.length
          ? h('ul.perm-list', scoped.map((line) => h('li', { text: line })))
          : h('p.note', { text: 'Every permission is institution-wide: none of this account\'s grants name a camera group.' }),
      ]),
    ],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
  });
}

/* ------------------------------------------------------------------ roles catalogue */

async function renderRoles(node, ctx) {
  render(node, panel('Roles', [emptyState('Reading the role and permission catalogue...')]));
  let roles;
  let permissions;
  let definitions;
  try {
    [roles, permissions, definitions] = await Promise.all([
      ctx.api.admin.roles(),
      ctx.api.admin.permissions(),
      ctx.api.admin.roleDefinitions(),
    ]);
  } catch (error) {
    render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    return;
  }

  const granted = new Set(roles.flatMap((role) => role.permissions));

  render(node, [
    panel('Role definitions', [
      h('table.matrix', [
        h('thead', [h('tr', [h('th', { text: 'Role' }), h('th', { text: 'Administrative' }), h('th', { text: 'Purpose' }), h('th', { text: 'Permissions granted' })])]),
        h('tbody', roles.map((role) => h('tr', [
          h('td', [h('div.name', { text: role.name }), h('div.sub.mono', { text: role.code })]),
          h('td', [h('span.chip', { class: `tone-${role.is_administrative ? 'warn' : 'muted'}` }, [
            h('span.chip-shape', { text: role.is_administrative ? '▲' : '○', 'aria-hidden': 'true' }),
            h('span.chip-label', { text: role.is_administrative ? 'administrative' : 'operational' }),
          ])]),
          h('td', { text: role.description || '-' }),
          h('td', { text: `${role.permissions.length} - ${role.permissions.slice(0, 4).join(', ')}${role.permissions.length > 4 ? ', ...' : ''}` }),
        ]))),
      ]),
    ]),
    panel('Permission catalogue', [
      h('p.note', { text: 'Video viewing (camera.view_live) and camera configuration (camera.configure) are separate permissions on purpose: an auditor can review records without being able to see or change a camera.' }),
      h('table.matrix', [
        h('thead', [h('tr', [h('th', { text: 'Permission' }), h('th', { text: 'What it allows' }), h('th', { text: 'Granted by' })])]),
        h('tbody', permissions.map((permission) => h('tr', [
          h('td.mono', { text: permission.code }),
          h('td', { text: permission.description }),
          h('td', { text: granted.has(permission.code)
            ? roles.filter((role) => role.permissions.includes(permission.code)).map((role) => role.code).join(', ')
            : 'no role - unreachable capability' }),
        ]))),
      ]),
    ]),
    panel('Seeded role definitions', [
      h('p.note', { text: 'The catalogue the bootstrap writes. Editing a role here is not supported by this build; grants are made by assigning these roles to accounts.' }),
      h('ul.perm-list', definitions.map((definition) => h('li', [
        h('strong', { text: `${definition.name} (${definition.code})` }),
        h('span', { text: ` - ${definition.description}` }),
      ]))),
    ]),
  ]);
}

/* ------------------------------------------------------------------ camera groups */

async function renderGroups(node, ctx) {
  render(node, panel('Camera groups', [emptyState('Loading groups...')]));
  let groups;
  try {
    groups = await ctx.api.cameras.groups();
    ctx.invalidate('groups');
  } catch (error) {
    render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    return;
  }

  const reload = () => renderGroups(node, ctx);
  const scope = h('div');

  const create = h('button', { type: 'button', class: 'btn primary', text: 'Create group' });
  create.addEventListener('click', () => {
    if (!ctx.can('admin.policies')) {
      ctx.toast('Not available: your role does not grant the "admin.policies" permission.', 'warn');
      return;
    }
    openGroupDialog(ctx, reload);
  });
  ctx.gate(create, 'admin.policies');

  const counts = new Map();
  ctx.cameras().forEach((camera) => {
    const key = camera.camera_group_id === null ? 'ungrouped' : String(camera.camera_group_id);
    counts.set(key, (counts.get(key) || 0) + 1);
  });

  render(scope, [
    h('p.note', { text: 'A group is both an operational folder and an access-control boundary: a role grant scoped to a group only reaches the cameras inside it.' }),
    h('div.toolbar', [create]),
    groups.length
      ? h('table.matrix', [
          h('thead', [h('tr', [h('th', { text: 'Code' }), h('th', { text: 'Name' }), h('th', { class: 'num', text: 'Cameras' })])]),
          h('tbody', groups.map((group) => h('tr', [
            h('td.mono', { text: group.code }),
            h('td', { text: group.name }),
            h('td.num', { text: String(counts.get(String(group.id)) || 0) }),
          ]))),
        ])
      : emptyState('No camera group exists yet. Ungrouped cameras are invisible to any group-scoped grant.'),
    h('p.note', { text: `Ungrouped cameras visible to you: ${counts.get('ungrouped') || 0}. A group-scoped operator cannot see these.` }),
  ]);
  render(node, panel(`Camera groups - ${groups.length}`, [scope]));
}

function openGroupDialog(ctx, reload) {
  const scope = h('div.create-user');
  const outcome = h('div.outcome-host');
  const inputs = {};
  scope.append(h('div.grid-2.cg-grid'));
  const add = (name, label, props = {}) => {
    const input = props.kind === 'textarea'
      ? h('textarea', { class: 'input', id: `wt-cg-${name}`, name, rows: '3' })
      : textInput({ id: `wt-cg-${name}`, name, ...props.dom });
    scope.querySelector('.cg-grid').append(h('div.form-field', { 'data-field': name }, [
      h('label', { for: `wt-cg-${name}`, text: label }),
      input,
      props.hint ? h('span.hint', { text: props.hint }) : null,
      fieldErrorSlot(),
    ]));
    inputs[name] = input;
  };
  add('code', 'Group code', { hint: 'For example MAIN-GATE, HOSTEL-BLOCK.' });
  add('name', 'Group name');
  add('description', 'Description', { kind: 'textarea' });

  const save = h('button', { type: 'button', class: 'btn primary', text: 'Create group' });
  save.addEventListener('click', (event) => {
    busy(event.currentTarget, true, 'Creating');
    ctx.api.admin.createGroup({
      code: inputs.code.value.trim(),
      name: inputs.name.value.trim(),
      description: inputs.description.value.trim() || null,
    })
      .then((result) => {
        render(outcome, h('div.outcome.tone-border-ok', [
          h('div.outcome-head', [h('span.outcome-title', { text: 'Group created' })]),
          h('div.outcome-rows', [field('Id', result.id), field('Code', result.code), field('Name', result.name)]),
        ]));
        reload();
      })
      .catch((error) => render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })))
      .finally(() => busy(event.currentTarget, false));
  });

  scope.append(h('div.toolbar', [save]), outcome);
  openDialog({
    title: 'Create a camera group',
    description: 'Groups are used for scoping role grants and for grouping cameras during registration.',
    width: 'small',
    body: [scope],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
  });
}

/* ------------------------------------------------------------------ monitoring policies */

async function renderPolicies(node, ctx) {
  render(node, panel('Monitoring policies', [emptyState('Loading policies...')]));
  let policies;
  try {
    policies = await ctx.api.admin.policies();
    ctx.invalidate('policies');
  } catch (error) {
    render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    return;
  }

  const reload = () => renderPolicies(node, ctx);
  const create = h('button', { type: 'button', class: 'btn primary', text: 'New policy' });
  create.addEventListener('click', () => openPolicyDialog(ctx, null, reload));
  ctx.gate(create, 'admin.policies');

  render(node, panel(`Monitoring policies - ${policies.length}`, [
    h('p.note', { text: 'A policy decides which detectors run for a camera, the confidence floor below which a detection is discarded, how often frames are analysed and how duplicates are coalesced. Attaching a policy to a camera is done on the camera record.' }),
    h('div.toolbar', [create]),
    policies.length
      ? h('table.matrix', [
          h('thead', [h('tr', [
            h('th', { text: 'Code' }), h('th', { text: 'Name' }), h('th', { text: 'State' }), h('th', { text: 'Detectors' }),
            h('th', { class: 'num', text: 'Min confidence' }), h('th', { class: 'num', text: 'Analysis fps' }),
            h('th', { class: 'num', text: 'Duplicate window' }), h('th', { text: 'Severity' }), h('th', { class: 'num', text: 'Zones' }), h('th', { text: '' }),
          ])]),
          h('tbody', policies.map((policy) => h('tr', [
            h('td.mono', { text: policy.code }),
            h('td', { text: policy.name }),
            h('td', [h('span.chip', { class: `tone-${policy.enabled ? 'ok' : 'muted'}` }, [
              h('span.chip-shape', { text: policy.enabled ? '●' : '■', 'aria-hidden': 'true' }),
              h('span.chip-label', { text: policy.enabled ? 'enabled' : 'disabled' }),
            ])]),
            h('td', { text: policy.detector_codes.length ? policy.detector_codes.join(', ') : 'no detector selected' }),
            h('td.num', { text: `${Math.round(policy.min_confidence * 100)}%`, title: `raw ${policy.min_confidence}` }),
            h('td.num', { text: String(policy.analysis_fps) }),
            h('td.num', { text: `${policy.duplicate_window_seconds}s` }),
            h('td', [statusChip(policy.severity, SEVERITY)]),
            h('td.num', { text: String((policy.zones || []).length) }),
            h('td.actions', [
              (() => {
                const edit = h('button', { type: 'button', class: 'btn small', text: 'Edit' });
                edit.addEventListener('click', () => openPolicyDialog(ctx, policy, reload));
                ctx.gate(edit, 'admin.policies');
                return edit;
              })(),
            ]),
          ]))),
        ])
      : emptyState('No monitoring policy is defined, so no camera can have analysis attached.'),
    !ctx.can('admin.policies') ? gatingNotice('admin.policies', 'Policies are readable here but cannot be changed by this role.') : null,
  ]));
}

function openPolicyDialog(ctx, policy, reload) {
  const scope = h('div.create-user');
  const outcome = h('div.outcome-host');
  const inputs = {};
  scope.append(h('div.grid-2.pol-grid'));

  const add = (name, label, value, props = {}) => {
    const input = props.kind === 'checkbox'
      ? h('input', { type: 'checkbox', id: `wt-pol-${name}`, name })
      : props.kind === 'textarea'
        ? h('textarea', { class: 'input', id: `wt-pol-${name}`, name, rows: '4' })
        : textInput({ id: `wt-pol-${name}`, name, type: props.type || 'text', value: value === null || value === undefined ? '' : String(value), ...props.dom });
    scope.querySelector('.pol-grid').append(h('div.form-field', { 'data-field': name }, [
      h('label', { for: `wt-pol-${name}`, text: label }),
      input,
      props.hint ? h('span.hint', { text: props.hint }) : null,
      fieldErrorSlot(),
    ]));
    inputs[name] = input;
    if (props.kind === 'checkbox') input.checked = Boolean(value);
    if (props.kind === 'textarea') input.value = value === null || value === undefined ? '' : value;
    return input;
  };

  add('code', 'Policy code', policy ? policy.code : '', { hint: 'Saving an existing code replaces that policy.' });
  add('name', 'Policy name', policy ? policy.name : '');
  add('enabled', 'Enabled', policy ? policy.enabled : false, { kind: 'checkbox', hint: 'A disabled policy attached to a camera produces no detections.' });
  add('detector_codes', 'Detector codes', policy ? policy.detector_codes.join(', ') : '', {
    kind: 'textarea',
    hint: 'Comma separated, exactly as the analysis layer registers them, for example restricted_zone_entry, unattended_object. Codes the deployment cannot run are recorded but report themselves as unavailable.',
  });
  add('min_confidence', 'Minimum confidence', policy ? policy.min_confidence : 0.55, {
    dom: { inputmode: 'decimal', placeholder: '0.55' },
    hint: 'Between 0 and 1. Detections below this are discarded before they reach the queue.',
  });
  add('analysis_fps', 'Analysis fps', policy ? policy.analysis_fps : 4, {
    dom: { inputmode: 'decimal', placeholder: '4' },
    hint: 'Frames per second actually inspected, above 0 and at most 30.',
  });
  add('duplicate_window_seconds', 'Duplicate window (seconds)', policy ? policy.duplicate_window_seconds : 90, {
    dom: { inputmode: 'numeric' },
    hint: 'Repeated findings inside this window collapse into one candidate event (5-3600).',
  });
  add('severity', 'Severity', policy ? policy.severity : 'medium', {
    kind: 'select',
    options: Object.keys(SEVERITY).map((value) => ({ value, label: SEVERITY[value].label })),
  });
  add('zones', 'Restricted zones (JSON)', policy ? JSON.stringify(policy.zones || [], null, 2) : '[]', {
    kind: 'textarea',
    hint: 'Polygon geometry is institution-approved, not drawn here. Enter a JSON array, or leave [] for none.',
  });

  const save = h('button', { type: 'button', class: 'btn primary', text: policy ? 'Save policy' : 'Create policy' });
  save.addEventListener('click', (event) => {
    showFieldError(scope, null, null);
    const confidence = Number(inputs.min_confidence.value);
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      showFieldError(scope, 'min_confidence', 'Confidence must be a number between 0 and 1.');
      return;
    }
    const fps = Number(inputs.analysis_fps.value);
    if (!Number.isFinite(fps) || fps <= 0 || fps > 30) {
      showFieldError(scope, 'analysis_fps', 'Analysis fps must be greater than 0 and at most 30.');
      return;
    }
    let zones;
    try {
      zones = inputs.zones.value.trim() ? JSON.parse(inputs.zones.value) : [];
      if (!Array.isArray(zones)) throw new Error('not an array');
    } catch {
      showFieldError(scope, 'zones', 'Zones must be a JSON array of zone objects, or [] for none.');
      return;
    }

    const payload = {
      code: inputs.code.value.trim(),
      name: inputs.name.value.trim(),
      enabled: inputs.enabled.checked,
      detector_codes: inputs.detector_codes.value.split(',').map((value) => value.trim()).filter(Boolean),
      min_confidence: confidence,
      analysis_fps: fps,
      zones,
      duplicate_window_seconds: Number(inputs.duplicate_window_seconds.value) || 90,
      severity: inputs.severity.value,
    };

    busy(event.currentTarget, true, 'Saving');
    ctx.api.admin.upsertPolicy(payload)
      .then((result) => {
        render(outcome, h('div.outcome.tone-border-ok', [
          h('div.outcome-head', [h('span.outcome-title', { text: 'Policy saved' })]),
          h('div.outcome-rows', [
            field('Id', result.id),
            field('Code', result.code),
            field('Detectors stored', payload.detector_codes.length ? payload.detector_codes.join(', ') : 'none'),
            field('Confidence floor', `${Math.round(payload.min_confidence * 100)}%`),
            field('Enabled', payload.enabled ? 'yes' : 'no'),
          ]),
          h('p.note', { text: 'Re-attaching a camera to this policy takes effect on the next analysed frame; no restart is needed.' }),
        ]));
        reload();
      })
      .catch((error) => render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })))
      .finally(() => busy(event.currentTarget, false));
  });

  scope.append(h('div.toolbar', [save]), outcome);
  openDialog({
    title: policy ? `Edit policy ${policy.code}` : 'Create a monitoring policy',
    description: 'Everything here is analysis tuning; it changes no camera connection setting.',
    width: 'wide',
    body: [scope],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
  });
}

/* ------------------------------------------------------------------ alerting and retention */

async function renderDelivery(node, ctx) {
  render(node, panel('Alerting and retention', [emptyState('Reading configuration...')]));
  let settings;
  let retention;
  try {
    [settings, retention] = await Promise.all([ctx.api.admin.notificationSettings(), ctx.api.admin.retention()]);
  } catch (error) {
    render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    return;
  }

  const channelRow = (name, state, explanation) => h('tr', [
    h('td', { text: name }),
    h('td', [h('span.chip', { class: `tone-${state === 'enabled' ? 'ok' : 'muted'}` }, [
      h('span.chip-shape', { text: state === 'enabled' ? '●' : '○', 'aria-hidden': 'true' }),
      h('span.chip-label', { text: state.replace('_', ' ') }),
    ])]),
    h('td', { text: explanation }),
  ]);

  const purge = h('button', { type: 'button', class: 'btn danger', text: 'Purge expired evidence now' });
  purge.addEventListener('click', () => {
    confirmDialog({
      title: 'Purge expired evidence?',
      message: 'Evidence past its retention date is deleted. This is irreversible and is recorded in the audit log.',
      confirmLabel: 'Purge now',
      onConfirm: () => {
        ctx.api.admin.purgeRetention()
          .then((result) => ctx.toast(`Server confirmed ${result.evidence_assets_removed} evidence asset(s) removed.`, 'warn'))
          .catch((error) => ctx.toast(describe(error), 'bad'));
      },
    });
  });
  ctx.gate(purge, 'admin.policies');

  render(node, [
    panel('Notification channels', [
      h('p.note', { text: settings.note }),
      h('table.matrix', [
        h('thead', [h('tr', [h('th', { text: 'Channel' }), h('th', { text: 'State' }), h('th', { text: 'What that means' })])]),
        h('tbody', [
          channelRow('Dashboard inbox', settings.dashboard, 'Alerts appear in the bell on this console for the recipient.'),
          channelRow('Webhook', settings.webhook, settings.webhook === 'enabled' ? 'An outbound integration is configured.' : 'No webhook URL is configured, so integrations receive nothing.'),
          channelRow('Email', settings.email, 'Not configured in this build; attempts are recorded as failed deliveries so the gap is visible.'),
          channelRow('SMS', settings.sms, 'Not configured in this build; attempts are recorded as failed deliveries.'),
          channelRow('Mobile push', settings.mobile_push, 'Not configured in this build; attempts are recorded as failed deliveries.'),
        ]),
      ]),
      h('p.note.tone-fg-warn', { text: 'A channel shown as not configured does not silently swallow alerts: the notification is stored with state failed and the failure reason, which the Overview banner reports.' }),
    ]),
    panel('Retention', [
      field('Evidence', `${retention.evidence_retention_days} days`),
      field('Health history', `${retention.health_retention_days} days`),
      field('Audit log', `${retention.audit_retention_days} days`),
      h('p.note', { text: 'Expired evidence is purged by the supervisor as evidence expires; the button below runs the same pass immediately.' }),
      h('div.toolbar', [purge]),
      !ctx.can('admin.policies') ? gatingNotice('admin.policies', 'Retention changes and purges need this permission.') : null,
    ]),
  ]);
}

/* ------------------------------------------------------------------ audit log */

async function renderAudit(node, ctx) {
  const filters = { action: '', actor: '', since: '', limit: '200' };
  const results = h('div.audit-results');
  render(results, emptyState('Loading recent audit entries...'));

  const grid = h('div.filter-bar');
  Object.entries({
    action: 'Action contains',
    actor: 'Actor contains',
    since: 'Since',
    limit: 'Limit',
  }).forEach(([key, label]) => {
    const input = key === 'since'
      ? textInput({ id: `wt-au-${key}`, type: 'date', 'aria-label': label })
      : textInput({ id: `wt-au-${key}`, 'aria-label': label, value: filters[key] });
    input.addEventListener(key === 'since' ? 'change' : 'input', (event) => { filters[key] = event.target.value; });
    grid.append(h('div.filter-item', [h('label.inline', { for: `wt-au-${key}`, text: label }), input]));
  });

  const run = () => {
    const query = {};
    Object.entries(filters).forEach(([key, value]) => {
      if (!value) return;
      query[key] = key === 'since' ? new Date(`${value}T00:00:00Z`).toISOString() : value;
    });
    render(results, emptyState('Reading the audit trail...'));
    ctx.api.admin.audit(query)
      .then((payload) => paintAudit(payload.entries || []))
      .catch((error) => render(results, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })));
  };

  const apply = h('button', { type: 'button', class: 'btn primary', text: 'Apply filters' });
  apply.addEventListener('click', run);

  function paintAudit(entries) {
    if (!entries.length) {
      render(results, emptyState('No audit entry matches these filters.'));
      return;
    }
    render(results, h('table.matrix.dense', [
      h('thead', [h('tr', [
        h('th', { text: 'When' }), h('th', { text: 'Actor' }), h('th', { text: 'Action' }),
        h('th', { text: 'Object' }), h('th', { text: 'Outcome' }), h('th', { text: 'Source' }), h('th', { text: 'Detail' }),
      ])]),
      h('tbody', entries.map((entry) => h('tr', [
        h('td', [timeEl(entry.created_at)]),
        h('td.mono', { text: entry.actor || 'system' }),
        h('td.mono', { text: entry.action }),
        h('td', { text: `${entry.object_type || '-'} ${entry.object_id || ''}`.trim() }),
        h('td', [h('span.chip', { class: `tone-${entry.outcome === 'failure' ? 'bad' : 'muted'}` }, [
          h('span.chip-shape', { text: entry.outcome === 'failure' ? '✖' : '●', 'aria-hidden': 'true' }),
          h('span.chip-label', { text: entry.outcome }),
        ])]),
        h('td.mono', { text: entry.source_ip || '-' }),
        h('td', { text: entry.details ? JSON.stringify(entry.details) : '-', class: 'wrap' }),
      ]))),
    ]));
  }

  render(node, panel('Audit log', [
    h('p.note', { text: 'Every operational action is recorded here with the actor, object, outcome and source address. Failed sign-ins are recorded too, so a lockout has an explanation.' }),
    grid,
    h('div.toolbar', [apply]),
    results,
  ]));
  run();
}

/* ------------------------------------------------------------------ operational report */

async function renderReports(node, ctx) {
  const results = h('div.report-results');
  const from = textInput({ id: 'wt-report-from', type: 'date', 'aria-label': 'Report window start' });
  const to = textInput({ id: 'wt-report-to', type: 'date', 'aria-label': 'Report window end' });

  // Pre-filled rather than left blank so the chart on screen and the window it was measured
  // over are the same thing an auditor can re-request and reproduce. From is 29 days back,
  // making the default a full thirty inclusive days.
  const today = new Date();
  to.value = isoDay(today);
  from.value = isoDay(new Date(today.getTime() - 29 * 86400000));

  const run = () => {
    render(results, emptyState('Measuring...'));
    ctx.api.admin.operationsReport({
      since: from.value ? `${from.value}T00:00:00Z` : undefined,
      // The end of the chosen day, not its start: a report that stops at midnight tonight would
      // quietly drop the shift the operator is asking about.
      until: to.value ? `${to.value}T23:59:59Z` : undefined,
    })
      .then(paint)
      .catch((error) => render(results, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })));
  };

  function paint(report) {
    const latency = report.mean_acknowledgement_seconds;
    const reviewRate = report.candidate_events
      ? Math.round((report.events_reviewed / report.candidate_events) * 100)
      : null;
    render(results, [
      h('p.note', { text: `Window measured from ${absoluteText(report.window_start)} to ${absoluteText(report.window_end)}. Figures are counts taken directly from the records, not estimates.` }),
      h('div.counter-grid', [
        counter('Candidate events', report.candidate_events, 'warn'),
        counter('Events reviewed', report.events_reviewed, 'info'),
        counter('Review coverage', reviewRate === null ? 'no data' : `${reviewRate}%`, 'info', 'Share of detections a human has decided on - the false-alarm burden.'),
        counter('Mean acknowledgement', latency === null ? 'no data' : durationText(latency), 'ok', 'Time from detection to a human decision.'),
        counter('Incidents raised', report.incidents_raised, 'bad'),
        counter('Incidents open', report.incidents_open, 'bad'),
        counter('Incidents resolved', report.incidents_resolved, 'ok'),
        counter('Recorded false positives', report.recorded_false_positives, 'muted', 'Feeds the accuracy metric in section 21.'),
        counter('Cameras online', `${report.cameras_online} / ${report.cameras_total}`, 'ok'),
        counter('Cameras registered', report.cameras_registered, 'info'),
        counter('Notifications created', report.notifications_created, 'info'),
        counter('Notifications failed', report.notifications_failed, 'bad', 'Alerts that could not reach their intended channel.'),
      ]),
      panel('Incidents by severity', [severityChart(report.incidents_by_severity, report.incidents_raised)]),
      panel('Detections and incidents per day', [trendChart(report.daily_trend)]),
      panel('Busiest cameras', [topCamerasChart(report.top_cameras)]),
      panel('Notification failure reasons', [
        report.notification_failure_reasons.length
          ? h('ul.perm-list', report.notification_failure_reasons.map((reason) => h('li', { text: reason || 'no reason recorded' })))
          : h('p.note', { text: 'No failed notification in this window.' }),
      ]),
    ]);
  }

  const apply = h('button', { type: 'button', class: 'btn primary', text: 'Generate report' });
  apply.addEventListener('click', run);

  render(node, panel('Operational report', [
    h('p.note', { text: 'Measures the proposal\'s success criteria: whether humans actually review detections, how fast, and how many are false positives.' }),
    h('div.filter-bar', [
      h('div.filter-item', [h('label.inline', { for: 'wt-report-from', text: 'From' }), from]),
      h('div.filter-item', [h('label.inline', { for: 'wt-report-to', text: 'To' }), to]),
      apply,
    ]),
    results,
  ]));
  run();
}

function counter(label, value, tone, note = '') {
  return statTile({ label, value, tone, note });
}

function isoDay(date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
}

/* ------------------------------------------------------------------ report charts */

/*
 * Hand-drawn SVG and CSS bars rather than a charting library: the console's CSP allows only
 * 'self' for scripts and styles, so a bundled chart package could not load anyway. The shapes
 * take their colour from the tone classes, which is what keeps them in the same palette as the
 * chips and tiles on every other screen.
 */

const DONUT_CIRCUMFERENCE = 2 * Math.PI * 42;

function severityChart(rows, incidentsRaised) {
  if (!Array.isArray(rows)) return notServedChart('a severity breakdown');
  const total = rows.reduce((sum, row) => sum + row.count, 0);
  if (total === 0) {
    return h('p.note', { text: 'No incident was raised in this window, so there is no severity split to draw. The count above is zero for the same reason.' });
  }
  let swept = 0;
  const arcs = rows.filter((row) => row.count > 0).map((row) => {
    const length = (row.count / total) * DONUT_CIRCUMFERENCE;
    const arc = svg('circle.donut-arc', {
      class: severityTone(row.severity),
      cx: '50', cy: '50', r: '42', fill: 'none', 'stroke-width': '15',
      'stroke-dasharray': `${length.toFixed(2)} ${(DONUT_CIRCUMFERENCE - length).toFixed(2)}`,
      'stroke-dashoffset': (-swept).toFixed(2),
    }, [svg('title', { text: `${row.severity}: ${row.count}` })]);
    swept += length;
    return arc;
  });
  return h('div.chart-with-legend', [
    h('figure.donut-wrap', [
      svg('svg.donut', { viewBox: '0 0 100 100', role: 'img', 'aria-label': `Severity split of ${total} incidents` }, [
        svg('g', { transform: 'rotate(-90 50 50)' }, arcs),
        svg('text.donut-total', { x: '50', y: '50', 'text-anchor': 'middle', 'dominant-baseline': 'middle', text: String(total) }),
      ]),
      h('figcaption', { text: `${total} incident${total === 1 ? '' : 's'} raised in the window` }),
    ]),
    h('ul.chart-legend', rows.map((row) => h('li.key-row', { class: severityTone(row.severity) }, [
      h('span.key-swatch', { 'aria-hidden': 'true' }),
      h('span.key-label', { text: (SEVERITY[row.severity] || { label: row.severity }).label }),
      h('span.key-value.mono', { text: String(row.count) }),
      h('span.key-share.mono', { text: `${Math.round((row.count / total) * 100)}%` }),
    ]))),
    incidentsRaised !== total
      ? h('p.note', { text: `These buckets sum to ${total} while ${incidentsRaised} incidents were raised: only the four named severities are counted here.` })
      : null,
  ]);
}

/*
 * A 320x120 box drawn at its own aspect ratio. The alternative - stretching a square viewBox
 * across a wide panel - turns every data point into an ellipse, which is exactly the kind of
 * distortion a figure an auditor might quote should not carry.
 */
const TREND_BOX = { width: 320, height: 120, padX: 6, padTop: 10, baseline: 104 };

function trendChart(trend) {
  if (!trend || !Array.isArray(trend.days)) return notServedChart('a daily trend');
  const days = trend.days;
  if (days.length === 0) {
    return h('p.note', { text: 'The window produced no day buckets.' });
  }
  const detectionsTotal = days.reduce((sum, day) => sum + day.detections, 0);
  const incidentsTotal = days.reduce((sum, day) => sum + day.incidents, 0);
  if (detectionsTotal === 0 && incidentsTotal === 0) {
    return h('p.note', { text: `Nothing was recorded on any of the ${days.length} days plotted. A flat line at zero is the honest reading of a quiet fortnight - it is not a broken chart.` });
  }
  const peak = Math.max(...days.map((day) => Math.max(day.detections, day.incidents)), 1);
  const x = (index) => (days.length === 1
    ? TREND_BOX.width / 2
    : TREND_BOX.padX + (index / (days.length - 1)) * (TREND_BOX.width - TREND_BOX.padX * 2));
  const y = (value) => TREND_BOX.baseline - (value / peak) * (TREND_BOX.baseline - TREND_BOX.padTop);
  const points = (key) => days.map((day, index) => `${x(index).toFixed(1)},${y(day[key]).toFixed(1)}`).join(' ');
  const series = (key, toneClass) => svg('polyline.trend-line', {
    class: toneClass, points: points(key), fill: 'none', 'stroke-width': '2',
  });
  const dots = (key, toneClass) => days.map((day, index) => day[key] === 0
    ? null
    : svg('circle.trend-dot', { class: toneClass, cx: x(index).toFixed(1), cy: y(day[key]).toFixed(1), r: '2.6' }));
  const box = { viewBox: `0 0 ${TREND_BOX.width} ${TREND_BOX.height}`, preserveAspectRatio: 'xMidYMid meet' };

  return h('div.chart-block', [
    h('figure.trend-wrap', [
      svg('svg.trend', {
        ...box,
        role: 'img',
        'aria-label': `Daily detections and incidents across ${days.length} days, peak ${peak} in a day`,
      }, [
        svg('line.trend-axis', { x1: '0', y1: String(TREND_BOX.baseline), x2: String(TREND_BOX.width), y2: String(TREND_BOX.baseline) }),
        series('detections', 'tone-info'),
        series('incidents', 'tone-warn'),
        ...dots('detections', 'tone-info'),
        ...dots('incidents', 'tone-warn'),
      ]),
      h('figcaption.trend-scale', [
        h('span', { text: `highest day: ${peak}` }),
        h('span', { text: `${days[0].day} to ${days[days.length - 1].day}` }),
      ]),
    ]),
    h('ul.chart-legend', [
      legendRow('tone-info', 'Candidate detections', detectionsTotal),
      legendRow('tone-warn', 'Incidents raised', incidentsTotal),
    ]),
    h('p.note', { text: trend.truncated
      ? `${days.length} days plotted with ${trend.excluded_days} earlier day(s) in the window left out - the chart is capped so a long window is never drawn as a thinned sample. Narrow the From date to see the rest.`
      : `${days.length} consecutive days plotted, gaps included: a day with nothing recorded is drawn at zero rather than skipped.` }),
  ]);
}

function topCamerasChart(rows) {
  if (!Array.isArray(rows)) return notServedChart('a busiest-camera breakdown');
  if (rows.length === 0) {
    return h('p.note', { text: 'No camera in the registry produced a detection or an incident in this window, so there is nothing to rank.' });
  }
  const peak = Math.max(...rows.map((row) => row.detections), 1);
  return h('div.rank-list', [
    h('p.note', { text: `Bars are candidate detections; the smaller figure is incidents raised from that camera. Only the ${rows.length} busiest are listed.` }),
    ...rows.map((row) => h('div.rank-row', [
      h('div.rank-label', [
        h('strong.mono', { text: row.code }),
        h('span', { text: row.display_name }),
        row.campus_location ? h('span.dim', { text: row.campus_location }) : null,
      ]),
      h('div.rank-track', [h('div.rank-fill', { class: 'tone-info', style: `--bar-w: ${Math.round((row.detections / peak) * 100)}%` })]),
      h('div.rank-value.mono', [
        h('span', { text: `${row.detections} detected` }),
        h('span.dim', { text: `${row.incidents} incident${row.incidents === 1 ? '' : 's'}` }),
      ]),
    ])),
  ]);
}

function legendRow(toneClass, label, value) {
  return h('li.key-row', { class: toneClass }, [
    h('span.key-swatch', { 'aria-hidden': 'true' }),
    h('span.key-label', { text: label }),
    h('span.key-value.mono', { text: String(value) }),
  ]);
}

function severityTone(value) {
  return `tone-${(SEVERITY[value] || { tone: 'muted' }).tone}`;
}

function notServedChart(what) {
  return h('p.note.tone-fg-bad', { text: `The server did not return ${what}. The console process is older than this screen expects; restart it to measure the window with the breakdown.` });
}

/* ------------------------------------------------------------------ system status */

async function renderSystem(node, ctx) {
  render(node, panel('System status', [emptyState('Reading system state...')]));
  try {
    const system = await ctx.api.admin.system();
    render(node, panel('System status', [
      h('div.two-col', [
        panel('Deployment', [
          field('Environment', system.environment),
          field('HTTPS enforced', system.require_https ? 'yes - plain HTTP writes are refused' : 'no - acceptable only for a lab trial'),
          field('Evidence directory', system.evidence_dir),
          field('Key ring file', system.key_ring),
        ]),
        panel('Capacity in use', [
          field('Concurrent stream limit', system.max_concurrent_streams),
          field('Concurrent connection-test limit', system.max_concurrent_connection_tests),
          field('Managed source streams', system.managed_sessions),
          field('Browser live sessions', system.live_view_sessions),
          h('p.note', { text: 'Several viewers of one camera share a single managed source stream, so viewers can exceed managed_sessions. When the cap is reached, activation and live start are refused with a capacity error rather than queued silently.' }),
        ]),
      ]),
      h('p.note', { text: `Read at ${absoluteText(new Date().toISOString())}.` }),
    ]));
  } catch (error) {
    render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
  }
}

/* ------------------------------------------------------------------ helpers */

function groupName(ctx, id) {
  const found = ctx.groups().find((group) => group.id === id);
  return found ? found.name : `${id}`;
}

function describe(error) {
  if (error instanceof ApiError) return error.display;
  return 'The request could not be completed.';
}
