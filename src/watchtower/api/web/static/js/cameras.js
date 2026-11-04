/**
 * Camera management (proposal sections 6, 7, 10, 13.2).
 *
 * Registration is deliberately two-stage: creating a record never starts a stream. The
 * operator runs a connection test, reads the specific section 6.5 outcome, then presses
 * Activate. Both registration methods are one form component behind keyboard-operable tabs,
 * and a 400/409 `detail.field` highlights the exact input at fault.
 */

import { ApiError } from './api.js';
import {
  CAMERA_STATUS,
  PROBE_RESULT,
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
  staticTabs,
  textInput,
  timeEl,
} from './ui.js';

/** Which registration tab owns each server-reported field name. */
const FIELD_TAB = {
  rtsp_url: 'rtsp',
  method: 'rtsp',
  host: 'structured',
  port: 'structured',
  stream_path: 'structured',
  username: 'structured',
  password: 'structured',
  transport: 'structured',
};

export function mount(host, ctx) {
  const tableHost = h('div.table-scroll');
  const notice = h('div.list-note');
  const toolbar = h('div.toolbar');
  let rows = [];
  let textFilter = '';
  let statusFilter = '';

  host.append(toolbar, notice, tableHost);

  function buildToolbar() {
    const add = h('button', { type: 'button', class: 'btn primary', text: 'Add camera' });
    add.addEventListener('click', () => openAddCamera(ctx, load));
    ctx.gate(add, 'camera.register');

    const refresh = h('button', { type: 'button', class: 'btn', text: 'Refresh' });
    refresh.addEventListener('click', () => load());

    const search = textInput({
      id: 'wt-camera-filter',
      placeholder: 'code, name or location',
      'aria-label': 'Filter cameras by code, name or campus location',
    });
    search.addEventListener('input', (event) => {
      textFilter = event.target.value.trim().toLowerCase();
      paint();
    });

    const statusSelect = selectInput(
      [{ value: '', label: 'All statuses' }, ...Object.entries(CAMERA_STATUS).map(([value, meta]) => ({ value, label: meta.label }))],
      { id: 'wt-camera-status', 'aria-label': 'Filter cameras by status' }
    );
    statusSelect.addEventListener('change', (event) => {
      statusFilter = event.target.value;
      paint();
    });

    render(toolbar, [
      h('div.toolbar-group', [h('label.inline', { for: 'wt-camera-filter', text: 'Find' }), search]),
      h('div.toolbar-group', [h('label.inline', { for: 'wt-camera-status', text: 'Status' }), statusSelect]),
      h('div.toolbar-spacer'),
      refresh,
      add,
    ]);
  }

  async function load() {
    buildToolbar();
    try {
      rows = await ctx.api.cameras.list();
      ctx.setCameras(rows);
      render(notice, ctx.can('camera.register') ? '' : gatingNotice('camera.register', 'This role cannot add cameras.'));
    } catch (error) {
      rows = [];
      render(notice, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    }
    paint();
  }

  function paint() {
    const visible = rows.filter((row) => {
      const textMatch = !textFilter
        || [row.code, row.display_name, row.campus_location]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(textFilter));
      return textMatch && (!statusFilter || row.status === statusFilter);
    });

    if (!visible.length) {
      render(tableHost, panel('Camera registry', [
        emptyState(rows.length
          ? 'No camera matches these filters.'
          : 'No cameras are visible to your role. A technical operator adds one with Add camera, verifies the connection, then activates it.'),
      ]));
      return;
    }

    render(tableHost, panel(`Camera registry - showing ${visible.length} of ${rows.length}`, [
      h('table.matrix.dense', [
        h('thead', [h('tr', [
          h('th', { text: 'Code' }),
          h('th', { text: 'Camera' }),
          h('th', { text: 'Status' }),
          h('th', { text: 'Campus location' }),
          h('th', { class: 'num', text: 'fps' }),
          h('th', { class: 'num', text: 'Viewers' }),
          h('th', { class: 'num', text: 'Retries' }),
          h('th', { text: 'Last connection test' }),
          h('th', { text: 'Last frame' }),
          h('th', { text: 'Actions' }),
        ])]),
        h('tbody', visible.map((row) => cameraRow(row, ctx, load))),
      ]),
    ]));
  }

  load();
  return { autoRefreshMs: ctx.timers.cameras, refresh: () => load(), teardown: null };
}

/* ------------------------------------------------------------------ one row */

function cameraRow(row, ctx, afterChange) {
  const open = h('button', { type: 'button', class: 'btn small', text: 'Manage' });
  open.addEventListener('click', () => openCamera(row, ctx, afterChange));

  const live = h('button', { type: 'button', class: 'btn small', text: 'Live view' });
  live.addEventListener('click', () => ctx.navigate('live'));
  ctx.gate(live, 'camera.view_live');
  if (!row.live_view_available && !live.disabled) {
    live.disabled = true;
    live.title = 'No managed stream is running for this camera, so there is nothing to view yet.';
  }

  return h('tr', { class: `row-tone-${(CAMERA_STATUS[row.status] || {}).tone || 'muted'}` }, [
    h('td.mono', { text: row.code }),
    h('td', [
      h('div.name', { text: row.display_name }),
      h('div.sub', { text: row.model || (row.is_registered ? 'registered' : 'draft record') }),
    ]),
    h('td', [
      statusChipCamera(row.status),
      h('div.sub', { text: `desired: ${row.desired_state}` }),
    ]),
    h('td', { text: row.campus_location }),
    h('td.num', { text: row.measured_fps ? row.measured_fps.toFixed(1) : '0.0' }),
    h('td.num', { text: String(row.viewers) }),
    h('td.num', { text: String(row.retry_count) }),
    h('td', [
      row.last_probe_result ? probeChip(row.last_probe_result) : h('span.dim', { text: 'never tested' }),
      row.last_error_code && row.status !== 'online'
        ? h('div.sub', { text: `last fault: ${row.last_error_code}` })
        : null,
    ]),
    h('td', [row.last_successful_frame_at
      ? timeEl(row.last_successful_frame_at)
      : h('span.dim', { text: 'no frame yet' })]),
    h('td.actions', [open, live]),
  ]);
}

/* ------------------------------------------------------------------ add camera */

function openAddCamera(ctx, onDone) {
  const form = buildRegistrationForm(ctx);
  openDialog({
    title: 'Add a camera',
    description: 'Describe the connection, test it, then activate. Creating the record does not start video.',
    width: 'wide',
    body: [form.warning, form.node],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
    onClose: () => {
      form.cancelPending();
      if (onDone) onDone();
    },
  });
}

function buildRegistrationForm(ctx) {
  const scope = h('div.registration');
  const resultHost = h('div.outcome-host');
  let inFlight = null;
  let busyFlag = false;

  const identity = identitySection(ctx);

  /* Method A - paste the whole address. */
  const rtspInput = textInput({
    id: 'wt-reg-rtsp',
    name: 'rtsp_url',
    placeholder: 'rtsp://user:pass@10.20.30.41:554/cam/realmonitor?channel=1&subtype=0',
  });
  const transportA = selectInput([{ value: 'tcp', label: 'TCP (recommended)' }, { value: 'udp', label: 'UDP' }], { id: 'wt-reg-transport-a' });
  const verifiedA = h('input', { type: 'checkbox', id: 'wt-reg-verified' });

  const rtspNode = h('div.tabpanel-inner', [
    formField('rtsp_url', 'Full RTSP connection string', rtspInput,
      'Paste exactly what VLC opens, credentials included if the camera needs them. The server parses it and encrypts the password; the string is never returned to this browser.'),
    formField('transport', 'Transport', transportA, null),
    h('div.form-field.check-field', { 'data-field': 'verified_in_vlc' }, [
      h('label', { for: 'wt-reg-verified' }, [verifiedA, h('span', { text: 'This address was already opened successfully in VLC by the registering operator' })]),
      h('span.hint', { text: 'Section 6.2 expects a human confirmation before an address becomes a registry entry.' }),
      fieldErrorSlot(),
    ]),
    h('p.note', { text: 'Only rtsp and rtsps are accepted. Any other protocol is rejected before a probe is attempted.' }),
  ]);

  /* Method B - structured fields. */
  const fields = {};
  const spec = [
    ['host', 'Host or IP address', 'Reachable from the WATCH TOWER server, not necessarily from your desk.', { placeholder: '10.20.30.41' }],
    ['port', 'Port', 'Blank means the standard RTSP port 554.', { placeholder: '554', inputmode: 'numeric' }],
    ['stream_path', 'Stream path', 'The exact path confirmed in VLC.', { placeholder: '/cam/realmonitor?channel=1&subtype=0' }],
    ['username', 'Username', 'Blank means the camera needs no credential.', { autocomplete: 'off' }],
    ['password', 'Password', 'Encrypted before storage; the API never reads it back.', { type: 'password', autocomplete: 'new-password' }],
  ];
  spec.forEach(([name, label, hint, dom]) => {
    const input = textInput({ id: `wt-reg-${name}`, name, type: name === 'password' ? 'password' : 'text', ...dom });
    fields[name] = input;
    fields[name].label = label;
    fields[name].hint = hint;
  });
  fields.transport = selectInput([{ value: 'tcp', label: 'TCP (recommended)' }, { value: 'udp', label: 'UDP' }], { id: 'wt-reg-transport' });
  fields.verified = h('input', { type: 'checkbox', id: 'wt-reg-verified-b' });

  const structuredNode = h('div.tabpanel-inner', [
    h('div.grid-2', [
      formField('host', 'Host or IP address', fields.host, spec[0][2]),
      formField('port', 'Port', fields.port, spec[1][2]),
      formField('stream_path', 'Stream path', fields.stream_path, spec[2][2]),
      formField('username', 'Username', fields.username, spec[3][2]),
      formField('password', 'Password', fields.password, spec[4][2]),
      formField('transport', 'Transport', fields.transport, null),
    ]),
    h('div.form-field.check-field', { 'data-field': 'verified_in_vlc' }, [
      h('label', { for: 'wt-reg-verified-b' }, [fields.verified, h('span', { text: 'This connection was already opened successfully in VLC by the registering operator' })]),
      fieldErrorSlot(),
    ]),
  ]);

  const tabsControl = staticTabs(h('div.tabs'), {
    idPrefix: 'wt-reg',
    ariaLabel: 'How the camera is reached',
    items: [
      { id: 'rtsp', label: 'Method A: paste RTSP address', node: rtspNode },
      { id: 'structured', label: 'Method B: structured fields', node: structuredNode },
    ],
  });

  const testBtn = h('button', { type: 'button', class: 'btn primary', text: 'Test connection' });
  testBtn.addEventListener('click', () => runTest(testBtn));
  ctx.gate(testBtn, 'camera.configure');

  const registerBtn = h('button', { type: 'button', class: 'btn', text: 'Register camera' });
  registerBtn.addEventListener('click', () => runRegister(registerBtn));
  ctx.gate(registerBtn, 'camera.register');

  scope.append(
    identity.node,
    h('fieldset.form-block', [h('legend', { text: 'How the camera is reached' }), tabsControl.node]),
    h('div.toolbar', [testBtn, registerBtn]),
    resultHost
  );

  const currentMethod = () => tabsControl.current();

  function payload() {
    const base = identity.collect();
    if (currentMethod() === 'rtsp') {
      return {
        ...base,
        method: 'rtsp_string',
        rtsp_url: rtspInput.value.trim(),
        transport: transportA.value,
        verified_in_vlc: verifiedA.checked,
      };
    }
    return {
      ...base,
      method: 'structured',
      host: fields.host.value.trim() || undefined,
      port: fields.port.value.trim() || undefined,
      stream_path: fields.stream_path.value.trim() || undefined,
      username: fields.username.value.trim() || undefined,
      password: fields.password.value || undefined,
      transport: fields.transport.value,
      verified_in_vlc: fields.verified.checked,
    };
  }

  /** Cheap pre-flight so the operator is not made to wait 20 s for a trivially missing field. */
  function localCheck() {
    const data = payload();
    const problems = [];
    if (!data.display_name) problems.push(['display_name', 'Camera name is required.']);
    if (!data.code) problems.push(['code', 'Camera code is required.']);
    if (!data.campus_location) problems.push(['campus_location', 'Campus location is required.']);
    if (data.method === 'rtsp_string' && !data.rtsp_url) problems.push(['rtsp_url', 'An RTSP connection string is required.']);
    if (data.method === 'structured' && !data.host) problems.push(['host', 'A camera host address is required.']);
    if (data.method === 'structured' && !data.stream_path) problems.push(['stream_path', 'A stream path is required - the exact path VLC opens.']);
    if (!problems.length) {
      showFieldError(scope, null, null);
      return true;
    }
    const [name, message] = problems[0];
    if (FIELD_TAB[name]) tabsControl.activate(FIELD_TAB[name]);
    showFieldError(scope, name, message);
    render(resultHost, h('p.note.tone-fg-warn', {
      role: 'alert',
      text: `${problems.length} field${problems.length === 1 ? '' : 's'} need attention before a request is sent.`,
    }));
    return false;
  }

  function revealServerError(error) {
    if (error instanceof ApiError && error.field) {
      if (FIELD_TAB[error.field]) tabsControl.activate(FIELD_TAB[error.field]);
      showFieldError(scope, error.field, error.display);
      render(resultHost, h('div.outcome.tone-border-bad', [
        h('div.outcome-head', [h('span.outcome-title', { text: 'Rejected by the server' })]),
        h('div.outcome-rows', [field('Code', error.code), field('Field', error.field), field('Message', error.display)]),
      ]));
    } else {
      render(resultHost, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
    }
  }

  /** A probe runs 5-20 s, so re-entry is blocked and the button says what it is doing. */
  async function runTest(node) {
    if (busyFlag || !localCheck()) return;
    busyFlag = true;
    busy(node, true, 'Testing');
    render(resultHost, h('p.note.tone-fg-info', {
      role: 'status',
      text: 'Probing this address. The test decodes several frames and holds the stream briefly, which can take up to twenty seconds.',
    }));
    inFlight = new AbortController();
    try {
      const probe = await ctx.api.cameras.testDraft(payload(), inFlight.signal);
      showFieldError(scope, null, null);
      render(resultHost, [
        probeResult(probe, 'Connection test result'),
        probe.result === 'connection_successful'
          ? h('p.note.tone-fg-ok', { text: 'Now press Register camera to create the record, then activate it from the result shown there.' })
          : h('p.note', { text: 'Nothing was written to the registry. Correct the configuration and test again.' }),
      ]);
    } catch (error) {
      if (error && error.name === 'AbortError') {
        render(resultHost, h('p.note.tone-fg-muted', { text: PROBE_RESULT.test_cancelled.advice }));
      } else {
        revealServerError(error);
      }
    } finally {
      busy(node, false);
      inFlight = null;
      busyFlag = false;
    }
  }

  async function runRegister(node) {
    if (busyFlag || !localCheck()) return;
    busyFlag = true;
    busy(node, true, 'Registering');
    try {
      const result = await ctx.api.cameras.create(payload());
      render(resultHost, [
        h('div.outcome.tone-border-info', [
          h('div.outcome-head', [h('span.outcome-title', { text: 'Camera record created - not yet streaming' }), statusChipCamera(result.camera.status)]),
          h('div.outcome-rows', [
            field('Camera', `${result.camera.display_name} (${result.camera.code})`),
            field('Campus location', result.camera.campus_location),
            field('Desired state', result.camera.desired_state),
            field('Server message', result.message),
          ]),
        ]),
        result.connection_test ? probeResult(result.connection_test, 'Connection test run during registration') : null,
        activationOffer(result, ctx, resultHost),
      ]);
    } catch (error) {
      revealServerError(error);
    } finally {
      busy(node, false);
      busyFlag = false;
    }
  }

  const missing = [];
  if (!ctx.can('camera.register')) missing.push('"camera.register" to create the record');
  if (!ctx.can('camera.configure')) missing.push('"camera.configure" to run a connection test');

  return {
    node: scope,
    warning: missing.length ? gatingNotice(missing.join(' and '), 'This role cannot complete part of the registration flow.') : null,
    cancelPending() {
      if (inFlight) inFlight.abort();
    },
  };
}

function activationOffer(result, ctx, resultHost) {
  if (!result.activatable) {
    return h('p.note.tone-fg-warn', {
      text: 'Activate is not offered: the registration test did not pass. Correct the configuration, run a new connection test, then activate.',
    });
  }
  const activateBtn = h('button', { type: 'button', class: 'btn primary', text: 'Activate this camera' });
  activateBtn.addEventListener('click', () => {
    busy(activateBtn, true, 'Activating');
    ctx.api.cameras.activate(result.camera.id)
      .then((camera) => resultHost.append(cameraResult(camera, 'Camera activated - managed stream requested')))
      .catch((error) => resultHost.append(h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })))
      .finally(() => busy(activateBtn, false));
  });
  ctx.gate(activateBtn, 'camera.configure');
  return h('div.toolbar', [
    h('span.dim', { text: 'Registering left this as a record only. Confirm the result above, then activate to start the managed stream.' }),
    activateBtn,
  ]);
}

/* ------------------------------------------------------------------ shared inputs */

function identitySection(ctx) {
  const host = h('div.grid-2');
  const inputs = {};

  const add = (name, label, props = {}) => {
    const input = props.kind === 'select'
      ? selectInput(props.options, { id: `wt-reg-${name}`, name })
      : textInput({ id: `wt-reg-${name}`, name, ...props.dom });
    host.append(formField(name, label, input, props.hint));
    inputs[name] = input;
    return input;
  };

  add('display_name', 'Camera name', { hint: 'For example: Main Gate Vehicle Boom.' });
  add('code', 'Camera code', { dom: { placeholder: 'AFIT-GATE-001' }, hint: '2-64 characters: letters, digits, dot, underscore or hyphen. Must be unique.' });
  add('campus_location', 'Campus location', { hint: 'Where the device physically is, so a reviewer can act on it.' });
  add('camera_group_id', 'Camera group', {
    kind: 'select',
    options: [{ value: '', label: 'Ungrouped' }, ...ctx.groups().map((group) => ({ value: String(group.id), label: `${group.name} (${group.code})` }))],
    hint: 'Grouping also scopes which role grants can see this camera.',
  });
  add('monitoring_policy_id', 'Monitoring policy', {
    kind: 'select',
    options: [{ value: '', label: 'No analysis policy' }, ...ctx.policies().map((policy) => ({ value: String(policy.id), label: `${policy.name}${policy.enabled ? '' : ' (disabled)'}` }))],
    hint: 'Chooses which detectors run and the confidence floor.',
  });
  add('model', 'Model', { hint: 'Optional. Helps a technician replace the device.' });
  add('description', 'Description', { hint: 'Optional. What it covers and any known blind spot.' });

  return {
    node: h('fieldset.form-block', [h('legend', { text: 'What this camera is' }), host]),
    collect: () => ({
      display_name: inputs.display_name.value.trim(),
      code: inputs.code.value.trim(),
      campus_location: inputs.campus_location.value.trim(),
      camera_group_id: inputs.camera_group_id.value === '' ? null : Number(inputs.camera_group_id.value),
      monitoring_policy_id: inputs.monitoring_policy_id.value === '' ? null : Number(inputs.monitoring_policy_id.value),
      model: inputs.model.value.trim() || null,
      description: inputs.description.value.trim() || null,
    }),
  };
}

function formField(name, label, input, hint) {
  return h('div.form-field', { 'data-field': name }, [
    h('label', { for: input.id, text: label }),
    input,
    hint ? h('span.hint', { text: hint }) : null,
    fieldErrorSlot(),
  ]);
}

/* ------------------------------------------------------------------ manage one camera */

function openCamera(camera, ctx, afterChange) {
  const working = { ...camera };
  const statusHost = h('div.tab-content');
  const configNode = editForm(working, ctx, afterChange);
  const healthHost = h('div.tab-content');

  const controls = staticTabs(h('div.tabs'), {
    idPrefix: 'wt-cam',
    ariaLabel: 'Camera views',
    items: [
      { id: 'status', label: 'Status and actions', node: statusHost },
      { id: 'config', label: 'Configuration', node: configNode },
      { id: 'health', label: 'Health history', node: healthHost },
    ],
    onChange: (id) => {
      if (id === 'health') loadHealth(working.id, ctx, healthHost);
    },
  });

  paintStatus(statusHost, working, ctx, afterChange);

  openDialog({
    title: `${working.display_name} - ${working.code}`,
    description: working.campus_location,
    width: 'wide',
    body: [controls.node],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
    onClose: () => {
      if (afterChange) afterChange();
    },
  });
}

function paintStatus(hostNode, camera, ctx, afterChange) {
  // One persistent result host: re-painting re-appends the same node, so the last outcome
  // stays on screen after a status change rather than vanishing.
  const outcome = h('div.outcome-host');

  const show = (content) => {
    render(outcome, content);
    paint();
  };
  const fail = (error) => show(h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));

  const withBusy = (node, label, task) => {
    if (!node || node.disabled) return;
    busy(node, true, label);
    Promise.resolve()
      .then(task)
      .catch(fail)
      .finally(() => busy(node, false));
  };

  const testBtn = h('button', { type: 'button', class: 'btn primary', text: 'Test connection' });
  testBtn.addEventListener('click', (event) => {
    show(h('p.note.tone-fg-info', { role: 'status', text: 'Probing the stored connection. This can take up to twenty seconds.' }));
    withBusy(event.currentTarget, 'Testing', () => ctx.api.cameras.test(camera.id).then((probe) => {
      camera.last_probe_result = probe.result;
      show(probeResult(probe, 'Connection test result'));
      if (afterChange) afterChange();
    }));
  });
  ctx.gate(testBtn, 'camera.configure');

  const activateBtn = h('button', { type: 'button', class: 'btn primary', text: 'Activate' });
  activateBtn.addEventListener('click', (event) => {
    withBusy(event.currentTarget, 'Activating', () => ctx.api.cameras.activate(camera.id).then((next) => {
      Object.assign(camera, next);
      show(cameraResult(next, 'Camera activated - managed stream requested'));
      if (afterChange) afterChange();
    }));
  });
  ctx.gate(activateBtn, 'camera.configure');
  if (camera.last_probe_result !== 'connection_successful') {
    activateBtn.disabled = true;
    activateBtn.title = 'The backend refuses activation until a connection test passes. Run Test connection first.';
  } else if (camera.status === 'online' && camera.desired_state === 'running') {
    activateBtn.disabled = true;
    activateBtn.title = 'This camera is already activated and online.';
  }

  const pollBtn = h('button', { type: 'button', class: 'btn', text: 'Poll health now' });
  pollBtn.addEventListener('click', (event) => {
    withBusy(event.currentTarget, 'Polling', () => ctx.api.cameras.refresh(camera.id).then((result) => {
      camera.status = result.status;
      show(h('div.outcome.tone-border-info', [
        h('div.outcome-head', [h('span.outcome-title', { text: 'Health poll result' }), statusChipCamera(result.status)]),
        h('div.outcome-rows', [
          field('Reason code', result.reason),
          field('Detail', result.detail),
          field('Changed from previous state', result.changed ? 'yes' : 'no'),
          field('Seconds since last frame', result.seconds_since_frame === null || result.seconds_since_frame === undefined
            ? 'no frame recorded'
            : `${result.seconds_since_frame}s`),
        ]),
      ]));
      if (afterChange) afterChange();
    }));
  });

  const disableBtn = h('button', { type: 'button', class: 'btn danger', text: 'Disable camera' });
  disableBtn.addEventListener('click', () => {
    confirmDialog({
      title: `Disable ${camera.code}?`,
      message: 'The managed stream stops, live viewing ends and the supervisor will not retry. Bringing it back needs a technical operator to re-test and activate.',
      confirmLabel: 'Disable camera',
      onConfirm: () => {
        ctx.api.cameras.disable(camera.id)
          .then((next) => {
            Object.assign(camera, next);
            show(cameraResult(next, 'Camera disabled'));
            if (afterChange) afterChange();
          })
          .catch(fail);
      },
    });
  });
  ctx.gate(disableBtn, 'camera.disable');

  const liveBtn = h('button', { type: 'button', class: 'btn', text: 'Open live monitoring' });
  liveBtn.addEventListener('click', () => ctx.navigate('live'));
  ctx.gate(liveBtn, 'camera.view_live');
  if (!camera.live_view_available && !liveBtn.disabled) {
    liveBtn.disabled = true;
    liveBtn.title = 'No managed stream is running for this camera, so there is nothing to view.';
  }

  function paint() {
    render(hostNode, [
      h('div.two-col', [
        panel('Record', [
          field('Code', camera.code),
          field('Camera name', camera.display_name),
          field('Campus location', camera.campus_location),
          field('Model', camera.model),
          field('Description', camera.description),
          field('Camera group', groupName(ctx, camera.camera_group_id)),
          field('Monitoring policy', policyName(ctx, camera.monitoring_policy_id)),
          field('Registered', camera.is_registered ? 'yes' : 'no'),
        ]),
        panel('Runtime state', [
          h('div.field-row', [h('span.field-label', { text: 'Status' }), h('span.field-value', [statusChipCamera(camera.status)])]),
          field('Desired state', camera.desired_state),
          field('Measured fps', camera.measured_fps ? camera.measured_fps.toFixed(2) : '0.00'),
          field('Live viewers', camera.viewers),
          field('Retry count', camera.retry_count),
          field('Live view available', camera.live_view_available ? 'yes - a managed stream is running' : 'no - no stream to relay'),
          h('div.field-row', [h('span.field-label', { text: 'Last connection test' }), h('span.field-value', [
            camera.last_probe_result ? probeChip(camera.last_probe_result) : h('span.dim', { text: 'never tested' }),
          ])]),
          field('Last successful frame', camera.last_successful_frame_at ? absoluteText(camera.last_successful_frame_at) : null),
          field('Last error code', camera.last_error_code),
          field('Verified in VLC by operator', camera.verified_in_vlc ? 'yes' : 'no'),
          field('Credential stored', camera.has_secret ? 'yes (value never disclosed to the browser)' : 'no credential on file'),
          h('p.note', { text: 'The RTSP address and camera password are held by the server and never sent to this browser. A stored credential is reported only as present or absent.' }),
        ]),
      ]),
      h('div.toolbar', [testBtn, activateBtn, pollBtn, liveBtn, disableBtn]),
      camera.status === 'pending_setup'
        ? h('p.note.tone-fg-warn', { text: 'This record exists but has never been activated, so no video is available. That is the expected state after registration.' })
        : null,
      !ctx.can('camera.configure') ? gatingNotice('camera.configure', 'Testing and activation are disabled for this role.') : null,
      outcome,
    ]);
  }

  paint();
}

/* ------------------------------------------------------------------ edit form */

function editForm(camera, ctx, afterChange) {
  const scope = h('div.tabpanel-inner');
  const outcome = h('div.outcome-host');

  if (!ctx.can('camera.configure')) {
    scope.append(panel('Stored connection', [
      h('p.note', { text: 'Editing needs the "camera.configure" permission, which your role does not grant. The values below are read-only.' }),
      field('Host', camera.host),
      field('Port', camera.port),
      field('Stream path', camera.stream_path),
      field('Username', camera.username),
      field('Transport', camera.transport),
      field('Password on file', camera.has_secret ? 'yes (value never disclosed)' : 'no'),
      field('Verified in VLC', camera.verified_in_vlc ? 'yes' : 'no'),
    ]));
    return scope;
  }

  const inputs = {};
  const add = (name, label, value, props = {}) => {
    const input = props.kind === 'select'
      ? selectInput(props.options, { id: `wt-edit-${name}`, name })
      : textInput({ id: `wt-edit-${name}`, name, type: props.type || 'text', value: value === null || value === undefined ? '' : String(value), ...props.dom });
    if (props.type === 'password') input.setAttribute('autocomplete', 'new-password');
    scope.querySelector('.identity-grid').append(formField(name, label, input, props.hint));
    inputs[name] = input;
    return input;
  };

  scope.append(
    h('fieldset.form-block', [h('legend', { text: 'Identification and scope' }), h('div.grid-2.identity-grid')])
  );

  add('display_name', 'Camera name', camera.display_name);
  add('campus_location', 'Campus location', camera.campus_location);
  add('model', 'Model', camera.model);
  add('description', 'Description', camera.description);
  add('camera_group_id', 'Camera group', camera.camera_group_id, {
    kind: 'select',
    options: [{ value: '', label: 'Ungrouped' }, ...ctx.groups().map((g) => ({ value: String(g.id), label: g.name }))],
  });
  add('monitoring_policy_id', 'Monitoring policy', camera.monitoring_policy_id, {
    kind: 'select',
    options: [{ value: '', label: 'No analysis policy' }, ...ctx.policies().map((p) => ({ value: String(p.id), label: p.name }))],
  });

  scope.append(h('fieldset.form-block', [
    h('legend', { text: 'Connection - only fill this in to change it' }),
    h('p.note', { text: 'Saving a new address, port, stream path, username or password clears the last connection test. The camera must be re-tested before it can be activated again.' }),
    h('div.grid-2.connection-grid'),
  ]));

  const connectionGrid = scope.querySelector('.connection-grid');

  const addConn = (name, label, value, props = {}) => {
    const input = props.kind === 'select'
      ? selectInput(props.options, { id: `wt-edit-${name}`, name })
      : textInput({ id: `wt-edit-${name}`, name, type: props.type || 'text', value: value === null || value === undefined ? '' : String(value), ...props.dom });
    if (props.type === 'password') input.setAttribute('autocomplete', 'new-password');
    connectionGrid.append(formField(name, label, input, props.hint));
    inputs[name] = input;
    return input;
  };

  addConn('rtsp_url', 'Replace the whole RTSP address', '', { dom: { placeholder: 'rtsp://... - blank keeps the stored address' } });
  addConn('host', 'Or host', '', { dom: { placeholder: camera.host ? `blank keeps ${camera.host}` : 'camera address' } });
  addConn('port', 'Port', '', { dom: { placeholder: camera.port ? `blank keeps ${camera.port}` : '554', inputmode: 'numeric' } });
  addConn('stream_path', 'Stream path', '', { dom: { placeholder: camera.stream_path ? 'blank keeps the stored path' : '/cam/realmonitor?channel=1&subtype=0' } });
  addConn('username', 'Username', '', { dom: { placeholder: camera.username ? `blank keeps ${camera.username}` : 'blank for none', autocomplete: 'off' } });
  addConn('password', 'New password', '', { type: 'password', hint: 'Blank keeps the stored credential. Nothing typed here is echoed back by the API.' });
  addConn('transport', 'Transport', camera.transport || 'tcp', {
    kind: 'select',
    options: [{ value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }],
  });

  const saveBtn = h('button', { type: 'button', class: 'btn primary', text: 'Save changes' });
  saveBtn.addEventListener('click', (event) => {
    const patch = {
      display_name: inputs.display_name.value.trim(),
      campus_location: inputs.campus_location.value.trim(),
      model: inputs.model.value.trim() || null,
      description: inputs.description.value.trim() || null,
      camera_group_id: inputs.camera_group_id.value === '' ? null : Number(inputs.camera_group_id.value),
      monitoring_policy_id: inputs.monitoring_policy_id.value === '' ? null : Number(inputs.monitoring_policy_id.value),
    };
    const addressText = inputs.rtsp_url.value.trim();
    const structuredAddress = inputs.host.value.trim();
    if (addressText || structuredAddress) {
      if (addressText) patch.rtsp_url = addressText;
      else {
        patch.host = structuredAddress;
        if (inputs.port.value.trim()) patch.port = inputs.port.value.trim();
        if (inputs.stream_path.value.trim()) patch.stream_path = inputs.stream_path.value.trim();
        if (inputs.username.value.trim()) patch.username = inputs.username.value.trim();
        patch.transport = inputs.transport.value;
      }
      if (inputs.password.value) patch.password = inputs.password.value;
    }

    busy(event.currentTarget, true, 'Saving');
    ctx.api.cameras.update(camera.id, patch)
      .then((result) => {
        Object.assign(camera, result.camera);
        render(outcome, [
          cameraResult(result.camera, 'Camera updated'),
          result.connection_test
            ? probeResult(result.connection_test, 'Re-test run by the server after the change')
            : h('p.note', {
                class: (addressText || structuredAddress) ? 'tone-fg-warn' : 'tone-fg-muted',
                text: (addressText || structuredAddress)
                  ? 'The connection changed, so the stored test result was cleared. Run a connection test, then activate.'
                  : 'Only descriptive fields changed; the previous connection test still stands.',
              }),
        ]);
        if (afterChange) afterChange();
      })
      .catch((error) => {
        if (error instanceof ApiError && error.field) showFieldError(scope, error.field, error.display);
        render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
      })
      .finally(() => busy(event.currentTarget, false));
  });

  scope.append(h('div.toolbar', [saveBtn]), outcome);
  return scope;
}

/* ------------------------------------------------------------------ health history */

async function loadHealth(cameraId, ctx, hostNode) {
  if (!ctx.can('health.view')) {
    render(hostNode, panel('Health history', [
      h('p.note', { text: 'Health history needs the "health.view" permission, which your role does not grant.' }),
    ]));
    return;
  }
  render(hostNode, panel('Health history', [emptyState('Reading transitions...')]));
  try {
    const events = await ctx.api.cameras.health(cameraId, 50);
    if (!events.length) {
      render(hostNode, panel('Health history', [
        emptyState('No health transition has been recorded for this camera yet. The supervisor writes one whenever a status changes.'),
      ]));
      return;
    }
    render(hostNode, panel(`Health history - ${events.length} transitions`, [
      h('ul.timeline', events.map((entry) => h('li.tl-item', [
        h('span.tl-marker', { class: `tone-bg-${(CAMERA_STATUS[entry.to] || {}).tone || 'muted'}`, 'aria-hidden': 'true' }),
        h('div.tl-body', [
          h('div.tl-head', [
            statusChipCamera(entry.from, 'mini'),
            h('span.dim', { text: 'to' }),
            statusChipCamera(entry.to, 'mini'),
            timeEl(entry.observed_at),
            h('span.dim', { text: `held ${durationText(entry.duration_seconds)}` }),
          ]),
          h('p.tl-detail', { text: `${entry.reason || 'no reason code'}: ${entry.detail || 'no detail recorded'}` }),
        ]),
      ]))),
    ]));
  } catch (error) {
    render(hostNode, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
  }
}

/* ------------------------------------------------------------------ chips and helpers */

function statusChipCamera(value, extraClass = '') {
  const meta = CAMERA_STATUS[value] || { label: value || 'Unknown', tone: 'muted', shape: '?' };
  const chip = h('span.chip', { class: `tone-${meta.tone} ${extraClass}`.trim() });
  chip.append(h('span.chip-shape', { text: meta.shape, 'aria-hidden': 'true' }));
  chip.append(h('span.chip-label', { text: meta.label }));
  if (meta.note) chip.title = `${meta.note}${value ? ` (${value})` : ''}`;
  return chip;
}

function probeChip(value) {
  const meta = PROBE_RESULT[value] || { label: value, tone: 'muted', advice: value };
  const chip = h('span.chip', { class: `tone-${meta.tone}` });
  chip.append(h('span.chip-shape', { text: '◇', 'aria-hidden': 'true' }));
  chip.append(h('span.chip-label', { text: meta.label }));
  chip.title = `${meta.advice || value} (${value})`;
  return chip;
}

function probeResult(probe, title) {
  const meta = PROBE_RESULT[probe.result]
    || { label: probe.result, tone: 'warn', advice: 'The server returned a probe outcome this console does not recognise.' };
  return h('div.outcome', { class: `tone-border-${meta.tone}` }, [
    h('div.outcome-head', [h('span.outcome-title', { text: title }), probeChip(probe.result)]),
    h('div.outcome-rows', [
      field('Server message', probe.message),
      field('Frames decoded', probe.frames_decoded),
      field('Measured fps', probe.measured_fps ? Number(probe.measured_fps).toFixed(2) : '0.00'),
      field('Resolution', probe.width && probe.height ? `${probe.width} x ${probe.height}` : 'not reported'),
      field('Elapsed', `${Number(probe.elapsed_seconds).toFixed(1)} s`),
    ]),
    h('p.note', { class: `tone-fg-${meta.tone}`, text: meta.advice }),
  ]);
}

function cameraResult(camera, title) {
  return h('div.outcome.tone-border-info', [
    h('div.outcome-head', [h('span.outcome-title', { text: title }), statusChipCamera(camera.status)]),
    h('div.outcome-rows', [
      field('Camera', `${camera.display_name} (${camera.code})`),
      field('Desired state', camera.desired_state),
      field('Last connection test', camera.last_probe_result),
      field('Measured fps', camera.measured_fps),
      field('Viewers', camera.viewers),
      field('Retry count', camera.retry_count),
      field('Last error code', camera.last_error_code),
    ]),
    h('p.note', { text: camera.status === 'online'
      ? 'The managed stream is running. Open Live monitoring to view it.'
      : 'Video is only available once the server reports online; the state above is the authoritative result of this action.' }),
  ]);
}

function groupName(ctx, id) {
  if (id === null || id === undefined) return 'ungrouped';
  const found = ctx.groups().find((group) => group.id === id);
  return found ? found.name : `group ${id}`;
}

function policyName(ctx, id) {
  if (id === null || id === undefined) return 'no analysis policy';
  const found = ctx.policies().find((policy) => policy.id === id);
  return found ? found.name : `policy ${id}`;
}

function describe(error) {
  if (error instanceof ApiError) return error.display;
  return 'The request could not be completed.';
}
