/**
 * Incident records (proposal sections 12, 13.4).
 *
 * The candidate detections that raise these records are reviewed under AI Intelligence; this
 * section owns the record itself. Every mutation renders the record the server returned, so
 * the operator sees the new state and the appended action rather than a bare confirmation.
 *
 * Evidence is the deliberate exception: an auditor may read the record and its metadata but
 * must not obtain the image, so the asset link only appears with the matching permission.
 */

import { ApiError } from './api.js';
import {
  INCIDENT_STATUS,
  SEVERITY,
  absoluteText,
  busy,
  bytesText,
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
  statusChip,
  textInput,
  timeEl,
} from './ui.js';

const CATEGORIES = ['intrusion', 'restricted_zone', 'unattended_object', 'unusual_movement', 'physical_altercation', 'theft_like_activity', 'camera_tamper', 'other'];
const OUTCOMES = ['actioned_by_security', 'false_positive', 'no_action_required', 'referred_to_police', 'maintenance_correction', 'training_observation'];

export function mount(host, ctx) {
  const listHost = h('div.tab-content');
  const detailHost = h('div.tab-content');
  detailHost.hidden = true;
  /** The incident shown in place of the table, or null while the table is on screen. */
  let openId = null;

  host.append(listHost, detailHost);

  /* ---------------------------------------------------------- incident records */
  let incidents = [];
  let counts = {};
  let page = 1;
  const filters = { status: '', category: '', severity: '', camera_id: '', campus_location: '', since: '', until: '', query: '', assigned_to: '', limit: '25' };

  function statusTotal() {
    return Object.values(counts).reduce((sum, value) => sum + (Number(value) || 0), 0);
  }

  async function loadIncidents() {
    if (!ctx.can('incident.view')) {
      render(listHost, panel('Incident records', [
        h('p.note', { text: 'Reading incidents needs the "incident.view" permission, which your role does not grant.' }),
      ]));
      return;
    }
    if (openId === null) render(listHost, panel('Incident records', [emptyState('Loading incidents...')]));
    const query = { offset: String((page - 1) * Number(filters.limit)) };
    Object.entries(filters).forEach(([key, value]) => {
      if (value !== '' && value !== null && value !== undefined) query[key] = value;
    });
    try {
      const payload = await ctx.api.incidents.list(query);
      incidents = payload.incidents || [];
      counts = payload.counts || {};
    } catch (error) {
      if (openId === null) render(listHost, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
      return;
    }
    // While an incident is open the table keeps refreshing underneath, but the operator is
    // reading a record they may be typing into - repainting it from a timer would discard that.
    if (openId === null) paintIncidents();
  }

  function paintIncidents() {
    const create = h('button', { type: 'button', class: 'btn primary', text: 'Raise incident' });
    create.addEventListener('click', () => openCreateIncident(ctx, loadIncidents));
    ctx.gate(create, 'incident.create');

    const chipRow = h('div.chip-row');
    const filterBar = h('div.filter-bar');
    const addFilter = (key, label, kind, options) => {
      const input = kind === 'select'
        ? selectInput(options, { id: `wt-f-${key}`, name: key, 'aria-label': label })
        : textInput({ id: `wt-f-${key}`, name: key, type: kind, 'aria-label': label });
      input.value = filters[key] || '';
      input.addEventListener(kind === 'select' ? 'change' : 'input', (event) => {
        filters[key] = event.target.value;
        if (kind !== 'text' && kind !== 'search') {
          page = 1;
          loadIncidents();
        }
      });
      filterBar.append(h('div.filter-item', [h('label.inline', { for: `wt-f-${key}`, text: label }), input]));
      return input;
    };

    addFilter('severity', 'Severity', 'select', [{ value: '', label: 'Any severity' }, ...Object.keys(SEVERITY).map((value) => ({ value, label: SEVERITY[value].label }))]);
    addFilter('category', 'Category', 'select', [{ value: '', label: 'Any category' }, ...CATEGORIES.map((value) => ({ value, label: value }))]);
    const search = addFilter('query', 'Text search', 'text');
    addFilter('camera_id', 'Camera', 'select', [{ value: '', label: 'Any camera' }, ...ctx.cameras().map((camera) => ({ value: camera.id, label: `${camera.code} - ${camera.display_name}` }))]);
    addFilter('campus_location', 'Location', 'text');
    addFilter('since', 'Since', 'date');
    addFilter('until', 'Until', 'date');
    addFilter('assigned_to', 'Assignee id', 'text');
    addFilter('limit', 'Per page', 'select', [10, 25, 50, 100, 200, 500].map((size) => ({ value: String(size), label: `${size}` })));

    const applySearch = () => {
      page = 1;
      loadIncidents();
    };
    search.addEventListener('change', applySearch);
    const go = h('button', { type: 'button', class: 'btn', text: 'Search history' });
    go.addEventListener('click', applySearch);
    const reset = h('button', { type: 'button', class: 'btn ghost', text: 'Clear filters' });
    reset.addEventListener('click', () => {
      Object.keys(filters).forEach((key) => { filters[key] = key === 'limit' ? '25' : ''; });
      page = 1;
      loadIncidents();
    });

    /**
     * The mockup asked for All / Active / Resolved. The server records six distinct states, and
     * "active" would silently merge open, investigating and assigned into one number an auditor
     * could not reconcile with the register, so the chips carry the real states and click
     * straight into the status filter.
     */
    const chip = (key, label, count, tone) => {
      const active = filters.status === key;
      const button = h('button', {
        type: 'button',
        class: `chip-toggle tone-${tone}${active ? ' is-active' : ''}`,
        'aria-pressed': active ? 'true' : 'false',
      }, [h('span', { text: label }), h('span.chip-count', { text: String(count) })]);
      button.addEventListener('click', () => {
        filters.status = active ? '' : key;
        page = 1;
        loadIncidents();
      });
      return button;
    };

    const chips = [chip('', 'All', statusTotal(), 'info')];
    Object.entries(INCIDENT_STATUS).forEach(([key, meta]) => {
      if (!counts[key] && filters.status !== key) return;
      chips.push(chip(key, meta.label, counts[key] || 0, meta.tone));
    });
    render(chipRow, [h('span.chip-row-label', { text: 'State' }), ...chips]);

    const matching = filters.status ? (counts[filters.status] || 0) : statusTotal();
    const pages = Math.max(1, Math.ceil(matching / Number(filters.limit)));
    const previous = h('button', { type: 'button', class: 'btn small', text: 'Previous' });
    previous.disabled = page <= 1;
    previous.addEventListener('click', () => {
      page = Math.max(1, page - 1);
      loadIncidents();
    });
    const next = h('button', { type: 'button', class: 'btn small', text: 'Next' });
    next.disabled = page >= pages;
    next.addEventListener('click', () => {
      page += 1;
      loadIncidents();
    });

    const rows = incidents.map((row) => {
      const open = h('button', { type: 'button', class: 'btn small', text: 'Open' });
      open.addEventListener('click', () => showIncident(row.id));
      return h('tr', [
        h('td.mono', { text: row.reference }),
        h('td', [h('div.name', { text: row.title }), h('div.sub', { text: row.category })]),
        h('td', [statusChip(row.status, INCIDENT_STATUS)]),
        h('td', [statusChip(row.severity, SEVERITY)]),
        h('td', { text: row.campus_location || '-' }),
        h('td', [timeEl(row.occurred_at)]),
        h('td.num', { text: String((row.actions || []).length) }),
        h('td.num', { text: String((row.evidence || []).length) }),
        h('td.actions', [open]),
      ]);
    });

    render(listHost, panel(`Incident records - ${incidents.length} on this page`, [
      chipRow,
      filterBar,
      h('div.toolbar', [go, reset, h('div.toolbar-spacer'), previous, h('span.dim', { text: `Page ${page} of ${pages}` }), next, create]),
      h('p.note', {
        text: matching
          ? `Counts are exact totals across all ${statusTotal()} records this account can read with the other filters applied - not only this page. Showing ${incidents.length} of the ${matching} in ${filters.status ? (INCIDENT_STATUS[filters.status] || { label: filters.status }).label : 'any state'}.`
          : 'No incident matches these filters for the cameras this account can read.',
      }),
      incidents.length
        ? h('table.matrix.dense', [
            h('thead', [h('tr', [
              h('th', { text: 'Reference' }), h('th', { text: 'Incident' }), h('th', { text: 'Status' }), h('th', { text: 'Severity' }),
              h('th', { text: 'Location' }), h('th', { text: 'Occurred' }), h('th', { class: 'num', text: 'Actions' }),
              h('th', { class: 'num', text: 'Evidence' }), h('th', { text: '' }),
            ])]),
            h('tbody', rows),
          ])
        : emptyState('No incident matches these filters. Widen the date range or choose All above to search history.'),
      !ctx.can('incident.create') ? gatingNotice('incident.create', 'This role records observations but does not raise incidents.') : null,
    ]));
  }

  /* ------------------------------------------------------ one incident, in page */

  async function showIncident(incidentId) {
    let incident;
    try {
      incident = (await ctx.api.incidents.get(incidentId)).incident;
    } catch (error) {
      ctx.toast(describe(error), 'bad');
      return;
    }

    openId = incidentId;
    listHost.hidden = true;
    detailHost.hidden = false;

    const bannerHost = h('div.incident-banner');
    const outcome = h('div.outcome-host');
    const recordHost = h('div.tab-content');
    const evidenceHost = h('div.tab-content');
    const timelineHost = h('div.tab-content');
    const actionsHost = h('div.tab-content');

    const back = h('button', { type: 'button', class: 'btn ghost', text: 'Back to incident list' });
    back.addEventListener('click', () => {
      openId = null;
      detailHost.hidden = true;
      listHost.hidden = false;
      loadIncidents();
    });

    const controls = staticTabs(h('div.tabs'), {
      idPrefix: 'wt-inc',
      ariaLabel: 'Incident views',
      items: [
        { id: 'record', label: 'Record', node: recordHost },
        { id: 'evidence', label: 'Evidence', node: evidenceHost },
        { id: 'timeline', label: 'Timeline', node: timelineHost },
        { id: 'actions', label: 'Acknowledge and workflow', node: actionsHost },
      ],
    });

    const done = (next, message) => {
      incident = next;
      render(outcome, incidentSummary(next, message));
      paint();
      void loadIncidents();
    };

    function paint() {
      const severityMeta = SEVERITY[incident.severity] || { label: incident.severity, tone: 'muted' };
      const statusMeta = INCIDENT_STATUS[incident.status] || { label: incident.status, tone: 'muted' };
      render(bannerHost, h('div.incident-head', { class: `tone-border-${severityMeta.tone}` }, [
        h('div.incident-head-top', [
          h('span.chip', { class: `tone-${severityMeta.tone}` }, [
            h('span.chip-shape', { text: severityMeta.shape || '', 'aria-hidden': 'true' }),
            h('span.chip-label', { text: `${severityMeta.label} severity` }),
          ]),
          h('span.chip', { class: `tone-${statusMeta.tone}` }, [
            h('span.chip-shape', { text: statusMeta.shape || '', 'aria-hidden': 'true' }),
            h('span.chip-label', { text: statusMeta.label }),
          ]),
          h('strong.incident-head-title', { text: incident.title }),
        ]),
        h('p.incident-head-detail', { text: incident.summary || 'No summary was recorded on this incident.' }),
        h('p.incident-head-ref.mono', { text: `${incident.reference} · ${incident.category} · occurred ${absoluteText(incident.occurred_at)}` }),
      ]));

      render(recordHost, h('div.two-col', [
        panel('Record', [
          field('Reference', incident.reference),
          field('Title', incident.title),
          field('Summary', incident.summary),
          field('Category', incident.category),
          h('div.field-row', [h('span.field-label', { text: 'Severity' }), h('span.field-value', [statusChip(incident.severity, SEVERITY)])]),
          h('div.field-row', [h('span.field-label', { text: 'Status' }), h('span.field-value', [statusChip(incident.status, INCIDENT_STATUS)])]),
          field('Camera', incident.camera_id ? cameraLabel(ctx, incident.camera_id) : null),
          field('Campus location', incident.campus_location),
          field('Occurred', absoluteText(incident.occurred_at)),
          field('Created', absoluteText(incident.created_at)),
          field('Raised from event', incident.origin_event_id),
        ]),
        panel('Ownership and closure', [
          field('Assigned to', userLabel(ctx, incident.assigned_to)),
          field('Escalated to', userLabel(ctx, incident.escalated_to)),
          field('Resolved at', incident.resolved_at ? absoluteText(incident.resolved_at) : null),
          field('Outcome', incident.outcome),
          field('Resolution', incident.resolution),
          field('Duration so far', durationText((Date.now() - new Date(incident.created_at).getTime()) / 1000)),
        ]),
      ]));
      render(evidenceHost, [evidencePanel(incident, ctx)]);
      render(timelineHost, [
        incident.actions.length
          ? h('ul.timeline', incident.actions.map((action) => h('li.tl-item', [
              h('span.tl-marker', { class: 'tone-bg-info', 'aria-hidden': 'true' }),
              h('div.tl-body', [
                h('div.tl-head', [h('strong', { text: action.action.replace(/_/g, ' ') }), timeEl(action.created_at), h('span.dim', { text: `actor ${userLabel(ctx, action.actor_id)}` })]),
                h('p.tl-detail', { text: action.note || 'no note recorded' }),
              ]),
            ])))
          : emptyState('No actions have been recorded on this incident yet.'),
      ]);
      render(actionsHost, [
        h('p.note', { text: 'There is no separate acknowledgement record: taking ownership is an assignment action and saying you saw it is a note, both appended to the timeline with your name and the time.' }),
        assignBlock(incident, ctx, done),
        escalateBlock(incident, ctx, done),
        noteBlock(incident, ctx, done),
        resolveBlock(incident, ctx, done),
        reopenBlock(incident, ctx, done),
      ]);
    }

    render(detailHost, [
      h('div.toolbar', [back, h('div.toolbar-spacer')]),
      bannerHost,
      controls.node,
      outcome,
    ]);
    paint();
  }

  loadIncidents();
  return {
    autoRefreshMs: 30000,
    refresh: () => loadIncidents(),
    teardown: null,
  };
}

/* ------------------------------------------------------------------ raise incident */

function openCreateIncident(ctx, afterChange) {
  const scope = h('div.create-incident');
  const outcome = h('div.outcome-host');
  const inputs = {};

  const add = (name, label, props = {}) => {
    const input = props.kind === 'select'
      ? selectInput(props.options, { id: `wt-nc-${name}`, name })
      : props.kind === 'textarea'
        ? h('textarea', { class: 'input', id: `wt-nc-${name}`, name, rows: props.rows || '3' })
        : props.kind === 'datetime'
          ? textInput({ id: `wt-nc-${name}`, name, type: 'datetime-local' })
          : textInput({ id: `wt-nc-${name}`, name, ...props.dom });
    scope.querySelector('.create-grid').append(formField(name, label, input, props.hint));
    inputs[name] = input;
    return input;
  };

  scope.append(h('div.grid-2.create-grid'));

  add('title', 'Title', { requiredHint: true, hint: 'Short, factual and searchable. Minimum five characters.' });
  add('category', 'Category', { kind: 'select', options: CATEGORIES.map((value) => ({ value, label: value })) });
  add('severity', 'Severity', { kind: 'select', options: Object.keys(SEVERITY).map((value) => ({ value, label: SEVERITY[value].label })) });
  add('camera_id', 'Camera', {
    kind: 'select',
    options: [{ value: '', label: 'Not tied to one camera' }, ...ctx.cameras().map((camera) => ({ value: camera.id, label: `${camera.code} - ${camera.display_name}` }))],
  });
  add('campus_location', 'Campus location', { hint: 'Leave blank to inherit the camera position.' });
  add('occurred_at', 'Occurred at', { kind: 'datetime', hint: 'Blank means the server records the moment of reporting.' });
  add('summary', 'Summary', { kind: 'textarea', hint: 'What was observed, what was done, what remains.' });

  const submit = h('button', { type: 'button', class: 'btn primary', text: 'Raise incident' });
  submit.addEventListener('click', (event) => {
    const payload = {
      title: inputs.title.value.trim(),
      category: inputs.category.value,
      severity: inputs.severity.value,
      summary: inputs.summary.value.trim() || null,
      camera_id: inputs.camera_id.value || null,
      campus_location: inputs.campus_location.value.trim() || null,
      occurred_at: inputs.occurred_at.value ? new Date(inputs.occurred_at.value).toISOString() : null,
    };
    if (payload.title.length < 5) {
      showFieldError(scope, 'title', 'A title of at least five characters is needed for the record to be searchable.');
      return;
    }
    showFieldError(scope, null, null);
    busy(event.currentTarget, true, 'Raising');
    ctx.api.incidents.create(payload)
      .then((result) => {
        render(outcome, incidentSummary(result.incident, 'Incident raised'));
        if (afterChange) afterChange();
      })
      .catch((error) => {
        if (error instanceof ApiError && error.field) showFieldError(scope, error.field, error.display);
        render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
      })
      .finally(() => busy(event.currentTarget, false));
  });

  scope.append(h('div.toolbar', [submit]), outcome);

  openDialog({
    title: 'Raise an incident manually',
    description: 'For anything a person observed that no detector raised. The reference number is assigned by the server.',
    width: 'wide',
    body: [scope],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
    onClose: () => afterChange && afterChange(),
  });
}

/* ------------------------------------------------------------------ evidence */

function evidencePanel(incident, ctx) {
  const items = [];
  if (!incident.evidence.length) {
    items.push(emptyState('No evidence asset is attached to this incident.'));
  }
  incident.evidence.forEach((asset) => {
    const isImage = (asset.content_type || '').startsWith('image/');
    const cell = h('div.evidence-item');

    if (ctx.can('evidence.view')) {
      cell.append(isImage
        ? h('a.evidence-thumb', { href: ctx.api.incidents.evidenceUrl(asset.id), target: '_blank', rel: 'noreferrer', 'aria-label': `Open evidence ${asset.id} full size` }, [
            h('img', { src: ctx.api.incidents.evidenceUrl(asset.id), alt: `Evidence ${asset.kind} captured ${absoluteText(asset.captured_at)}`, loading: 'lazy' }),
          ])
        : h('a.btn.small', { href: ctx.api.incidents.evidenceUrl(asset.id), target: '_blank', rel: 'noreferrer', text: `Open ${asset.content_type}` }));
    } else {
      cell.append(h('div.evidence-none', [
        h('span.chip-shape', { text: '■', 'aria-hidden': 'true', class: 'tone-fg-muted' }),
        h('span', { text: 'Asset withheld: evidence.view is not granted to this role.' }),
      ]));
    }

    const exportBtn = h('a', { class: 'btn small', href: ctx.api.incidents.evidenceUrl(asset.id, true), text: 'Export' });
    ctx.gate(exportBtn, 'evidence.export');
    if (exportBtn.disabled) exportBtn.removeAttribute('href');

    cell.append(
      h('div.evidence-meta', [
        h('strong', { text: `${asset.kind} #${asset.id}` }),
        h('span', { text: `${asset.content_type} · ${bytesText(asset.byte_size)}` }),
        timeEl(asset.captured_at),
        h('span.sha', { text: `sha256 ${clip(asset.sha256 || '', 16)}...`, title: asset.sha256 }),
        asset.expires_at ? h('span.dim', { text: `retained until ${absoluteText(asset.expires_at)}` }) : h('span.dim', { text: 'no expiry recorded' }),
      ]),
      exportBtn
    );
    items.push(cell);
  });

  return panel('Evidence', [h('div.evidence-grid', items)],
    ctx.can('evidence.export') ? null : h('span.dim', { text: 'export disabled' }));
}

/* ------------------------------------------------------------------ workflow blocks */

function assignBlock(incident, ctx, done) {
  const control = assigneeControl(ctx, 'Assign to');
  const save = h('button', { type: 'button', class: 'btn', text: 'Assign' });
  save.addEventListener('click', (event) => {
    const userId = control.value();
    if (userId === null) {
      control.showError('Choose a person or enter their numeric user id.');
      return;
    }
    busy(event.currentTarget, true, 'Assigning');
    ctx.api.incidents.assign(incident.id, userId)
      .then((payload) => done(payload.incident, 'Incident assigned'))
      .catch((error) => control.showError(describe(error)))
      .finally(() => busy(event.currentTarget, false));
  });
  ctx.gate(save, 'incident.assign');

  return panel('Assignment', [
    field('Currently assigned to', userLabel(ctx, incident.assigned_to)),
    control.node,
    h('div.toolbar', [save]),
    ctx.can('incident.assign') ? null : gatingNotice('incident.assign'),
  ]);
}

function escalateBlock(incident, ctx, done) {
  const control = assigneeControl(ctx, 'Escalate to');
  const note = h('textarea.input', { id: `wt-esc-${incident.id}`, rows: '2', 'aria-label': 'Escalation reason' });
  const save = h('button', { type: 'button', class: 'btn', text: 'Escalate' });
  save.addEventListener('click', (event) => {
    const userId = control.value();
    if (userId === null) {
      control.showError('Choose who receives the escalation.');
      return;
    }
    busy(event.currentTarget, true, 'Escalating');
    ctx.api.incidents.escalate(incident.id, userId, note.value.trim() || null)
      .then((payload) => done(payload.incident, 'Incident escalated'))
      .catch((error) => control.showError(describe(error)))
      .finally(() => busy(event.currentTarget, false));
  });
  ctx.gate(save, 'incident.escalate');

  return panel('Escalation', [
    field('Currently escalated to', userLabel(ctx, incident.escalated_to)),
    control.node,
    h('div.form-field', [h('label', { for: `wt-esc-${incident.id}`, text: 'Reason recorded on the action' }), note]),
    h('div.toolbar', [save]),
    ctx.can('incident.escalate') ? null : gatingNotice('incident.escalate'),
  ]);
}

function noteBlock(incident, ctx, done) {
  const note = h('textarea.input', { id: `wt-note-${incident.id}`, rows: '3', maxlength: '4000', 'aria-label': 'New note' });
  const save = h('button', { type: 'button', class: 'btn', text: 'Record note' });
  save.addEventListener('click', (event) => {
    if (!note.value.trim()) {
      note.setCustomValidity('A note cannot be empty.');
      note.reportValidity();
      return;
    }
    busy(event.currentTarget, true, 'Recording');
    ctx.api.incidents.note(incident.id, note.value.trim())
      .then((payload) => {
        note.value = '';
        done(payload.incident, 'Note recorded');
      })
      .catch((error) => ctx.toast(describe(error), 'bad'))
      .finally(() => busy(event.currentTarget, false));
  });

  return panel('Add a note', [
    h('p.note', { text: 'Notes are appended to the action timeline with your name and the time. The server accepts them for anyone who can view this incident.' }),
    h('div.form-field', [h('label', { for: `wt-note-${incident.id}`, text: 'Observation or instruction' }), note]),
    h('div.toolbar', [save]),
  ]);
}

function resolveBlock(incident, ctx, done) {
  const scope = h('div.resolve-form');
  const outcomes = OUTCOMES.map((value) => ({ value, label: value.replace(/_/g, ' ') }));
  const outcomeSelect = selectInput([{ value: '', label: 'Choose an outcome...' }, ...outcomes],
    { id: `wt-res-outcome-${incident.id}` });
  const resolution = h('textarea.input', { id: `wt-res-text-${incident.id}`, rows: '3', maxlength: '4000', 'aria-label': 'Resolution description' });
  const falsePositive = h('input', { type: 'checkbox', id: `wt-res-fp-${incident.id}` });

  const save = h('button', { type: 'button', class: 'btn primary', text: 'Resolve incident' });
  save.addEventListener('click', (event) => {
    const text = resolution.value.trim();
    if (!outcomeSelect.value) {
      showFieldError(scope, 'outcome', 'Select the outcome so the record can be counted correctly in reports.');
      return;
    }
    if (text.length < 2) {
      showFieldError(scope, 'resolution', 'Describe what closed this incident.');
      return;
    }
    showFieldError(scope, null, null);
    busy(event.currentTarget, true, 'Resolving');
    ctx.api.incidents.resolve(incident.id, {
      outcome: outcomeSelect.value,
      resolution: text,
      false_positive: falsePositive.checked,
    })
      .then((payload) => done(payload.incident, falsePositive.checked ? 'Incident closed as false positive' : 'Incident resolved'))
      .catch((error) => ctx.toast(describe(error), 'bad'))
      .finally(() => busy(event.currentTarget, false));
  });
  ctx.gate(save, 'incident.resolve');

  scope.append(
    panel('Resolve', [
      field('Current status', (INCIDENT_STATUS[incident.status] || { label: incident.status }).label),
      h('div.form-field', { 'data-field': 'outcome' }, [
        h('label', { for: `wt-res-outcome-${incident.id}`, text: 'Outcome' }),
        outcomeSelect,
        h('span.hint', { text: 'Marking a detection as a false positive feeds the accuracy review in section 21.' }),
        fieldErrorSlot(),
      ]),
      h('div.form-field', { 'data-field': 'resolution' }, [
        h('label', { for: `wt-res-text-${incident.id}`, text: 'Resolution' }),
        resolution,
        fieldErrorSlot(),
      ]),
      h('div.form-field.check-field', [
        h('label', { for: `wt-res-fp-${incident.id}` }, [falsePositive, h('span', { text: 'This was a false positive - no security action was needed' })]),
      ]),
      h('div.toolbar', [save]),
      ctx.can('incident.resolve') ? null : gatingNotice('incident.resolve'),
    ])
  );
  return scope;
}

function reopenBlock(incident, ctx, done) {
  if (!['resolved', 'closed', 'false_positive'].includes(incident.status)) return null;
  const reason = textInput({ id: `wt-reopen-${incident.id}`, 'aria-label': 'Reason for reopening' });
  const save = h('button', { type: 'button', class: 'btn danger', text: 'Reopen' });
  save.addEventListener('click', (event) => {
    if (reason.value.trim().length < 3) {
      ctx.toast('A reopening reason of at least three characters is required.', 'warn');
      return;
    }
    busy(event.currentTarget, true, 'Reopening');
    ctx.api.incidents.reopen(incident.id, reason.value.trim())
      .then((payload) => done(payload.incident, 'Incident reopened'))
      .catch((error) => ctx.toast(describe(error), 'bad'))
      .finally(() => busy(event.currentTarget, false));
  });
  ctx.gate(save, 'incident.resolve');

  return panel('Reopen', [
    h('p.note', { text: 'This record was closed. Reopening states the reason on the action timeline and returns the incident to open.' }),
    h('div.form-field', [h('label', { for: `wt-reopen-${incident.id}`, text: 'Reason' }), reason]),
    h('div.toolbar', [save]),
  ]);
}

/* ------------------------------------------------------------------ assignee picker */

/**
 * The only user directory endpoint needs admin.users, which supervisors and operators do not
 * hold. Rather than 403 in silence, fall back to the numeric id and say why.
 */
function assigneeControl(ctx, label) {
  const error = h('span.field-error', { role: 'alert' });
  const directory = ctx.assignees();

  if (directory) {
    const select = selectInput(
      [{ value: '', label: `Choose ${label.toLowerCase()}...` }, ...directory.map((user) => ({ value: String(user.id), label: `${user.display_name} (${user.username})${user.is_active ? '' : ' - disabled'}` }))],
      { id: `wt-${slug(label)}`, 'aria-label': label }
    );
    return {
      node: h('div.form-field', [h('label', { for: select.id, text: label }), select, h('span.hint', { text: 'Populated from the user directory.' }), error]),
      value: () => (select.value === '' ? null : Number(select.value)),
      showError: (message) => { error.textContent = message; },
    };
  }

  const input = textInput({ id: `wt-${slug(label)}`, inputmode: 'numeric', 'aria-label': `${label} - numeric user id` });
  return {
    node: h('div.form-field', [
      h('label', { for: input.id, text: `${label} (user id)` }),
      input,
      h('span.hint', { text: 'Your role cannot read the user directory (it needs the "admin.users" permission), so enter the numeric id an administrator can give you.' }),
      error,
    ]),
    value: () => (input.value.trim() === '' || Number.isNaN(Number(input.value)) ? null : Number(input.value)),
    showError: (message) => { error.textContent = message; },
  };
}

/* ------------------------------------------------------------------ helpers */

function incidentSummary(incident, title) {
  return h('div.outcome.tone-border-info', [
    h('div.outcome-head', [h('span.outcome-title', { text: title }), statusChip(incident.status, INCIDENT_STATUS)]),
    h('div.outcome-rows', [
      field('Reference', incident.reference),
      field('Title', incident.title),
      field('Severity', (SEVERITY[incident.severity] || { label: incident.severity }).label),
      field('Assigned to', incident.assigned_to === null ? 'unassigned' : `user id ${incident.assigned_to}`),
      field('Escalated to', incident.escalated_to === null ? 'nobody' : `user id ${incident.escalated_to}`),
      field('Actions recorded', incident.actions.length),
      field('Evidence assets', incident.evidence.length),
      field('Outcome', incident.outcome),
    ]),
    h('p.note', { text: 'The record above is the server response, not an assumption made by this console.' }),
  ]);
}

function formField(name, label, input, hint) {
  return h('div.form-field', { 'data-field': name }, [
    h('label', { for: input.id, text: label }),
    input,
    hint ? h('span.hint', { text: hint }) : null,
    fieldErrorSlot(),
  ]);
}

function cameraLabel(ctx, id) {
  const found = ctx.cameras().find((camera) => camera.id === id);
  return found ? `${found.display_name} (${found.code})` : `camera ${id}`;
}

function userLabel(ctx, id) {
  if (id === null || id === undefined) return 'not recorded';
  const found = (ctx.assignees() || []).find((user) => user.id === id);
  return found ? `${found.display_name} (@${found.username})` : `user id ${id}`;
}

function clip(value, length) {
  const text = String(value);
  return text.length > length ? `${text.slice(0, length)}` : text;
}

function slug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, '-');
}

function describe(error) {
  if (error instanceof ApiError) return error.display;
  return 'The request could not be completed.';
}
