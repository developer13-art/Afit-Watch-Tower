/**
 * AFIT WATCH TOWER - shared presentation primitives.
 *
 * Two rules shape everything here:
 *   1. Status is carried by text AND shape AND colour. Institutional security users may be
 *      on a poor monitor, in glare, or colour-blind; a colour-only chip is not a status.
 *   2. No innerHTML with data, no inline handlers. Nodes are built explicitly, so operator
 *      content (camera names, notes, audit detail) can never become markup.
 */

/* ------------------------------------------------------------------ status vocabulary */

/** Camera statuses from section 10 - the exact values GET /api/cameras returns. */
export const CAMERA_STATUS = {
  pending_setup: { label: 'Pending setup', shape: '◇', tone: 'neutral', note: 'Registered, not yet verified or activated. No video exists.' },
  testing: { label: 'Testing', shape: '◌', tone: 'info', note: 'A connection test is running.' },
  online: { label: 'Online', shape: '●', tone: 'ok', note: 'Frames are arriving.' },
  degraded: { label: 'Degraded', shape: '◐', tone: 'warn', note: 'Video is arriving but below the expected rate.' },
  reconnecting: { label: 'Reconnecting', shape: '○', tone: 'info', note: 'The stream dropped and the supervisor is retrying.' },
  offline: { label: 'Offline', shape: '■', tone: 'bad', note: 'No managed stream and no frames.' },
  authentication_failed: { label: 'Auth failed', shape: '✖', tone: 'bad', note: 'The camera rejected the credential.' },
  maintenance: { label: 'Maintenance', shape: '▲', tone: 'muted', note: 'Deliberately taken out of service.' },
  disabled: { label: 'Disabled', shape: '■', tone: 'muted', note: 'Stopped by an operator; will not start.' },
};

/** Connection-test results from section 6.5, each with the corrective action. */
export const PROBE_RESULT = {
  connection_successful: { label: 'Connection verified', tone: 'ok', advice: 'Streams decode frames. Registration can be activated.' },
  authentication_failed: { label: 'Authentication failed', tone: 'bad', advice: 'The camera rejected the username or password. Re-enter both; check the account is not locked on the device.' },
  host_unreachable: { label: 'Host unreachable', tone: 'bad', advice: 'No route to that address. Verify the IP, the VLAN and any firewall between the server and the camera.' },
  stream_path_invalid_or_unsupported: { label: 'Stream path invalid', tone: 'bad', advice: 'The host answered but the path is wrong. Use the exact path VLC opens, for example /cam/realmonitor?channel=1&subtype=0.' },
  video_decode_failed: { label: 'Video decode failed', tone: 'bad', advice: 'The stream arrived but the codec could not be decoded. Switch the sub-stream or the encoder profile on the camera.' },
  timed_out: { label: 'Test timed out', tone: 'warn', advice: 'The camera did not deliver frames in time. It may be busy or the path may be blocking; retry once, then check concurrent-connection limits.' },
  test_cancelled: { label: 'Test cancelled', tone: 'muted', advice: 'The test did not complete. Start it again when ready.' },
  testing: { label: 'Test in progress', tone: 'info', advice: 'The probe is still running.' },
};

export const VIEW_STATE = {
  not_started: { label: 'Not started', shape: '◇', tone: 'neutral', note: 'No live session has been opened for this tile.' },
  loading: { label: 'Starting', shape: '◌', tone: 'info', note: 'Connecting to the managed stream; no frame confirmed yet.' },
  live: { label: 'Live', shape: '●', tone: 'ok', note: 'Frames are arriving.' },
  reconnecting: { label: 'Reconnecting', shape: '○', tone: 'info', note: 'Frames have stopped and the supervisor is retrying.' },
  offline: { label: 'Offline', shape: '■', tone: 'bad', note: 'No video available for this camera.' },
};

export const INCIDENT_STATUS = {
  open: { label: 'Open', shape: '▲', tone: 'bad', note: 'Raised and awaiting action.' },
  investigating: { label: 'Investigating', shape: '◌', tone: 'warn', note: 'Someone is looking into it.' },
  assigned: { label: 'Assigned', shape: '◆', tone: 'info', note: 'A named person owns it.' },
  resolved: { label: 'Resolved', shape: '●', tone: 'ok', note: 'Closed with a recorded outcome.' },
  closed: { label: 'Closed', shape: '■', tone: 'muted', note: 'No further action.' },
  false_positive: { label: 'False positive', shape: '✖', tone: 'muted', note: 'The detection was not a real incident.' },
};

export const SEVERITY = {
  low: { label: 'Low', shape: '|', tone: 'muted', note: 'Note and monitor.' },
  medium: { label: 'Medium', shape: '||', tone: 'info', note: 'Respond during the shift.' },
  high: { label: 'High', shape: '|||', tone: 'warn', note: 'Respond now and inform the supervisor.' },
  critical: { label: 'Critical', shape: '!!', tone: 'bad', note: 'Immediate response; escalate without waiting.' },
};

export const EVENT_STATUS = {
  new: { label: 'New', shape: '▲', tone: 'warn', note: 'Awaiting a human decision.' },
  acknowledged: { label: 'Acknowledged', shape: '●', tone: 'info', note: 'A person has reviewed it.' },
  dismissed: { label: 'Dismissed', shape: '■', tone: 'muted', note: 'Recorded as not actionable.' },
  escalated: { label: 'Escalated', shape: '◆', tone: 'bad', note: 'Turned into an incident.' },
};

export function statusChip(value, dictionary, extraClass = '') {
  const meta = dictionary[value] || { label: value || 'Unknown', tone: 'muted', shape: '?' };
  const chip = h('span.chip', { class: `tone-${meta.tone} ${extraClass}`.trim() }, [
    h('span.chip-shape', { text: meta.shape, 'aria-hidden': 'true' }),
    h('span.chip-label', { text: meta.label }),
  ]);
  if (meta.note) chip.title = meta.note;
  return chip;
}

/* ------------------------------------------------------------------ node builder */

/**
 * h('button.btn.primary', {text, on: {click}}, [child, 'plain string'])
 * Selector syntax only; unknown props become attributes, so `disabled`, `href`, `type`,
 * `colspan` and `for` all work without a special case.
 *
 * The props slot also accepts the children list directly, which is the form used wherever a
 * node has no attributes: h('li.item', [h('span', {text: 'one'})]).
 */
export function h(spec, props = null, children = null) {
  // A list in the props position means children, which is how most call sites read:
  // h('div.section-head', [h('h2', ...), h('p', ...)]). Treated as attributes instead,
  // Object.entries() would emit 0="[object HTMLElement]" and the node would render empty.
  if (Array.isArray(props)) {
    children = props;
    props = null;
  }

  let rest = spec;
  const tagMatch = /^[a-zA-Z][\w-]*/.exec(rest);
  const tag = tagMatch ? tagMatch[0] : 'div';
  if (tagMatch) rest = rest.slice(tag.length);

  const node = document.createElement(tag);
  rest.split(/(?=[#.])/).forEach((part) => {
    if (!part) return;
    if (part[0] === '#') node.id = part.slice(1);
    else if (part[0] === '.') node.classList.add(part.slice(1).replace(/_/g, '-'));
  });

  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'text') node.textContent = String(value);
      else if (key === 'class') String(value).split(/\s+/).filter(Boolean).forEach((c) => node.classList.add(c));
      else if (key === 'on') Object.entries(value).forEach(([type, fn]) => node.addEventListener(type, fn));
      else if (key === 'aria') Object.entries(value).forEach(([k, v]) => node.setAttribute(`aria-${k}`, String(v)));
      else if (key === 'data') Object.entries(value).forEach(([k, v]) => { node.dataset[k] = String(v); });
      else if (key === 'ref') value(node);
      else if (value === true) node.setAttribute(key, '');
      else node.setAttribute(key, String(value));
    }
  }

  if (children !== null && children !== undefined) {
    (Array.isArray(children) ? children : [children]).forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
  }
  return node;
}

export function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * `h()` builds HTML elements. An SVG child created that way is in the wrong namespace and the
 * browser draws nothing at all - no error, just a blank box - so chart markup needs this
 * namespaced twin. Same selector syntax as `h()`.
 */
export function svg(spec, props = null, children = null) {
  if (Array.isArray(props)) {
    children = props;
    props = null;
  }
  let rest = spec;
  const tagMatch = /^[a-zA-Z][\w-]*/.exec(rest);
  const tag = tagMatch ? tagMatch[0] : 'g';
  if (tagMatch) rest = rest.slice(tag.length);

  const node = document.createElementNS(SVG_NS, tag);
  rest.split(/(?=[#.])/).forEach((part) => {
    if (!part) return;
    if (part[0] === '#') node.setAttribute('id', part.slice(1));
    else node.classList.add(part.slice(1).replace(/_/g, '-'));
  });

  if (props) {
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === 'text') node.textContent = String(value);
      else if (key === 'class') String(value).split(/\s+/).filter(Boolean).forEach((c) => node.classList.add(c));
      else if (key === 'aria') Object.entries(value).forEach(([k, v]) => node.setAttribute(`aria-${k}`, String(v)));
      else if (value === true) node.setAttribute(key, '');
      else node.setAttribute(key, String(value));
    }
  }

  if (children !== null && children !== undefined) {
    (Array.isArray(children) ? children : [children]).forEach((child) => {
      if (child === null || child === undefined || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
  }
  return node;
}

export function render(target, ...nodes) {
  clear(target);
  nodes.flat().forEach((n) => {
    if (n === null || n === undefined || n === false) return;
    target.append(n instanceof Node ? n : document.createTextNode(String(n)));
  });
  return target;
}

/** A labelled read-only value row, used everywhere a returned record must be shown. */
export function field(label, value, props = null) {
  const empty = value === null || value === undefined || value === '';
  return h('div.field-row', [
    h('span.field-label', { text: label }),
    h('span.field-value', props, [empty ? h('span.dim', { text: 'not recorded' }) : String(value)]),
  ]);
}

export function panel(title, body, aside = null) {
  return h('section.panel', [
    title ? h('header.panel-head', [h('h3', { text: title }), aside]) : null,
    h('div.panel-body', Array.isArray(body) ? body : [body]),
  ]);
}

export function emptyState(text) {
  return h('p.empty', { text });
}

/**
 * Headline number tile. The glyph and the sentence are both derived from what is counted, so
 * a tile never relies on colour alone to say whether the number is good or bad.
 */
export function statTile({ label, value, tone = 'info', note = '', icon = null }) {
  return h('div.counter', { class: `tone-${tone}`, title: note || label }, [
    h('span.counter-icon', { text: icon || SEVERITY_LIKE_GLYPH[tone] || '●', 'aria-hidden': 'true' }),
    h('span.counter-text', [
      h('span.counter-value', { text: String(value) }),
      h('span.counter-label', { text: label }),
      note ? h('span.counter-note', { text: note }) : null,
    ]),
  ]);
}

const SEVERITY_LIKE_GLYPH = {
  ok: '✓',
  warn: '!',
  bad: '▲',
  info: '◉',
  muted: '○',
  neutral: '◇',
};

/* ------------------------------------------------------------------ time */

const MINUTE = 60;
const HOUR = 3600;
const DAY = 86400;

export function parseDate(value) {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function relativeText(value, now = Date.now()) {
  const date = parseDate(value);
  if (!date) return 'unknown time';
  const delta = (now - date.getTime()) / 1000;
  const future = delta < 0;
  const magnitude = Math.abs(delta);
  if (magnitude < 45) return future ? 'in a moment' : 'just now';
  let text;
  if (magnitude < HOUR) text = `${Math.round(magnitude / MINUTE)} min`;
  else if (magnitude < DAY) text = `${Math.round(magnitude / HOUR)} h`;
  else {
    const days = Math.round(magnitude / DAY);
    if (days >= 31) return date.toLocaleDateString();
    text = `${days} day${days === 1 ? '' : 's'}`;
  }
  return future ? `in ${text}` : `${text} ago`;
}

export function absoluteText(value) {
  const date = parseDate(value);
  if (!date) return 'unknown time';
  return date.toLocaleString(undefined, { hour12: false });
}

/** <time> with the relative form visible and both the ISO and local instant on hover. */
export function timeEl(value, className = 'rel-time') {
  const date = parseDate(value);
  return h('time', {
    class: className,
    datetime: date ? date.toISOString() : '',
    title: date ? `${absoluteText(value)}\nISO ${date.toISOString()}` : 'no timestamp',
    text: relativeText(value),
  });
}

export function durationText(seconds) {
  if (seconds === null || seconds === undefined) return 'open';
  const total = Math.max(0, Math.round(Number(seconds)));
  if (total < 60) return `${total}s`;
  if (total < HOUR) return `${Math.floor(total / MINUTE)}m ${total % 60}s`;
  if (total < DAY) return `${Math.floor(total / HOUR)}h ${Math.floor((total % HOUR) / MINUTE)}m`;
  return `${Math.floor(total / DAY)}d ${Math.floor((total % DAY) / HOUR)}h`;
}

export function bytesText(size) {
  if (size === null || size === undefined) return 'unknown size';
  const n = Number(size);
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

/* ------------------------------------------------------------------ outcome reporting */

/**
 * The console must show what actually happened after an operational action, so every
 * mutation renders the returned record rather than only a toast.
 */
export function outcomeBox(tone, title, rows, { closable = true } = {}) {
  const box = h('div.outcome', { class: `tone-border-${tone}` }, [
    h('div.outcome-head', [
      h('span.outcome-title', { text: title }),
      closable
        ? h('button.btn.icon', {
            type: 'button',
            text: 'Close',
            aria: { label: 'Dismiss this result' },
            on: { click: () => box.remove() },
          })
        : null,
    ]),
    h('div.outcome-rows', rows),
  ]);
  return box;
}

export function noteLine(tone, text) {
  return h('p.note', { class: `tone-fg-${tone}`, role: tone === 'bad' ? 'alert' : 'status', text });
}

let liveRegion = null;
/** Announce transient state to assistive tech without a decorative toast. */
export function announce(message, tone = 'info') {
  if (!liveRegion) {
    liveRegion = h('div', { id: 'wt-live-region', aria: { live: 'polite', atomic: 'true' } });
    document.body.append(liveRegion);
  }
  clear(liveRegion);
  liveRegion.classList.add(`tone-fg-${tone}`);
  liveRegion.append(document.createTextNode(message));
}

/* ------------------------------------------------------------------ permission gating */

/**
 * Rather than showing a button the backend will reject with 403, a control the operator
 * cannot use is disabled and names the missing permission on hover and in the accessible
 * description.
 */
export function gate(node, permission, permissions, { hide = false } = {}) {
  if (!node) return node;
  if (!permission || permissions.has(permission)) return node;
  const missing = `Not available: your role does not grant the "${permission}" permission.`;
  if (hide) {
    node.remove();
    return null;
  }
  // An anchor cannot be `disabled`, and leaving its href intact would let a browser fetch a
  // record the backend would refuse, so links are defanged instead.
  if (node.tagName === 'A') {
    node.removeAttribute('href');
    node.removeAttribute('download');
    node.classList.add('is-gated');
    node.setAttribute('aria-disabled', 'true');
    node.title = missing;
    node.addEventListener('click', (event) => event.preventDefault());
    return node;
  }
  node.disabled = true;
  node.setAttribute('aria-disabled', 'true');
  node.title = missing;
  node.classList.add('is-gated');
  return node;
}

export function can(permissions, permission) {
  return permissions.has(permission);
}

export function gatingNotice(permission, extra = '') {
  return h('p.note.tone-fg-muted', {
    text: `${extra ? `${extra} ` : ''}Controls needing the "${permission}" permission are disabled for your role.`,
  });
}

/* ------------------------------------------------------------------ forms */

export function labelled(labelText, input, { hint = null, required = false, forId = null, errorSlot = null } = {}) {
  const id = input.id || forId;
  const parts = [];
  if (id) {
    parts.push(h('label', { for: id, class: required ? 'required' : '' }, [
      labelText,
      required ? h('span.req', { text: ' (required)', 'aria-hidden': 'true' }) : null,
    ]));
  } else {
    parts.push(h('span.label-text', { text: labelText }));
  }
  parts.push(input);
  if (hint) parts.push(h('span.hint', { text: hint }));
  if (errorSlot) parts.push(errorSlot);
  return h('div.form-field', parts);
}

export function textInput(props = {}) {
  return h('input', { class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false', ...props });
}

export function selectInput(options, props = {}) {
  const select = h('select', { class: 'input', ...props });
  options.forEach((option) => {
    if (option === null || option === undefined) return;
    const value = typeof option === 'object' ? option.value : option;
    const label = typeof option === 'object' ? option.label : option;
    select.append(h('option', { value: String(value), text: String(label) }));
  });
  return select;
}

export function button(label, onClick, { variant = '', ...props } = {}) {
  return h('button', {
    type: 'button',
    class: `btn ${variant}`.trim(),
    text: label,
    on: { click: onClick },
    ...props,
  });
}

/** Puts a 400/409 `detail.field` value onto the matching input. */
export function showFieldError(form, fieldName, message) {
  let matched = false;
  form.querySelectorAll('[data-field]').forEach((wrapper) => {
    const isMatch = wrapper.dataset.field === fieldName;
    const slot = wrapper.querySelector('.field-error');
    if (isMatch && slot) {
      slot.textContent = message;
      wrapper.classList.add('has-error');
      matched = true;
    } else if (slot) {
      slot.textContent = '';
      wrapper.classList.remove('has-error');
    }
  });
  if (!matched) announce(message, 'bad');
  return matched;
}

export function fieldErrorSlot() {
  return h('span.field-error', { role: 'alert' });
}

export function busy(buttonNode, isBusy, busyLabel = 'Working') {
  if (isBusy) {
    if (!buttonNode.dataset.idleLabel) buttonNode.dataset.idleLabel = buttonNode.textContent;
    buttonNode.disabled = true;
    buttonNode.setAttribute('aria-busy', 'true');
    buttonNode.textContent = `${busyLabel}...`;
  } else {
    buttonNode.disabled = false;
    buttonNode.removeAttribute('aria-busy');
    if (buttonNode.dataset.idleLabel) buttonNode.textContent = buttonNode.dataset.idleLabel;
  }
}

/* ------------------------------------------------------------------ tabs & dialogs */

/**
 * Accessible tablist: roles, aria-selected, roving tabindex, Left/Right/Home/End and
 * activation that moves focus into the panel.
 */
export function tabs(host, definitions, { onSwitch = null } = {}) {
  clear(host);
  const tablist = h('div.tablist', { role: 'tablist', aria: { label: definitions.ariaLabel || 'View' } });
  const panelsHost = h('div.tab-panels');
  const nodes = [];

  definitions.items.forEach((item, index) => {
    const tab = h('button', {
      type: 'button',
      class: 'tab',
      role: 'tab',
      id: `${definitions.idPrefix}-tab-${item.id}`,
      text: item.label,
      aria: {
        controls: `${definitions.idPrefix}-panel-${item.id}`,
        selected: index === definitions.active ? 'true' : 'false',
        tabindex: index === definitions.active ? '0' : '-1',
      },
      on: {
        click: () => activate(index),
        keydown: (event) => onTabKey(event, index),
      },
    });
    tablist.append(tab);
    nodes.push({ tab, item });
  });

  function panelFor(index) {
    const item = nodes[index].item;
    const panelNode = h('div', {
      role: 'tabpanel',
      class: 'tabpanel',
      id: `${definitions.idPrefix}-panel-${item.id}`,
      tabindex: '0',
      aria: { labelledby: `${definitions.idPrefix}-tab-${item.id}` },
    });
    item.render(panelNode);
    return panelNode;
  }

  function activate(index) {
    nodes.forEach((entry, i) => {
      entry.tab.setAttribute('aria-selected', i === index ? 'true' : 'false');
      entry.tab.tabIndex = i === index ? 0 : -1;
    });
    clear(panelsHost);
    panelsHost.append(panelFor(index));
    definitions.active = index;
    if (onSwitch) onSwitch(nodes[index].item.id);
  }

  function onTabKey(event, index) {
    const last = nodes.length - 1;
    let next = null;
    if (event.key === 'ArrowRight') next = index === last ? 0 : index + 1;
    else if (event.key === 'ArrowLeft') next = index === 0 ? last : index - 1;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = last;
    if (next === null) return;
    event.preventDefault();
    nodes[next].tab.focus();
    activate(next);
  }

  host.append(tablist, panelsHost);
  activate(definitions.active || 0);
  return {
    activate(idOrIndex) {
      const index = typeof idOrIndex === 'number'
        ? idOrIndex
        : nodes.findIndex((entry) => entry.item.id === idOrIndex);
      if (index >= 0) activate(index);
    },
    current: () => nodes[definitions.active] ? nodes[definitions.active].item.id : null,
  };
}

/**
 * Show/hide tabs whose panels are built once and kept in the document, so switching away
 * from a half-filled form does not discard what the operator typed.
 */
export function staticTabs(host, { idPrefix, ariaLabel, items, active = 0, onChange = null }) {
  clear(host);
  let index = active;
  const tablist = h('div.tablist', { role: 'tablist', aria: { label: ariaLabel || 'View' } });
  const wrappers = items.map((item) => h('div', {
    role: 'tabpanel',
    class: 'tabpanel',
    id: `${idPrefix}-panel-${item.id}`,
    tabindex: '0',
    aria: { labelledby: `${idPrefix}-tab-${item.id}` },
  }, [item.node]));

  const tabNodes = items.map((item, i) => h('button', {
    type: 'button',
    class: 'tab',
    role: 'tab',
    id: `${idPrefix}-tab-${item.id}`,
    text: item.label,
    'aria-controls': `${idPrefix}-panel-${item.id}`,
    on: {
      click: () => select(i),
      keydown: (event) => onKey(event, i),
    },
  }));

  function select(next, { focus = false } = {}) {
    if (next < 0 || next >= items.length) return;
    index = next;
    tabNodes.forEach((tab, i) => {
      tab.setAttribute('aria-selected', i === index ? 'true' : 'false');
      tab.tabIndex = i === index ? 0 : -1;
      tab.classList.toggle('is-selected', i === index);
    });
    wrappers.forEach((wrapper, i) => {
      wrapper.hidden = i !== index;
      wrapper.classList.toggle('is-hidden', i !== index);
    });
    if (focus) tabNodes[index].focus();
    if (onChange) onChange(items[index].id);
  }

  function onKey(event, i) {
    const last = items.length - 1;
    let next = null;
    if (event.key === 'ArrowRight') next = i === last ? 0 : i + 1;
    else if (event.key === 'ArrowLeft') next = i === 0 ? last : i - 1;
    else if (event.key === 'Home') next = 0;
    else if (event.key === 'End') next = last;
    if (next === null) return;
    event.preventDefault();
    select(next, { focus: true });
  }

  host.append(tablist, h('div.tab-panels', wrappers));
  select(index);

  return {
    node: host,
    current: () => items[index].id,
    activate(idOrIndex) {
      const next = typeof idOrIndex === 'number'
        ? idOrIndex
        : items.findIndex((item) => item.id === idOrIndex);
      if (next >= 0) select(next);
    },
    panelFor: (id) => wrappers[items.findIndex((item) => item.id === id)],
  };
}

/**
 * A rail section built from panels that each need their own permission. Panels the role
 * cannot read are not rendered at all, so the operator never sees a form the server would
 * refuse; a section with nothing left to show says so instead of opening on an empty tab.
 *
 * The page title and its description are printed once, by the shell's page head, so a section
 * adds only its tabs or its refusal.
 */
export function panelSection(host, { title, idPrefix, ariaLabel, items, allowed, empty, autoRefreshMs = 0 }) {
  const visible = items.filter((item) => allowed(item.permission));
  if (!visible.length) {
    host.append(panel(title, [emptyState(empty)]));
    return { autoRefreshMs: 0, refresh: null, teardown: null };
  }

  host.append(h('div.tabs-host'));
  let current = visible[0].id;
  const control = tabs(host.querySelector('.tabs-host'), {
    idPrefix,
    ariaLabel,
    active: 0,
    items: visible.map((item) => ({
      id: item.id,
      label: item.label,
      render: (node) => {
        current = item.id;
        item.render(node);
      },
    })),
  });

  return { autoRefreshMs, refresh: () => control.activate(current), teardown: null };
}

let dialogSequence = 0;

/**
 * Modal built on <dialog>, so Escape, focus trapping and inertness are the browser's
 * responsibility. Returns a controller the caller uses to close it.
 */
export function openDialog({ title, description, body, actions = [], onClose = null, width = null }) {
  const titleId = `wt-dialog-title-${(dialogSequence += 1)}`;
  const descId = `${titleId}-desc`;
  const dialog = h('dialog.wt-dialog', {
    class: width ? `w-${width}` : '',
    aria: { labelledby: titleId, describedby: description ? descId : null, modal: 'true' },
  });

  const footer = h('footer.dialog-actions');
  actions.forEach((action) => {
    const node = h('button', {
      type: 'button',
      class: `btn ${action.variant || ''}`.trim(),
      text: action.label,
      on: {
        click: () => {
          if (action.onClick) action.onClick(controller);
          else controller.close(action.value);
        },
      },
    });
    if (action.desired) node.setAttribute('data-autofocus', 'true');
    footer.append(node);
  });

  dialog.append(
    h('header.dialog-head', [h('h2', { id: titleId, text: title })]),
    description ? h('p', { id: descId, class: 'dialog-desc', text: description }) : null,
    h('div.dialog-body', Array.isArray(body) ? body : [body]),
    actions.length ? footer : null
  );

  document.body.append(dialog);
  dialog.showModal();
  const autofocus = dialog.querySelector('[data-autofocus]') || dialog.querySelector('input, select, textarea, button');
  if (autofocus) autofocus.focus();

  const controller = {
    node: dialog,
    close(value) {
      // The 'close' listener below does the removal and callback exactly once.
      dialog.close(value);
    },
  };
  dialog.addEventListener('close', () => {
    dialog.remove();
    if (onClose) onClose(dialog.returnValue);
  });
  return controller;
}

/** A modal confirmation for anything destructive. */
export function confirmDialog({ title, message, confirmLabel = 'Confirm', tone = 'bad', onConfirm }) {
  return openDialog({
    title,
    description: message,
    width: 'small',
    actions: [
      { label: 'Cancel', variant: 'ghost' },
      {
        label: confirmLabel,
        variant: tone === 'bad' ? 'danger' : 'primary',
        desired: true,
        onClick: (controller) => {
          controller.close();
          onConfirm(controller);
        },
      },
    ],
  });
}
