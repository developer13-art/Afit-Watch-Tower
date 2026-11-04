/**
 * AFIT WATCH TOWER - application shell: session bootstrap, permission context, the left
 * rail router, the notification inbox and the global live-session cleanup.
 */

import { api, ApiError, takeSessionNotice } from './api.js';
import { announce, clear, gate as gatePermission, h, openDialog, render, timeEl } from './ui.js';
import { prefs } from './prefs.js';
import { mount as mountOverview } from './overview.js';
import { mount as mountCameras } from './cameras.js';
import { mount as mountLive, releaseAllSessions } from './live.js';
import { mount as mountIncidents } from './incidents.js';
import { mount as mountIntelligence } from './intelligence.js';
import { mount as mountPersonnel } from './personnel.js';
import { mount as mountReports } from './reports.js';
import { mount as mountHardware } from './hardware.js';
import { mount as mountSettings } from './settings.js';

const REFRESH_MS = { overview: prefs.refreshMs, cameras: prefs.refreshMs, notifications: 30000 };

const SECTIONS = [
  {
    id: 'dashboard',
    label: 'Dashboard',
    icon: '⌂',
    description: 'Live posture for the cameras your role can see. Figures come from the server on each refresh; nothing here is estimated.',
    anyOf: ['camera.list'],
    mount: mountOverview,
  },
  {
    id: 'live',
    label: 'Live Monitoring',
    icon: '▶',
    description: 'Browser video comes from streams the server is already managing. Starting a tile attaches a viewer to that shared source; it does not open a second RTSP connection.',
    anyOf: ['camera.view_live'],
    mount: mountLive,
  },
  {
    id: 'cameras',
    label: 'Cameras',
    icon: '◉',
    description: 'Registry, connection verification, activation and health history for every camera your role can see.',
    anyOf: ['camera.list'],
    mount: mountCameras,
  },
  {
    id: 'incidents',
    label: 'Incidents',
    icon: '⚑',
    description: 'The incident records this post holds. Candidate detections are reviewed under AI Intelligence; escalating one is what creates a record like these.',
    anyOf: ['event.view', 'incident.view'],
    mount: mountIncidents,
  },
  {
    id: 'intelligence',
    label: 'AI Intelligence',
    icon: '✦',
    description: 'Detections raised by the analysis layer, each awaiting a human decision, and the policies that set their confidence floor and analysis rate.',
    anyOf: ['event.view', 'camera.list'],
    mount: mountIntelligence,
  },
  {
    id: 'personnel',
    label: 'Personnel',
    icon: '☰',
    description: 'Accounts, role grants and the permission catalogue. A grant is either institution-wide or limited to one camera group; institution-wide is the wider authority.',
    anyOf: ['admin.users'],
    mount: mountPersonnel,
  },
  {
    id: 'reports',
    label: 'Reports',
    icon: '▤',
    description: 'Counts taken directly from the records for a chosen window, plus the audit entries that explain how they got there.',
    anyOf: ['report.operational', 'audit.view'],
    mount: mountReports,
  },
  {
    id: 'hardware',
    label: 'Hardware',
    icon: '▦',
    description: 'Server capacity, camera grouping, alerting channels and evidence retention - the parts of the deployment that are configured rather than watched.',
    anyOf: ['audit.view', 'camera.list'],
    mount: mountHardware,
  },
  {
    id: 'settings',
    label: 'Settings',
    icon: '⚙',
    description: 'This console only: how often the tab re-reads, and whether it announces a new alert here. Nothing on this screen changes what the server records or what another operator sees.',
    anyOf: [],
    mount: mountSettings,
  },
];

const data = {
  cameras: [],
  groups: [],
  policies: [],
  users: null,
};

/**
 * A section with an empty `anyOf` is open to every signed-in account - Settings describes this
 * browser, not a server record. The rail and the router must use this one rule, or a section
 * renders as reachable in the rail and as locked when clicked.
 */
function isAllowed(section) {
  return section.anyOf.length === 0 || section.anyOf.some((permission) => state.permissions.has(permission));
}

/**
 * Shared reference lists. They back the camera, group, policy and assignee pickers, so a
 * panel never fetches the same catalogue twice. A list the role cannot read stays empty and
 * the panels that need it explain the missing permission instead of failing.
 */
const LOOKUPS = {
  cameras: { permission: 'camera.list', load: () => api.cameras.list(), assign: (value) => { data.cameras = value; } },
  groups: { permission: 'camera.list', load: () => api.cameras.groups(), assign: (value) => { data.groups = value; } },
  policies: { permission: 'camera.list', load: () => api.cameras.policies(), assign: (value) => { data.policies = value; } },
  users: { permission: 'admin.users', load: () => api.admin.users(), assign: (value) => { data.users = value; } },
};

async function loadLookup(key) {
  const lookup = LOOKUPS[key];
  if (!lookup || !state.permissions.has(lookup.permission)) return;
  try {
    lookup.assign(await lookup.load());
  } catch (error) {
    if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return;
  }
}

async function reloadLookups() {
  await Promise.all(Object.keys(LOOKUPS).map((key) => loadLookup(key)));
}

function invalidate(key) {
  if (key && LOOKUPS[key]) loadLookup(key);
  else reloadLookups();
}

const state = {
  identity: null,
  permissions: new Set(),
  section: null,
  controller: null,
  railItems: new Map(),
  timers: { section: null, notifications: null, status: null, clock: null },
};

const context = {
  api,
  state,
  identity: null,
  permissions: state.permissions,
  can: (permission) => state.permissions.has(permission),
  gate: (node, permission) => gatePermission(node, permission, state.permissions),
  toast: (message, tone) => announce(message, tone || 'info'),
  invalidate,
  reloadLookups,
  cameras: () => data.cameras,
  groups: () => data.groups,
  policies: () => data.policies,
  /** null when the role cannot read the directory, which the assignee picker handles. */
  assignees: () => data.users,
  setCameras: (list) => { data.cameras = list || []; },
  timers: REFRESH_MS,
  navigate: (sectionId) => { window.location.hash = `#/${sectionId}`; },
  signOut: signOutNow,
  announceAlert,
  setRefreshInterval: (ms) => {
    REFRESH_MS.overview = ms;
    REFRESH_MS.cameras = ms;
    // Re-routing re-arms the current section on the new cadence instead of waiting for the
    // next tick of the old interval.
    route();
  },
};

/* ------------------------------------------------------------------ boot */

function splash(status) {
  return h('div.splash', [
    h('img.splash-emblem', { src: '/static/img/afit-emblem.png', alt: 'AFIT WATCH TOWER emblem' }),
    h('h1.splash-title', { text: 'AFIT WATCH TOWER' }),
    h('p.splash-tagline', { text: 'Intelligent Security. Safer Tomorrow.' }),
    h('div.splash-bar', { role: 'progressbar', 'aria-label': 'Console start-up' }, [h('span.splash-bar-fill')]),
    h('p.splash-status', { text: status }),
  ]);
}

async function boot() {
  const mount = document.getElementById('app');
  render(mount, splash('Initializing security system...'));
  const statusNode = mount.querySelector('.splash-status');
  if (statusNode) statusNode.textContent = 'Checking your session...';

  let identity;
  try {
    identity = await api.auth.me();
  } catch (error) {
    // A 401 already redirected to /login; anything else is a real failure worth naming.
    if (error instanceof ApiError && error.status === 401) return;
    render(mount, fatal(error));
    return;
  }

  state.identity = identity;
  context.identity = identity;
  identity.permissions.forEach((permission) => state.permissions.add(permission));

  render(mount, buildShell());
  bindGlobalCleanup();
  startStatusPill();
  await reloadLookups();
  startNotificationPoll();
  window.addEventListener('hashchange', route);
  route();
}

function fatal(error) {
  return h('div.boot-error', [
    h('h2', { text: 'Console could not start' }),
    h('p', { text: error instanceof ApiError ? error.display : 'Unexpected error.' }),
    h('a.btn.primary', { href: '/login', text: 'Return to sign in' }),
  ]);
}

/* ------------------------------------------------------------------ shell */

function buildShell() {
  const railList = h('nav.rail-list', { 'aria-label': 'Console sections' });
  SECTIONS.forEach((section) => {
    const allowed = isAllowed(section);
    const link = h('a.rail-item', {
      href: `#/${section.id}`,
      data: { section: section.id },
      title: allowed ? section.description : `Hidden: none of ${section.anyOf.join(', ')} is granted to your role.`,
      class: allowed ? '' : 'is-locked',
      'aria-disabled': allowed ? 'false' : 'true',
    }, [
      h('span.rail-icon', { text: section.icon, 'aria-hidden': 'true' }),
      h('span.rail-label', { text: section.label }),
      allowed ? null : h('span.rail-lock', { text: 'no access' }),
    ]);
    if (!allowed) link.addEventListener('click', (event) => event.preventDefault());
    state.railItems.set(section.id, link);
    railList.append(link);
  });

  const bell = h('button', {
    type: 'button',
    class: 'btn bell',
    id: 'wt-bell',
    'aria-label': 'Notification inbox',
  }, [h('span.bell-shape', { text: '☐', 'aria-hidden': 'true' }), h('span.bell-count', { id: 'wt-bell-count', text: '0' })]);
  bell.addEventListener('click', () => openInbox());

  const identity = state.identity;
  const identityChip = h('div.avatar-chip', [
    h('span.avatar', { text: initials(identity.display_name), 'aria-hidden': 'true' }),
    h('span.avatar-text', [
      h('strong', { text: identity.display_name }),
      h('small', { text: identity.is_administrative ? 'Administrative' : 'Operational' }),
    ]),
  ]);
  identityChip.title = `@${identity.username} - ${state.permissions.size} permission${state.permissions.size === 1 ? '' : 's'} granted`;

  const signOut = h('button', { type: 'button', class: 'btn ghost', text: 'Sign out' });
  signOut.addEventListener('click', signOutNow);

  const main = h('main#main-region', { tabindex: '-1' });

  return h('div.shell', [
    h('aside.rail', [
      railList,
      h('div.rail-footer', [
        h('p.motto', { text: 'From Passive Surveillance to Intelligent Security Awareness' }),
      ]),
    ]),
    h('div.working', [
      h('header.topbar', [
        h('div.topbar-brand', [
          h('img.brand-mark', { src: '/static/img/afit-emblem.png', alt: 'AFIT WATCH TOWER emblem' }),
          h('span.brand-text', [
            h('strong', { text: 'AFIT WATCH TOWER' }),
            h('small', { text: 'Security Operations Centre' }),
          ]),
        ]),
        h('div.topbar-right', [
          h('span.sys-pill.tone-muted', { id: 'wt-status' }, [
            h('span.sys-pill-shape', { text: '◌', 'aria-hidden': 'true' }),
            h('span', { id: 'wt-status-text', text: 'Reading camera state...' }),
          ]),
          h('span.clock', { id: 'wt-clock', title: 'Server console local time' }),
          bell,
          identityChip,
          signOut,
        ]),
      ]),
      h('div.page-head', [
        h('h1', { id: 'wt-section-title', text: 'Dashboard' }),
        h('span', { id: 'wt-section-sub', class: 'topbar-sub', text: 'Loading...' }),
      ]),
      h('div#wt-banner.banner', { 'aria-live': 'polite' }),
      main,
      h('footer.statusbar', [
        h('span', { id: 'wt-refresh', text: 'Auto-refresh armed' }),
        h('span.dim', { text: 'Video is relayed from the server; RTSP addresses and camera credentials never reach this browser.' }),
      ]),
    ]),
  ]);
}

function initials(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!parts.length) return '?';
  return parts.slice(0, 2).map((part) => part[0]).join('').toUpperCase();
}

/**
 * The header status pill reports what the server actually says about the camera estate. A
 * role that cannot read the camera summary gets no pill rather than an assurance nobody
 * measured.
 */
function startStatusPill() {
  const pill = document.getElementById('wt-status');
  const text = document.getElementById('wt-status-text');
  const shape = pill ? pill.querySelector('.sys-pill-shape') : null;
  if (!pill || !text || !shape) return;
  if (!state.permissions.has('camera.list')) {
    pill.remove();
    return;
  }

  const paint = (summary) => {
    const unreachable = (summary.offline || 0) + (summary.degraded || 0)
      + (summary.reconnecting || 0) + (summary.authentication_failed || 0);
    let tone = 'ok';
    let label = 'All cameras delivering';
    let glyph = '●';
    if (!summary.total_cameras) {
      tone = 'muted';
      label = 'No cameras registered';
      glyph = '◇';
    } else if (unreachable > 0) {
      tone = 'bad';
      label = `${unreachable} camera${unreachable === 1 ? '' : 's'} not delivering`;
      glyph = '▲';
    } else if (summary.online === 0) {
      tone = 'warn';
      label = 'No camera is online';
      glyph = '○';
    }
    pill.className = `sys-pill tone-${tone}`;
    shape.textContent = glyph;
    text.textContent = label;
    pill.title = `${summary.online || 0} of ${summary.total_cameras || 0} cameras online. Read from the server summary.`;
  };

  const poll = () => {
    api.cameras.overview()
      .then(paint)
      .catch(() => {
        pill.className = 'sys-pill tone-muted';
        shape.textContent = '?';
        text.textContent = 'Camera state unavailable';
      });
  };
  poll();
  state.timers.status = window.setInterval(() => {
    if (!document.hidden) poll();
  }, REFRESH_MS.notifications);
}

/* ------------------------------------------------------------------ routing */

function currentSectionId() {
  const raw = (window.location.hash || '').replace(/^#\//, '').trim();
  const match = SECTIONS.find((section) => section.id === raw);
  if (match && isAllowed(match)) return match.id;
  const fallback = SECTIONS.find(isAllowed);
  return fallback ? fallback.id : null;
}

function route() {
  const id = currentSectionId();
  const host = document.getElementById('main-region');
  if (!host) return;

  if (!id) {
    state.railItems.forEach((node) => node.classList.remove('is-current'));
    render(host, h('div.panel', [
      h('h2', { text: 'No console access' }),
      h('p', { text: 'Your role grants none of the permissions this console needs to display a section. An administrator can review your role grants.' }),
    ]));
    return;
  }

  const section = SECTIONS.find((entry) => entry.id === id);
  if (state.controller && state.controller.teardown) {
    try { state.controller.teardown(); } catch { /* a teardown must not block navigation */ }
  }
  // Leaving any section releases every live session this browser opened, so the managed
  // stream drops its viewer instead of holding one for a screen nobody is looking at.
  releaseAllSessions();

  state.section = id;
  state.railItems.forEach((node, key) => {
    node.classList.toggle('is-current', key === id);
    if (key === id) node.setAttribute('aria-current', 'page');
    else node.removeAttribute('aria-current');
  });

  const title = document.getElementById('wt-section-title');
  const sub = document.getElementById('wt-section-sub');
  if (title) title.textContent = section.label;
  if (sub) sub.textContent = section.description;

  clear(host);
  const container = h('div.section-host');
  host.append(container);

  /**
   * Mount contract: a section returns { autoRefreshMs, refresh, teardown }. `refresh` is
   * called on the interval while the tab is visible, `teardown` when the rail moves away.
   */
  const controller = normalizeController(safeMount(section, container));
  state.controller = controller;

  if (controller.autoRefreshMs > 0) {
    controller.timer = window.setInterval(() => {
      if (document.hidden) return;
      if (controller.refresh) Promise.resolve(controller.refresh()).catch(() => {});
    }, controller.autoRefreshMs);
    const stop = controller.teardown;
    controller.teardown = () => {
      window.clearInterval(controller.timer);
      controller.timer = null;
      if (stop) stop();
    };
  }
  const stamp = document.getElementById('wt-refresh');
  if (stamp) {
    stamp.textContent = controller.autoRefreshMs > 0
      ? `Auto-refresh every ${Math.round(controller.autoRefreshMs / 1000)}s`
      : 'Auto-refresh off for this section';
  }
}

function safeMount(section, container) {
  try {
    return section.mount(container, context);
  } catch (error) {
    render(container, h('div.panel', [
      h('h2', { text: 'This section could not be displayed' }),
      h('p', { text: error instanceof ApiError ? error.display : 'Unexpected error while loading the section.' }),
    ]));
    return null;
  }
}

function normalizeController(result) {
  if (!result || typeof result !== 'object') return { autoRefreshMs: 0 };
  return { ...result, autoRefreshMs: Number(result.autoRefreshMs) || 0 };
}

/* ------------------------------------------------------------------ session */

async function signOutNow() {
  try {
    await api.auth.logout();
  } catch {
    /* the cookie is cleared regardless of the revocation call outcome */
  }
  Object.keys(state.timers).forEach((key) => {
    window.clearInterval(state.timers[key]);
    state.timers[key] = null;
  });
  releaseAllSessions();
  window.location.replace('/login');
}

function bindGlobalCleanup() {
  // `fetch(..., keepalive: true)` rather than sendBeacon: a beacon cannot set the CSRF
  // header, and the backend rejects a header-less DELETE with 403 csrf_check_failed.
  window.addEventListener('pagehide', () => releaseAllSessions());
  window.addEventListener('beforeunload', () => releaseAllSessions());
  startClock();
}

function startClock() {
  const node = document.getElementById('wt-clock');
  if (!node) return;
  const tick = () => {
    node.textContent = new Date().toLocaleTimeString(undefined, { hour12: false });
  };
  tick();
  state.timers.clock = window.setInterval(tick, 1000);
}

/* ------------------------------------------------------------------ alerting in this tab */

let audioContext = null;

/**
 * A short two-tone beep. Browsers only allow audio after a gesture on the page, so the first
 * arming happens on the Settings toggle or the test button; a blocked attempt is silently
 * dropped rather than breaking the notification poll.
 */
function playChime() {
  try {
    const Ctor = window.AudioContext || window.webkitAudioContext;
    if (!Ctor) return;
    audioContext = audioContext || new Ctor();
    if (audioContext.state === 'suspended') audioContext.resume().catch(() => {});
    const start = audioContext.currentTime;
    [880, 1174].forEach((frequency, index) => {
      const oscillator = audioContext.createOscillator();
      const gain = audioContext.createGain();
      oscillator.type = 'triangle';
      oscillator.frequency.value = frequency;
      const from = start + index * 0.18;
      gain.gain.setValueAtTime(0.0001, from);
      gain.gain.exponentialRampToValueAtTime(0.18, from + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, from + 0.16);
      oscillator.connect(gain).connect(audioContext.destination);
      oscillator.start(from);
      oscillator.stop(from + 0.18);
    });
  } catch {
    /* no audio output available - the visible alert still happened */
  }
}

/**
 * Announce one alert inside this browser only: an accessible message, plus the sound and the
 * system notification the operator armed on the Settings screen. A closed tab cannot be
 * reached, which is why the personnel app carries the same alert to a phone.
 */
function announceAlert({ title, body = '', tone = 'warn' }) {
  announce(title, tone);
  if (prefs.sound) playChime();
  if (prefs.desktop && typeof window.Notification === 'function' && Notification.permission === 'granted') {
    try {
      new Notification(title, { body, tag: `watchtower-${Date.now()}`, requireInteraction: false });
    } catch {
      /* Chrome throws when the profile blocks notifications outright */
    }
  }
}

/* ------------------------------------------------------------------ notifications */

let lastNotificationSignature = '';
const seenAlertIds = new Set();
let alertsPrimed = false;

/**
 * Unread alerts already present when the console opened are history, not a new alarm, so the
 * first poll only records them. After that, any unread alert id the console has not announced
 * is a fresh one.
 */
function detectNewAlerts(payload) {
  const unread = (payload.notifications || []).filter((row) => row.state === 'pending' || row.state === 'delivered');
  if (!alertsPrimed) {
    unread.forEach((row) => seenAlertIds.add(row.id));
    alertsPrimed = true;
    return;
  }
  unread
    .filter((row) => !seenAlertIds.has(row.id))
    .slice(0, 3)
    .forEach((row) => {
      seenAlertIds.add(row.id);
      const urgent = ['critical', 'high'].includes(String(row.severity || '').toLowerCase());
      announceAlert({ title: row.title, body: row.body, tone: urgent ? 'bad' : 'warn' });
    });
}

function startNotificationPoll() {
  const poll = async () => {
    if (document.hidden) return;
    let payload;
    try {
      payload = await api.notifications.inbox(true, 100);
    } catch (error) {
      if (error instanceof ApiError && (error.status === 401 || error.status === 403)) return;
      return;
    }
    paintBell(payload);
    paintBanner(payload);
    detectNewAlerts(payload);
  };
  poll();
  state.timers.notifications = window.setInterval(poll, REFRESH_MS.notifications);
}

function paintBell(payload) {
  const node = document.getElementById('wt-bell-count');
  if (!node) return;
  const open = (payload.counts && (payload.counts.pending || 0) + (payload.counts.delivered || 0)) || 0;
  node.textContent = String(open);
  node.classList.toggle('has-items', open > 0);
  const failed = (payload.counts && payload.counts.failed) || 0;
  node.classList.toggle('has-failure', failed > 0);
  node.title = failed > 0
    ? `${open} unread alerts, ${failed} failed deliveries`
    : `${open} unread alerts`;
  document.title = open > 0 ? `(${open}) AFIT WATCH TOWER` : 'AFIT WATCH TOWER';
}

function paintBanner(payload) {
  const banner = document.getElementById('wt-banner');
  if (!banner) return;
  const failed = payload.notifications.filter((row) => row.state === 'failed');
  const notice = takeSessionNotice();
  clear(banner);
  if (notice) {
    banner.append(h('div.banner-item.warn', { role: 'status' }, [
      h('span.banner-shape', { text: '▲', 'aria-hidden': 'true' }),
      h('span', { text: notice }),
      h('button.btn.icon', {
        type: 'button',
        text: 'Dismiss',
        on: { click: () => banner.classList.add('is-muted') },
      }),
    ]));
    return;
  }
  if (failed.length) {
    // Section 15: an undelivered alert is a visible gap, not a silent list entry.
    banner.append(h('div.banner-item.bad', { role: 'alert' }, [
      h('span.banner-shape', { text: '✖', 'aria-hidden': 'true' }),
      h('span', {
        text: `${failed.length} notification${failed.length === 1 ? '' : 's'} could not be delivered`
          + ` (${describeReason(failed[0].failure_reason)}). Dashboard alerts still work; another channel is missing.`,
      }),
    ]));
  }
  if (payload.notifications.length && !lastNotificationSignature) {
    lastNotificationSignature = 'seen';
  }
}

function describeReason(reason) {
  if (!reason) return 'no reason recorded';
  return String(reason).slice(0, 120);
}

async function openInbox() {
  let payload;
  try {
    payload = await api.notifications.inbox(false, 100);
  } catch (error) {
    announce(error instanceof ApiError ? error.display : 'Inbox unavailable.', 'bad');
    return;
  }

  const list = h('div.inbox-list');
  const refresh = () => {
    clear(list);
    if (!payload.notifications.length) {
      list.append(h('p.empty', { text: 'No notifications have been raised for this account.' }));
      return;
    }
    payload.notifications.forEach((row) => list.append(inboxRow(row, () => openInbox())));
  };

  const counts = Object.entries(payload.counts || {})
    .filter(([, value]) => value > 0)
    .map(([key, value]) => `${key}: ${value}`)
    .join('  |  ');

  openDialog({
    title: 'Notification inbox',
    description: counts || 'No recorded notifications.',
    body: [list],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
  });
  refresh();
}

function inboxRow(row, afterChange) {
  const failed = row.state === 'failed';
  const actions = [];
  if (row.state === 'pending' || row.state === 'delivered') {
    actions.push(h('button.btn.small', {
      type: 'button',
      text: 'Mark read',
      on: {
        click: async (event) => {
          event.target.disabled = true;
          try {
            await api.notifications.read(row.id);
            afterChange();
          } catch (error) {
            announce(error.display || 'Could not mark as read.', 'bad');
            event.target.disabled = false;
          }
        },
      },
    }));
  }
  if (row.state !== 'acknowledged' && row.state !== 'suppressed') {
    actions.push(h('button.btn.small', {
      type: 'button',
      text: 'Acknowledge',
      on: {
        click: async (event) => {
          event.target.disabled = true;
          try {
            await api.notifications.acknowledge(row.id);
            afterChange();
          } catch (error) {
            announce(error.display || 'Could not acknowledge.', 'bad');
            event.target.disabled = false;
          }
        },
      },
    }));
  }

  return h('article.inbox-item', { class: failed ? 'is-failed' : '' }, [
    h('div.inbox-head', [
      h('strong', { text: row.title }),
      h('span.inbox-meta', { text: `${row.kind} · ${row.severity}` }),
      timeEl(row.created_at),
      h('span.chip', { class: `tone-${failed ? 'bad' : 'muted'}` }, [
        h('span.chip-shape', { text: failed ? '✖' : '○', 'aria-hidden': 'true' }),
        h('span.chip-label', { text: row.state }),
      ]),
    ]),
    h('p.inbox-body', { text: row.body }),
    failed
      ? h('p.note.tone-fg-bad', {
          text: `Delivery failed: ${describeReason(row.failure_reason)}. This alert was not received on its intended channel.`,
        })
      : null,
    h('div.inbox-actions', actions),
  ]);
}

/* ------------------------------------------------------------------ start */

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot, { once: true });
} else {
  boot();
}
