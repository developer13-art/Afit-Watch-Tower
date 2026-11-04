/**
 * Live monitoring (proposal section 9, 13.3).
 *
 * Browsers cannot play RTSP, so the console displays the server's multipart-JPEG relay for a
 * live session it has been issued. Three honesty rules govern this module:
 *
 *   * a tile shows "Not started" until an operator presses Start - it never looks like a
 *     paused video;
 *   * the relay <img> is only attached once a session exists, and the badge reflects the
 *     polled view_state, so "live" is only ever claimed while frames are arriving;
 *   * a camera with no stream is rendered as an offline panel, not a black rectangle.
 *
 * Every session is registered in `openSessions` so it is released on Stop, on leaving the
 * section and on page unload; otherwise the managed stream would keep a viewer attached.
 */

import { ApiError } from './api.js';
import {
  CAMERA_STATUS,
  VIEW_STATE,
  emptyState,
  h,
  panel,
  render,
  selectInput,
  timeEl,
} from './ui.js';

const POLL_MS = 3000;

/** token -> tile id, kept module-wide so unload can release sessions from anywhere. */
const openSessions = new Map();

export function releaseAllSessions() {
  // fetch(keepalive) rather than sendBeacon: a beacon cannot carry the CSRF header, and the
  // backend answers a header-less DELETE with 403 csrf_check_failed.
  openSessions.forEach((tileId, token) => {
    void tileId;
    releaseToken(token);
  });
  openSessions.clear();
}

let apiRef = null;
function releaseToken(token) {
  if (apiRef) apiRef.live.release(token);
}

export function mount(host, ctx) {
  apiRef = ctx.api;
  const gridHost = h('div.live-grid');
  const chipsHost = h('div.chip-row');
  const toolbar = h('div.toolbar');
  const notice = h('div.list-note');
  const legend = h('div.legend');
  let tiles = [];
  let sequence = 0;
  let focusId = null;
  let density = 3;
  let cameraRows = [];
  /** Until the registry has been read, the console does not know whether the role can see any
   * camera at all - so the chip row stays empty rather than asserting that none is registered. */
  let camerasLoaded = false;
  /** '' = every camera, 'none' = ungrouped, otherwise the id of one camera group. */
  let groupFilter = '';

  host.append(chipsHost, toolbar, notice, legend, gridHost);

  if (!ctx.can('camera.view_live')) {
    render(notice, h('p.note.tone-fg-bad', {
      text: 'Live viewing needs the "camera.view_live" permission, which your role does not grant. Camera records, health and incidents remain available to you.',
    }));
    render(gridHost, panel('Live view', [emptyState('Live video is not available for this role.')]));
    return { autoRefreshMs: 0, refresh: null, teardown: null };
  }

  /* ------------------------------------------------------------- group filtering */

  /**
   * The mockup asked for "Indoor / Outdoor" chips. Cameras store no such attribute, so the chips
   * bind to the grouping that does exist in the registry: camera groups. They are also an access
   * boundary, so filtering by one here is the same partition the server enforces on role grants.
   */
  function inGroup(groupId) {
    if (groupFilter === '') return true;
    if (groupFilter === 'none') return groupId === null || groupId === undefined;
    return String(groupId) === groupFilter;
  }

  function visibleCameras() {
    return cameraRows.filter((camera) => inGroup(camera.camera_group_id));
  }

  function groupName(groupId) {
    if (groupId === null || groupId === undefined) return 'ungrouped';
    const found = (ctx.groups() || []).find((group) => String(group.id) === String(groupId));
    return found ? found.name : `group ${groupId}`;
  }

  function paintChips() {
    if (!camerasLoaded) return;
    const grouped = (ctx.groups() || []).filter((group) => cameraRows.some((camera) => String(camera.camera_group_id) === String(group.id)));
    const ungroupedCount = cameraRows.filter((camera) => camera.camera_group_id === null || camera.camera_group_id === undefined).length;

    if (!grouped.length) {
      render(chipsHost, h('p.note', {
        text: ungroupedCount
          ? `Every camera you can see is ungrouped, so there is nothing to filter. Groups are created under Hardware; a group is both a folder and an access boundary.`
          : 'No camera is registered that your role can see, so there is nothing to monitor.',
      }));
      return;
    }

    const chips = [chipButton('', 'All cameras', cameraRows.length)];
    grouped.forEach((group) => {
      chips.push(chipButton(String(group.id), group.name, cameraRows.filter((camera) => String(camera.camera_group_id) === String(group.id)).length));
    });
    if (ungroupedCount) chips.push(chipButton('none', 'Ungrouped', ungroupedCount));
    render(chipsHost, [h('span.chip-row-label', { text: 'Group' }), ...chips]);
  }

  function chipButton(key, label, count) {
    const active = groupFilter === key;
    const button = h('button', {
      type: 'button',
      class: `chip-toggle tone-info${active ? ' is-active' : ''}`,
      'aria-pressed': active ? 'true' : 'false',
    }, [h('span', { text: label }), h('span.chip-count', { text: String(count) })]);
    button.addEventListener('click', () => {
      groupFilter = key;
      paintChips();
      buildToolbar();
      paint();
    });
    return button;
  }

  function buildToolbar() {
    const present = new Set(tiles.map((tile) => tile.cameraId));
    const options = visibleCameras()
      .filter((camera) => !present.has(camera.id))
      .map((camera) => ({
        value: camera.id,
        label: `${camera.code} - ${camera.display_name} (${(CAMERA_STATUS[camera.status] || { label: camera.status }).label})`,
      }));

    const picker = selectInput(
      [{ value: '', label: options.length ? 'Choose a camera to add...' : 'No camera left in this group' }, ...options],
      { id: 'wt-live-pick', 'aria-label': 'Camera to add to the monitoring grid' }
    );
    const addBtn = h('button', { type: 'button', class: 'btn primary', text: 'Add tile' });
    addBtn.addEventListener('click', () => {
      if (!picker.value) {
        render(notice, h('p.note.tone-fg-warn', { text: options.length ? 'Select a camera first.' : 'Every camera in this group is already on screen, or none is visible to your role.' }));
        return;
      }
      addTile(picker.value);
    });

    const densitySelect = selectInput([
      { value: '2', label: '2 columns' },
      { value: '3', label: '3 columns' },
      { value: '4', label: '4 columns' },
    ], { id: 'wt-live-density', 'aria-label': 'Grid density' });
    densitySelect.value = String(density);
    densitySelect.addEventListener('change', (event) => {
      density = Number(event.target.value);
      applyLayout();
    });

    const stopAll = h('button', { type: 'button', class: 'btn', text: 'Stop all video' });
    stopAll.addEventListener('click', () => {
      tiles.forEach((tile) => stopTile(tile));
      render(notice, h('p.note.tone-fg-info', { text: 'All live sessions on this screen were released; managed streams dropped a viewer.' }));
    });

    render(toolbar, [
      h('div.toolbar-group', [h('label.inline', { for: 'wt-live-pick', text: 'Camera' }), picker, addBtn]),
      h('div.toolbar-group', [h('label.inline', { for: 'wt-live-density', text: 'Layout' }), densitySelect]),
      h('div.toolbar-spacer'),
      stopAll,
    ]);
  }

  async function refreshCameraList() {
    let cameras = [];
    try {
      cameras = await ctx.api.cameras.list();
    } catch (error) {
      render(notice, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
      return [];
    }
    cameraRows = cameras;
    camerasLoaded = true;
    ctx.setCameras(cameras);
    // Keep tile metadata truthful even when the operator stays on this screen.
    tiles.forEach((tile) => {
      const fresh = cameras.find((camera) => camera.id === tile.cameraId);
      if (fresh) tile.camera = fresh;
    });
    buildToolbar();
    paintChips();
    paint();
    return cameras;
  }

  function addTile(cameraId) {
    const camera = (ctx.cameras() || []).find((row) => row.id === cameraId) || null;
    tiles.push({
      id: `tile-${(sequence += 1)}`,
      cameraId,
      camera,
      token: null,
      viewState: 'not_started',
      detail: null,
      session: null,
      secondsSinceFrame: null,
      img: null,
      frameSeenAt: null,
      openError: null,
      openedAt: null,
    });
    buildToolbar();
    paint();
    const tile = tiles[tiles.length - 1];
    startTile(tile);
  }

  function removeTile(tile) {
    stopTile(tile);
    tiles = tiles.filter((entry) => entry !== tile);
    if (focusId === tile.id) focusId = null;
    buildToolbar();
    paint();
  }

  function stopTile(tile) {
    if (tile.token) {
      openSessions.delete(tile.token);
      releaseToken(tile.token);
      tile.token = null;
    }
    if (tile.img) {
      // Detaching the src aborts the multipart connection, which releases the viewer count
      // on the server side too.
      tile.img.removeAttribute('src');
      tile.img = null;
    }
    tile.session = null;
    tile.secondsSinceFrame = null;
    tile.openError = null;
    tile.viewState = 'not_started';
    tile.detail = null;
  }

  async function startTile(tile) {
    if (tile.token) return;
    tile.viewState = 'loading';
    tile.openError = null;
    paint();
    try {
      const result = await ctx.api.live.open(tile.cameraId);
      tile.token = result.live_session;
      tile.openedAt = new Date().toISOString();
      openSessions.set(result.live_session, tile.id);
      attachRelay(tile);
    } catch (error) {
      tile.viewState = 'offline';
      tile.openError = error instanceof ApiError ? error : new ApiError(0, 'unknown', 'Could not open a live session.');
      // A refused session is a real answer, not a spinner: name the reason.
      tile.detail = tile.openError.display;
    }
    paint();
  }

  function attachRelay(tile) {
    const img = h('img.relay', {
      alt: `Video relay for ${tile.camera ? `${tile.camera.display_name} (${tile.camera.code})` : 'this camera'}`,
      decoding: 'async',
    });
    img.addEventListener('load', () => {
      tile.frameSeenAt = Date.now();
      if (tile.viewState === 'loading') tile.viewState = 'live';
      paint();
    });
    img.addEventListener('error', () => {
      // A relay error means the server closed the stream or the session was released; say so
      // instead of freezing a stale frame.
      if (tile.token) {
        openSessions.delete(tile.token);
        tile.token = null;
        tile.viewState = 'offline';
        tile.detail = 'The video relay closed. The server released or refused this session.';
      }
      paint();
    });
    img.src = ctx.api.live.mjpegUrl(tile.token);
    tile.img = img;
  }

  async function pollStates() {
    const active = tiles.filter((tile) => tile.token);
    if (!active.length) return;
    await Promise.all(active.map(async (tile) => {
      try {
        const state = await ctx.api.live.state(tile.token);
        tile.viewState = state.view_state;
        tile.detail = state.detail;
        tile.session = state.session;
        tile.secondsSinceFrame = state.seconds_since_frame;
        if (state.view_state === 'offline' && !tile.secondsSinceFrame) tile.openError = null;
      } catch (error) {
        if (error instanceof ApiError && (error.status === 410 || error.status === 404)) {
          // The server released the session; do not keep a dead relay on screen.
          openSessions.delete(tile.token);
          tile.token = null;
          tile.viewState = 'offline';
          tile.detail = 'This live viewing session was released by the server.';
        } else if (error instanceof ApiError && error.status === 401) {
          return;
        }
      }
    }));
    paint();
  }

  function applyLayout() {
    gridHost.style.setProperty('--live-columns', String(density));
    gridHost.classList.toggle('has-focus', focusId !== null);
  }

  /**
   * A tile whose camera record cannot be read stays on screen under any filter: hiding it would
   * leave a live session with no Stop button, and the server would keep it as a viewer.
   */
  function visibleTiles() {
    return tiles.filter((tile) => !tile.camera || inGroup(tile.camera.camera_group_id));
  }

  function paint() {
    applyLayout();
    if (!tiles.length) {
      render(gridHost, panel('Monitoring grid', [
        emptyState('No camera is on screen. Choose one above and press Add tile. A tile you have not started is shown as Not started - it is not a paused video.'),
      ]));
      return;
    }
    const shown = visibleTiles();
    if (!shown.length) {
      render(gridHost, panel('Monitoring grid', [
        emptyState(`No tile on this screen belongs to ${groupName(groupFilter)}. Your other tiles are still running underneath - switch group to see and stop them.`),
      ]));
      return;
    }
    render(gridHost, shown.map((tile) => tileNode(tile, ctx, {
      focused: focusId === tile.id,
      onStart: () => startTile(tile),
      onStop: () => { stopTile(tile); paint(); },
      onRemove: () => removeTile(tile),
      onFocus: () => { focusId = focusId === tile.id ? null : tile.id; paint(); },
      onFullscreen: (node) => goFullscreen(node),
    })));
  }

  buildToolbar();
  paintChips();
  refreshCameraList();

  render(legend, h('div.legend-row', Object.entries(VIEW_STATE).map(([key, meta]) => h('span.legend-item', [
    h('span.chip-shape', { text: meta.shape, 'aria-hidden': 'true', class: `tone-fg-${meta.tone}` }),
    h('span', { text: `${key === 'not_started' ? 'Not started' : meta.label}: ${meta.note}` }),
  ]))));

  return {
    // The app shell drives this, so the state poll stops the moment the rail moves away.
    autoRefreshMs: POLL_MS,
    refresh: () => pollStates(),
    teardown: () => {
      tiles.forEach((tile) => stopTile(tile));
      tiles = [];
      focusId = null;
    },
  };
}

/* ------------------------------------------------------------------ one tile */

function tileNode(tile, ctx, handlers) {
  const camera = tile.camera;
  const name = camera ? camera.display_name : 'Camera record unavailable';
  const code = camera ? camera.code : tile.cameraId.slice(0, 8);
  const location = camera ? camera.campus_location : 'unknown location';
  const meta = VIEW_STATE[tile.viewState] || VIEW_STATE.offline;

  const body = h('div.tile-video');
  if (tile.img && (tile.viewState === 'live' || tile.viewState === 'reconnecting')) {
    body.append(tile.img);
    if (tile.viewState === 'reconnecting') {
      body.append(h('div.tile-overlay', [h('span.chip', { class: 'tone-info' }, [
        h('span.chip-shape', { text: meta.shape, 'aria-hidden': 'true' }),
        h('span.chip-label', { text: 'Last frame held while reconnecting' }),
      ])]));
    }
  } else if (tile.img && tile.viewState === 'loading') {
    body.append(tile.img);
    body.append(h('div.tile-overlay', [h('p', { text: 'Connecting - no frame confirmed yet.' })]));
  } else {
    body.append(h('div.tile-none', { class: `tone-border-${meta.tone}` }, [
      h('span.tile-none-shape', { text: meta.shape, 'aria-hidden': 'true' }),
      h('p.tile-none-title', { text: honestTitle(tile, meta) }),
      h('p.tile-none-detail', { text: honestDetail(tile) }),
    ]));
  }

  const stats = tile.session || {};
  const metrics = h('div.tile-metrics', [
    metric('State', meta.label, `tone-fg-${meta.tone}`),
    metric('Measured fps', stats.measured_fps ? Number(stats.measured_fps).toFixed(1) : 'no stream'),
    metric('Viewers', stats.viewers === undefined ? (camera ? String(camera.viewers) : '0') : String(stats.viewers)),
    metric('Frames in', stats.frames_received === undefined ? '-' : String(stats.frames_received)),
    metric('Dropped', stats.frames_dropped === undefined ? '-' : String(stats.frames_dropped)),
    metric('Decode errors', stats.decode_failures === undefined ? '-' : String(stats.decode_failures)),
    metric('Retries', stats.retry_count === undefined ? (camera ? String(camera.retry_count) : '0') : String(stats.retry_count)),
    metric('Since frame', tile.secondsSinceFrame === null || tile.secondsSinceFrame === undefined ? '-' : `${tile.secondsSinceFrame}s`),
    stats.width ? metric('Resolution', `${stats.width} x ${stats.height}`) : null,
  ]);

  const startStop = tile.token
    ? h('button', { type: 'button', class: 'btn small', text: 'Stop' })
    : h('button', { type: 'button', class: 'btn small primary', text: 'Start' });
  startStop.addEventListener('click', () => (tile.token ? handlers.onStop() : handlers.onStart()));
  if (!ctx.can('camera.view_live')) {
    startStop.disabled = true;
    startStop.title = 'Not available: your role does not grant the "camera.view_live" permission.';
  }

  const focus = h('button', { type: 'button', class: 'btn small', text: handlers.focused ? 'Shrink' : 'Enlarge' });
  focus.addEventListener('click', handlers.onFocus);

  const full = h('button', { type: 'button', class: 'btn small', text: 'Full screen' });
  full.addEventListener('click', () => handlers.onFullscreen(full.closest('.live-tile')));
  if (!tile.token) {
    full.disabled = true;
    full.title = 'Start the video for this tile before going full screen.';
  }

  const still = h('a', { class: 'btn small', href: tile.token ? ctx.api.live.snapshotUrl(tile.token) : '#', text: 'Capture still' });
  if (!tile.token) {
    still.classList.add('is-disabled');
    still.setAttribute('aria-disabled', 'true');
    still.addEventListener('click', (event) => event.preventDefault());
    still.title = 'No live session, so there is no frame to capture.';
  } else {
    still.setAttribute('target', '_blank');
    still.setAttribute('rel', 'noreferrer');
    still.title = 'Opens the newest confirmed frame as a JPEG in a new tab.';
  }

  const remove = h('button', { type: 'button', class: 'btn small danger', text: 'Remove tile' });
  remove.addEventListener('click', handlers.onRemove);

  return h('article', {
    // `is-focused` is what the stylesheet uses to span the enlarged tile across the grid.
    class: `live-tile tile-tone-${meta.tone}${tile.token ? ' has-session' : ''}${handlers.focused ? ' is-focused' : ''}`,
    'aria-label': `Live tile for ${code}`,
  }, [
    h('header.tile-head', [
      h('div.tile-title', [
        h('span.tile-code', { text: code }),
        h('h3', { text: name }),
        h('span.tile-location', { text: location }),
      ]),
      h('span.chip', { class: `tone-${meta.tone}` }, [
        h('span.chip-shape', { text: meta.shape, 'aria-hidden': 'true' }),
        h('span.chip-label', { text: meta.label }),
      ]),
    ]),
    camera ? h('div.tile-subline', [
      h('span.dim', { text: `Registry status: ${(CAMERA_STATUS[camera.status] || { label: camera.status }).label}` }),
      camera.last_successful_frame_at ? timeEl(camera.last_successful_frame_at, 'dim rel-time') : h('span.dim', { text: 'no frame ever recorded' }),
    ]) : null,
    body,
    metrics,
    tile.detail && tile.viewState !== 'live'
      ? h('p.tile-detail', { class: `tone-fg-${meta.tone}`, role: tile.viewState === 'offline' ? 'alert' : 'status', text: tile.detail })
      : null,
    tile.openError && tile.openError.code === 'not_activated'
      ? h('p.tile-detail.tone-fg-warn', { text: 'This camera was registered but never activated. A technical operator must pass a connection test and activate it before any video exists.' })
      : null,
    h('footer.tile-actions', [startStop, focus, full, still, remove]),
  ]);
}

function focusAllowed(tile) {
  return Boolean(tile.token);
}

function honestTitle(tile, meta) {
  if (tile.viewState === 'not_started') return 'Not started';
  if (tile.viewState === 'loading') return 'Starting - no frame confirmed';
  if (tile.viewState === 'offline') return tile.camera && tile.camera.status === 'disabled'
    ? 'Camera disabled'
    : 'No video from this camera';
  if (tile.viewState === 'reconnecting') return 'Frames have stopped';
  return meta.label;
}

function honestDetail(tile) {
  if (tile.detail) return tile.detail;
  if (tile.viewState === 'not_started') return 'The operator has not opened a live session for this tile.';
  if (tile.viewState === 'loading') return 'Waiting for the managed stream to deliver its first frame.';
  if (tile.viewState === 'reconnecting') return 'The relay is being re-established; the last confirmed frame is held rather than faked.';
  return (VIEW_STATE[tile.viewState] || VIEW_STATE.offline).note;
}

function metric(label, value, className = '') {
  return h('span.metric', [
    h('span.metric-label', { text: label }),
    h('span.metric-value', { class: className, text: value }),
  ]);
}

function goFullscreen(node) {
  if (!node || !node.requestFullscreen) return;
  // Full screen is a local browser action; it never changes what the server is streaming.
  Promise.resolve(node.requestFullscreen()).catch(() => {});
}

function describe(error) {
  if (error instanceof ApiError) return error.display;
  return 'The request could not be completed.';
}
