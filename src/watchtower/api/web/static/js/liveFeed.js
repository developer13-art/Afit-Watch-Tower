/**
 * A single reusable live view.
 *
 * The dashboard uses it for its "Live Camera Feed" panel and any later screen that needs one
 * named camera on screen. It goes through the same session endpoints as the monitoring grid, so
 * the server still arbitrates capacity and the shell's navigation cleanup still releases it:
 * `releaseAllSessions()` in live.js forgets the token, and the DELETE in the teardown here is
 * what tells the server to drop this viewer.
 *
 * A view nobody asked for is not opened: the caller passes a camera id, so an operator's click
 * is what consumes a managed stream slot.
 */

import { ApiError } from './api.js';
import { VIEW_STATE, h } from './ui.js';

const LOCAL_TIME = new Intl.DateTimeFormat(undefined, { hour12: false });

export function createLiveFeed(ctx, { cameraId, onState }) {
  const state = {
    cameraId,
    token: null,
    viewState: 'loading',
    detail: null,
    session: null,
    secondsSinceFrame: null,
    img: null,
    frameAt: null,
    timer: null,
    released: false,
  };

  const open = async () => {
    closeRelay();
    state.viewState = 'loading';
    state.detail = null;
    paint();
    try {
      const result = await ctx.api.live.open(state.cameraId);
      if (state.released) {
        // The screen moved away while this request was in flight; give the slot straight back.
        ctx.api.live.release(result.live_session).catch(() => {});
        return;
      }
      state.token = result.live_session;
      attachRelay();
    } catch (error) {
      // A refused session is an answer, not a spinner: name the reason the server gave.
      state.viewState = 'offline';
      state.detail = error instanceof ApiError
        ? error.display
        : 'The server would not open a session for this camera.';
    }
    paint();
  };

  const attachRelay = () => {
    const img = h('img.relay', {
      alt: `Video relay for camera ${state.cameraId}`,
      decoding: 'async',
    });
    img.addEventListener('load', () => {
      state.frameAt = new Date();
      if (state.viewState === 'loading') state.viewState = 'live';
      paint();
    });
    img.addEventListener('error', () => {
      // A relay error means the stream was closed server-side; do not freeze a stale frame.
      if (state.token) {
        state.token = null;
        state.viewState = 'offline';
        state.detail = 'The video relay closed. The server released or refused this session.';
        paint();
      }
    });
    img.src = ctx.api.live.mjpegUrl(state.token);
    state.img = img;
  };

  const poll = async () => {
    if (!state.token) return;
    try {
      const result = await ctx.api.live.state(state.token);
      state.viewState = result.view_state;
      state.detail = result.detail;
      state.session = result.session;
      state.secondsSinceFrame = result.seconds_since_frame;
      paint();
    } catch (error) {
      if (error instanceof ApiError && (error.status === 410 || error.status === 404)) {
        state.token = null;
        state.viewState = 'offline';
        state.detail = 'This live viewing session was released by the server.';
        paint();
      }
    }
  };

  const closeRelay = () => {
    if (state.img) {
      // Detaching src aborts the multipart connection, which drops the viewer count too.
      state.img.removeAttribute('src');
      state.img = null;
    }
  };

  const teardown = () => {
    state.released = true;
    if (state.timer) window.clearInterval(state.timer);
    state.timer = null;
    const token = state.token;
    closeRelay();
    state.token = null;
    if (token) ctx.api.live.release(token).catch(() => {});
  };

  const paint = () => {
    if (onState) onState(state);
  };

  // The state poll is started here rather than by the shell so the feed keeps its own cadence
  // independently of whichever section is showing it.
  state.timer = window.setInterval(() => {
    if (!document.hidden) poll();
  }, 3000);

  return { open, teardown, state };
}

/**
 * The video area, with the state read-out under it.
 *
 * It takes the controller rather than its state object: the two are always used together and
 * passing the wrong one produced a placeholder that read every field as "not recorded".
 */
export function feedArea(feed, camera, onRetry) {
  const state = feed.state;
  const label = camera ? `${camera.code} - ${camera.display_name}` : 'camera';
  const meta = VIEW_STATE[state.viewState] || VIEW_STATE.offline;
  const body = h('div.tile-video');

  if (state.img && ['loading', 'live', 'reconnecting'].includes(state.viewState)) {
    body.append(state.img, feedOverlay(state, label));
    if (state.viewState === 'reconnecting') {
      body.append(h('div.tile-overlay', [h('p', { text: state.detail || 'Frames have stopped while the server retries.' })]));
    }
    if (state.viewState === 'loading') {
      body.append(h('div.tile-overlay', [h('p', { text: 'Connecting - no frame confirmed yet.' })]));
    }
  } else {
    const retry = h('button.btn.small', { type: 'button', text: 'Try again', on: { click: onRetry } });
    body.append(h('div.tile-none', { class: `tone-border-${meta.tone}` }, [
      h('span.tile-none-shape', { text: meta.shape, 'aria-hidden': 'true' }),
      h('p.tile-none-title', { text: meta.label }),
      h('p.tile-none-detail', { text: state.detail || meta.note }),
      retry,
    ]));
  }

  return h('div.dash-feed-body', [body, feedMetrics(state, camera)]);
}

/** The header strip drawn over the video: state, camera and the local time of the last frame. */
function feedOverlay(state, label) {
  const meta = VIEW_STATE[state.viewState] || VIEW_STATE.offline;
  const live = state.viewState === 'live';
  return h('div.feed-overlay', [
    h('span.feed-badge', { class: live ? 'is-live' : 'is-idle' }, [
      h('span.feed-dot', { 'aria-hidden': 'true' }),
      h('span', { text: live ? 'LIVE' : meta.label.toUpperCase() }),
    ]),
    h('span.feed-caption', [
      h('strong', { text: label }),
      h('span.feed-time', { text: live && state.frameAt ? LOCAL_TIME.format(state.frameAt) : 'no frame confirmed' }),
    ]),
  ]);
}

function feedMetrics(state, camera) {
  const session = state.session || {};
  const meta = VIEW_STATE[state.viewState] || VIEW_STATE.offline;
  // A missing session figure means the state read has not answered yet, which is not the same
  // claim as the server recording nothing - so the two cases get different words.
  const notRead = 'not read yet';
  const rows = [
    ['State', meta.label, '-'],
    ['Measured fps', session.measured_fps ? Number(session.measured_fps).toFixed(1) : 'no stream', notRead],
    ['Viewers', session.viewers, notRead],
    ['Frames in', session.frames_received, notRead],
    ['Decode errors', session.decode_failures, notRead],
    ['Retries', session.retry_count, notRead],
    ['Since frame', state.secondsSinceFrame === null || state.secondsSinceFrame === undefined ? null : `${state.secondsSinceFrame}s`, notRead],
    ['Location', camera ? camera.campus_location : null, 'not recorded'],
  ];
  return h('div.feed-metrics', rows.map(([label, value, fallback]) => h('div.metric', [
    h('span.metric-label', { text: label }),
    h('span.metric-value', { text: value === null || value === undefined || value === '' ? fallback : String(value) }),
  ])));
}
