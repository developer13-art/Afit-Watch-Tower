/**
 * Dashboard (proposal section 13.1): the four numbers an operator reads first, one named camera
 * on screen, and the state of the campus the camera records describe.
 *
 * Every figure is read from the server on each refresh - nothing here is estimated or carried
 * over from a previous shift. The live panel opens a real viewing session through the same
 * endpoints the monitoring grid uses, so the server still arbitrates stream capacity, and the
 * session is released when the rail moves away.
 */

import { ApiError } from './api.js';
import { createLiveFeed, feedArea } from './liveFeed.js';
import {
  CAMERA_STATUS,
  EVENT_STATUS,
  emptyState,
  h,
  panel,
  relativeText,
  render,
  selectInput,
  statTile,
  statusChip,
  timeEl,
} from './ui.js';

const OPEN_INCIDENT_STATES = ['open', 'investigating', 'assigned'];
const ESCALATED_SEVERITIES = ['high', 'critical'];

export function mount(host, ctx) {
  const tiles = h('div.counter-grid', { 'aria-label': 'Posture summary' });
  const feedHost = h('div.dash-feed');
  const campusHost = h('div.dash-campus');
  const eventsHost = h('div.dash-events');
  const alertsHost = h('div.dash-alerts');
  const stamp = h('p.as-of');
  const errorLine = h('p.note', { role: 'alert' });

  const view = {
    overview: null,
    incidents: null,
    notifications: [],
    eventRows: [],
  };

  /** The one viewing session this screen owns, so leaving the rail can close it. */
  let feed = null;
  let feedCameraId = '';

  host.append(
    h('div.toolbar', [
      h('button.btn', { type: 'button', text: 'Refresh now', on: { click: () => load(true) } }),
      stamp,
    ]),
    errorLine,
    tiles,
    h('div.dash-split', [feedHost, campusHost]),
    h('div.two-col', [eventsHost, alertsHost])
  );

  const chosenCamera = () => ctx.cameras().find((camera) => camera.id === feedCameraId) || null;

  /* ------------------------------------------------------------------ loading */

  async function load(manual) {
    const tasks = [ctx.api.cameras.overview()];
    const keys = ['overview'];
    if (ctx.can('incident.view')) {
      tasks.push(ctx.api.incidents.list({ limit: 200 }));
      keys.push('incidents');
    }
    if (ctx.can('event.view')) {
      tasks.push(ctx.api.events.pending(true, 8));
      keys.push('events');
    }
    tasks.push(ctx.api.notifications.inbox(true, 8));
    keys.push('notifications');

    const results = await Promise.all(tasks);
    const bag = {};
    keys.forEach((key, index) => { bag[key] = results[index]; });

    view.overview = bag.overview;
    view.incidents = bag.incidents ? bag.incidents.incidents || [] : null;
    view.eventRows = bag.events ? bag.events.events || [] : [];
    view.notifications = (bag.notifications && bag.notifications.notifications) || [];
    render(errorLine, '');
    if (manual) stamp.textContent = `Refreshed ${relativeText(new Date().toISOString())}`;

    paintTiles();
    paintCampus();
    paintEvents();
    paintAlerts();
    // A running relay repaints itself from its own state poll; re-rendering the panel around it
    // would detach the <img> and drop the viewer.
    if (!feed) paintFeedPanel();
  }

  function loadQuietly() {
    return load(false).catch((error) => {
      const sentence = error instanceof ApiError ? error.display : 'The dashboard could not be re-read.';
      render(errorLine, h('span.tone-fg-bad', { text: sentence }));
    });
  }

  /* ------------------------------------------------------------------ tiles */

  function paintTiles() {
    const data = view.overview;
    if (!data) {
      render(tiles, h('div.counter', { text: 'Reading the post state...' }));
      return;
    }
    const total = data.total_cameras || 0;
    const online = data.online || 0;
    const readable = view.incidents !== null;
    const active = readable ? view.incidents.filter((row) => OPEN_INCIDENT_STATES.includes(row.status)).length : null;
    const escalated = readable
      ? view.incidents.filter((row) => OPEN_INCIDENT_STATES.includes(row.status) && ESCALATED_SEVERITIES.includes(row.severity)).length
      : null;
    const noIncidentPermission = 'Reading incidents needs the "incident.view" permission, which your role does not grant.';

    render(tiles, [
      statTile({
        label: 'Active alerts',
        value: active === null ? '-' : active,
        tone: active ? 'warn' : 'muted',
        icon: '⚑',
        note: active === null ? noIncidentPermission : 'Incidents open, investigating or assigned.',
      }),
      statTile({
        label: 'High priority',
        value: escalated === null ? '-' : escalated,
        tone: escalated ? 'bad' : 'muted',
        icon: '▲',
        note: escalated === null ? noIncidentPermission : 'Open incidents recorded as high or critical severity.',
      }),
      statTile({
        label: 'Under review',
        value: data.candidate_events,
        tone: data.candidate_events ? 'info' : 'muted',
        icon: '◌',
        note: 'Candidate detections still awaiting a human decision.',
      }),
      statTile({
        label: 'System health',
        value: total ? `${((online / total) * 100).toFixed(1)}%` : 'no cameras',
        tone: !total ? 'muted' : (online === total ? 'ok' : (online ? 'warn' : 'bad')),
        icon: '✓',
        note: total
          ? `${online} of ${total} cameras delivering frames right now.`
          : 'No camera record is visible to your role, so there is no delivery rate to measure.',
      }),
    ]);
  }

  /* ------------------------------------------------------------------ live panel */

  function openFeed(camera) {
    if (feed) feed.teardown();
    feed = createLiveFeed(ctx, { cameraId: camera.id, onState: () => paintFeedArea() });
    feedCameraId = camera.id;
    paintFeedPanel();
    feed.open();
  }

  function stopFeed() {
    if (feed) feed.teardown();
    feed = null;
    paintFeedPanel();
  }

  function paintFeedPanel() {
    const cameras = ctx.cameras();
    const delivering = cameras.filter((camera) => ['online', 'degraded', 'reconnecting'].includes(camera.status));
    const pool = delivering.length ? delivering : cameras;
    if (!feedCameraId && pool.length) feedCameraId = pool[0].id;

    const picker = selectInput(
      pool.length
        ? pool.map((camera) => ({ value: camera.id, label: `${camera.code} - ${camera.display_name}` }))
        : [{ value: '', label: 'No camera registered' }],
      { id: 'wt-dash-camera', name: 'dash-camera', 'aria-label': 'Camera on the dashboard feed' }
    );
    picker.value = feedCameraId;
    picker.disabled = !pool.length;
    picker.addEventListener('change', (event) => {
      feedCameraId = event.target.value;
      // Changing the camera is a deliberate act, so the old slot goes back to the server first.
      if (feed) stopFeed();
      else paintFeedPanel();
    });

    const start = h('button', { type: 'button', class: 'btn primary', text: feed ? 'Reload feed' : 'Show live feed' });
    start.addEventListener('click', () => {
      const camera = chosenCamera();
      if (!camera) {
        ctx.toast('No camera is registered, so there is nothing to show.', 'warn');
        return;
      }
      openFeed(camera);
    });
    ctx.gate(start, 'camera.view_live');

    const body = [];
    if (!cameras.length) {
      body.push(emptyState('No camera record is visible to your role, so there is no feed to open.'));
    } else if (!ctx.can('camera.view_live')) {
      body.push(h('p.note', { text: 'Opening video needs the "camera.view_live" permission, which your role does not grant. The counts and the campus state are still read for you.' }));
    } else {
      body.push(h('div.form-field', [
        h('label', { for: 'wt-dash-camera', text: 'Camera' }),
        picker,
        h('span.hint', {
          text: delivering.length
            ? `${delivering.length} camera${delivering.length === 1 ? '' : 's'} currently delivering frames. Showing a feed attaches this browser as a viewer of the stream the server already manages.`
            : 'No camera is delivering frames, so a feed will report what the server says about the source instead of showing video.',
        }),
      ]));
      body.push(h('div.toolbar', [
        start,
        feed ? h('button', { type: 'button', class: 'btn ghost', text: 'Stop feed', on: { click: stopFeed } }) : null,
      ]));
      body.push(h('div.feed-host'));
    }
    render(feedHost, panel('Live camera feed', body));
    paintFeedArea();
  }

  /**
   * Only the frame area is replaced, so a live relay survives the refresh that repaints the
   * tiles, the campus and the two lists underneath it.
   */
  function paintFeedArea() {
    const area = feedHost.querySelector('.feed-host');
    if (!area) return;
    render(area, feed ? feedArea(feed, chosenCamera(), () => feed && feed.open()) : h('p.note', {
      text: 'No viewing session is open, so no stream capacity is in use.',
    }));
  }

  /* ------------------------------------------------------------------ campus */

  function paintCampus() {
    const data = view.overview || {};
    const cameras = ctx.cameras();
    const total = data.total_cameras || 0;
    const body = [];

    if (!total) {
      body.push(emptyState('No camera record is visible to your role yet, so there is no campus coverage to show.'));
    } else {
      const entries = Object.entries(CAMERA_STATUS)
        .map(([key, meta]) => ({ key, meta, count: (data.by_status && data.by_status[key]) || 0 }))
        .filter((entry) => entry.count > 0);
      body.push(
        h('div.bar', { role: 'img', 'aria-label': `Coverage across ${total} cameras` },
          entries.map((entry) => h('span.bar-seg', {
            class: `bg-tone-${entry.meta.tone}`,
            style: `flex-grow: ${entry.count}`,
            title: `${entry.meta.label}: ${entry.count}`,
          }))
        )
      );
      body.push(h('div.campus-legend', entries.map((entry) => h('span.legend-item', [
        h('span.chip-shape', { text: entry.meta.shape, 'aria-hidden': 'true', class: `tone-fg-${entry.meta.tone}` }),
        h('span', { text: `${entry.meta.label} ${entry.count}` }),
      ]))));

      const byLocation = new Map();
      cameras.forEach((camera) => {
        const key = camera.campus_location || 'No location recorded';
        byLocation.set(key, [...(byLocation.get(key) || []), camera]);
      });
      body.push(h('ul.campus-list', [...byLocation.entries()]
        .sort((a, b) => b[1].length - a[1].length)
        .map(([location, list]) => h('li.campus-row', [
          h('div.campus-name', [
            h('strong', { text: location }),
            h('span.dim', { text: `${list.length} camera${list.length === 1 ? '' : 's'}` }),
          ]),
          h('div.campus-dots', list.map((camera) => {
            const meta = CAMERA_STATUS[camera.status] || CAMERA_STATUS.pending_setup;
            const dot = h('span.chip-shape', { text: meta.shape, 'aria-hidden': 'true', class: `tone-fg-${meta.tone}` });
            dot.title = `${camera.code} - ${camera.display_name}: ${meta.label}`;
            return dot;
          })),
        ]))));
      body.push(h('p.note', { text: 'Positions are recorded as free text on each camera and this deployment stores no coordinates, so the campus is grouped by the recorded location rather than drawn on a map.' }));
    }

    if (data.pending_setup > 0) {
      body.push(h('p.note.tone-fg-warn', {
        text: `${data.pending_setup} camera${data.pending_setup === 1 ? '' : 's'} exist as records but have no verified connection, so no video is available for them.`,
      }));
    }

    render(campusHost, panel('Campus overview', body, h('span.dim', { text: `${total} camera${total === 1 ? '' : 's'} visible` })));
  }

  /* ------------------------------------------------------------------ alerts and detections */

  function paintAlerts() {
    const body = [];
    if (!view.notifications.length) {
      body.push(emptyState('No unread alerts for this account.'));
    } else {
      view.notifications.forEach((row) => {
        const failed = row.state === 'failed';
        body.push(h('li.alert-row', { class: failed ? 'is-failed' : '' }, [
          h('div.alert-head', [
            h('strong', { text: row.title }),
            h('span.chip', { class: `tone-${failed ? 'bad' : 'muted'}` }, [
              h('span.chip-shape', { text: failed ? '✖' : '○', 'aria-hidden': 'true' }),
              h('span.chip-label', { text: row.state }),
            ]),
            timeEl(row.created_at),
          ]),
          h('p.alert-body', { text: row.body }),
          failed
            ? h('p.note.tone-fg-bad', { text: `Not delivered: ${row.failure_reason || 'no reason recorded'}.` })
            : null,
        ]));
      });
    }
    render(
      alertsHost,
      panel('Recent alerts', [h('ul.plain-list', body)], ctx.can('incident.view')
        ? h('button.btn.small', { type: 'button', text: 'Open incidents', on: { click: () => ctx.navigate('incidents') } })
        : null)
    );
  }

  function paintEvents() {
    const body = [];
    if (!ctx.can('event.view')) {
      body.push(emptyState('Candidate detections need the "event.view" permission, which your role does not grant.'));
    } else if (!view.eventRows.length) {
      body.push(emptyState('No candidate events are waiting for review.'));
    } else {
      view.eventRows.forEach((row) => {
        body.push(h('tr', [
          h('td', { text: row.camera_name || row.camera_code || 'unknown camera' }),
          h('td', { text: row.category }),
          h('td.num', { text: `${Math.round((row.confidence || 0) * 100)}%` }),
          h('td', [timeEl(row.occurred_at)]),
          h('td', [statusChip(row.status, EVENT_STATUS)]),
          h('td.actions', [h('button.btn.small', {
            type: 'button',
            text: 'Review',
            on: { click: () => ctx.navigate('intelligence') },
          })]),
        ]));
      });
    }
    render(eventsHost, panel('Newest candidate detections', [
      body.length ? (body.length > 1 ? h('table.matrix', [
        h('thead', [h('tr', [
          h('th', { text: 'Camera' }), h('th', { text: 'Category' }), h('th', { class: 'num', text: 'Confidence' }),
          h('th', { text: 'Occurred' }), h('th', { text: 'State' }), h('th', { text: 'Action' }),
        ])]),
        h('tbody', body),
      ]) : body[0]) : emptyState('Nothing is waiting for review.'),
      h('p.note', { text: 'A detection is a candidate raised by the analysis layer, never a finding of wrongdoing. Decisions are made on the AI Intelligence screen.' }),
    ]));
  }

  loadQuietly();

  return {
    autoRefreshMs: ctx.timers.overview,
    refresh: () => loadQuietly(),
    teardown: () => {
      if (feed) feed.teardown();
      feed = null;
    },
  };
}
