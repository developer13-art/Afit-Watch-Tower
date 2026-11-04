/**
 * AI Intelligence (proposal sections 11, 12): the candidate detections the analysis layer
 * raised, the confidence each carried, and the monitoring policy that decided both.
 *
 * What this deployment runs is classical computer vision, not a trained model: no ML weights
 * ship with it, so the numbers here are a detector's own score against a policy floor rather
 * than a model's probability. Every detection is a candidate for a human to judge, never a
 * finding of wrongdoing.
 */

import { ApiError } from './api.js';
import { PANEL_PERMISSIONS, renderPolicies } from './admin.js';
import {
  EVENT_STATUS,
  absoluteText,
  busy,
  emptyState,
  field,
  gatingNotice,
  h,
  openDialog,
  panel,
  panelSection,
  render,
  statusChip,
  timeEl,
} from './ui.js';

export function mount(host, ctx) {
  return panelSection(host, {
    title: 'AI Intelligence',
    idPrefix: 'wt-ai',
    ariaLabel: 'Intelligence areas',
    allowed: (permission) => ctx.can(permission),
    empty: 'Reading detections needs the "event.view" permission and the policy catalogue needs "camera.list"; your role grants neither.',
    autoRefreshMs: 30000,
    items: [
      {
        id: 'detections',
        label: 'Candidate detections',
        permission: 'event.view',
        render: (node) => renderDetections(node, ctx),
      },
      {
        id: 'policies',
        label: 'Monitoring policies',
        permission: PANEL_PERMISSIONS.policies,
        render: (node) => renderPolicies(node, ctx),
      },
    ],
  });
}

/* ------------------------------------------------------------------ detection queue */

/*
 * Held outside the render closure so the operator's filter survives the 30-second refresh and a
 * trip to another tab; re-creating it on every paint would silently reset the queue to "new
 * only" under whoever is reading it.
 */
let onlyNew = true;

function renderDetections(node, ctx) {
  async function load() {
    if (!ctx.can('event.view')) {
      render(node, panel('Candidate detections', [
        h('p.note', { text: 'Reading detections needs the "event.view" permission, which your role does not grant.' }),
      ]));
      return;
    }
    render(node, panel('Candidate detections', [emptyState('Loading detections...')]));
    let events;
    try {
      events = (await ctx.api.events.pending(onlyNew, 100)).events || [];
    } catch (error) {
      render(node, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) }));
      return;
    }
    paint(events);
  }

  function paint(events) {
    const toggle = h('label', { class: 'inline-check' }, [
      h('input', { type: 'checkbox', checked: onlyNew ? 'checked' : null }),
      h('span', { text: 'Only events awaiting review' }),
    ]);
    toggle.querySelector('input').addEventListener('change', (event) => {
      onlyNew = event.target.checked;
      load();
    });

    const rows = events.map((row) => {
      const review = h('button', { type: 'button', class: 'btn small primary', text: 'Review' });
      review.addEventListener('click', () => openReview(row, ctx, load));
      ctx.gate(review, 'event.review');

      return h('tr', [
        h('td', [h('div.name', { text: row.camera_name || row.camera_code || 'unknown camera' }), h('div.sub', { text: row.campus_location || 'no location recorded' })]),
        h('td', { text: row.category }),
        h('td.num', { text: `${Math.round((row.confidence || 0) * 100)}%`, title: `raw confidence ${row.confidence}` }),
        h('td', { text: detectorOf(row) }),
        h('td', [timeEl(row.occurred_at)]),
        h('td', [statusChip(row.status, EVENT_STATUS)]),
        h('td', { text: row.suppressed ? 'suppressed' : row.review_note ? clip(row.review_note, 60) : '-' }),
        h('td.actions', [review]),
      ]);
    });

    const reload = h('button', { type: 'button', class: 'btn', text: 'Reload' });
    reload.addEventListener('click', () => load());

    render(node, panel(`Candidate detections - ${events.length} shown`, [
      h('div.toolbar', [toggle, h('div.toolbar-spacer'), reload]),
      events.length
        ? h('table.matrix.dense', [
            h('thead', [h('tr', [
              h('th', { text: 'Camera' }), h('th', { text: 'Category' }), h('th', { class: 'num', text: 'Confidence' }),
              h('th', { text: 'Detector' }), h('th', { text: 'Detected' }), h('th', { text: 'Review state' }),
              h('th', { text: 'Note' }), h('th', { text: 'Action' }),
            ])]),
            h('tbody', rows),
          ])
        : emptyState('No candidate events match this filter. Either nothing has been detected or every detection has been reviewed.'),
      h('p.note', { text: 'Confidence is the detector score recorded at the moment of detection, measured against the floor set by the camera\'s monitoring policy. It is not a probability that an offence occurred.' }),
      !ctx.can('event.review') ? gatingNotice('event.review', 'Review buttons are disabled because this role cannot change detection states.') : null,
    ]));
  }

  load();
}

function openReview(event, ctx, afterChange) {
  const outcome = h('div.outcome-host');
  const note = h('textarea.input', { id: 'wt-review-note', rows: '3', maxlength: '2000', 'aria-label': 'Review note' });

  const decide = (decision, label, variant) => {
    const node = h('button', { type: 'button', class: `btn ${variant}`, text: label });
    node.addEventListener('click', (clickEvent) => {
      busy(clickEvent.currentTarget, true, label);
      ctx.api.events.review(event.id, decision, note.value.trim() || null)
        .then((result) => {
          render(outcome, [
            h('div.outcome.tone-border-info', [
              h('div.outcome-head', [h('span.outcome-title', { text: `Event marked ${result.event.status}` }), statusChip(result.event.status, EVENT_STATUS)]),
              h('div.outcome-rows', [
                field('Camera', `${result.event.camera_name || ''} (${result.event.camera_code || 'no code'})`),
                field('Category', result.event.category),
                field('Confidence', `${Math.round((result.event.confidence || 0) * 100)}%`),
                field('Review note recorded', result.event.review_note),
                field('Reviewed at', result.event.reviewed_at ? absoluteText(result.event.reviewed_at) : null),
              ]),
            ]),
            result.incident
              ? h('div.outcome.tone-border-warn', [
                  h('div.outcome-head', [h('span.outcome-title', { text: 'Incident raised from this detection' })]),
                  h('div.outcome-rows', [field('Reference', result.incident.reference), field('Status', result.incident.status)]),
                ])
              : null,
          ]);
          if (afterChange) afterChange();
        })
        .catch((error) => render(outcome, h('p.note.tone-fg-bad', { role: 'alert', text: describe(error) })))
        .finally(() => busy(clickEvent.currentTarget, false));
    });
    ctx.gate(node, 'event.review');
    return node;
  };

  openDialog({
    title: 'Review candidate detection',
    description: `${event.category} on ${event.camera_name || event.camera_code || 'camera'} at ${absoluteText(event.occurred_at)}. Confidence ${Math.round((event.confidence || 0) * 100)}%.`,
    width: 'wide',
    body: [
      h('div.two-col', [
        panel('Detection', [
          field('Camera', event.camera_name),
          field('Code', event.camera_code),
          field('Location', event.campus_location),
          field('Category', event.category),
          field('Confidence', event.confidence),
          field('Detector', detectorOf(event)),
          field('Metadata', event.metadata ? JSON.stringify(event.metadata) : null),
          field('Suppressed', event.suppressed ? 'yes' : 'no'),
          field('Previous review', event.review_note),
        ]),
        panel('Decision', [
          h('p.note', { text: 'Acknowledge keeps the detection as reviewed without raising an incident. Dismiss records it as not actionable. Escalate raises an incident for follow-up.' }),
          h('div.form-field', [h('label', { for: 'wt-review-note', text: 'Note (optional, recorded on the event and the incident action)' }), note]),
          h('div.toolbar', [
            decide('acknowledge', 'Acknowledge', ''),
            decide('dismiss', 'Dismiss', 'ghost'),
            decide('escalate', 'Escalate to incident', 'primary'),
          ]),
        ]),
      ]),
      outcome,
    ],
    actions: [{ label: 'Close', variant: 'ghost', desired: true }],
    onClose: () => afterChange && afterChange(),
  });
}

/** The detector code the analysis layer stamped on the event, when it recorded one. */
function detectorOf(event) {
  const metadata = event.metadata || {};
  return metadata.detector || 'not recorded by the detector';
}

function clip(value, length) {
  const text = String(value);
  return text.length > length ? text.slice(0, length) : text;
}

function describe(error) {
  if (error instanceof ApiError) return error.display;
  return 'The request could not be completed.';
}
