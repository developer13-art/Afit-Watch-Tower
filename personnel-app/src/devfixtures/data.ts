/**
 * ---------------------------------------------------------------------------
 * FIXTURE DATA — DEVELOPMENT ONLY.
 *
 * Reached only when `import.meta.env.DEV && VITE_USE_FIXTURES === '1'`. In a
 * production build `env.fixturesEnabled` folds to `false`, this module is never
 * imported, and Rollup drops it from the bundle (`src/devfixtures/gate.ts`
 * asserts that the sentinel below is absent from `dist/`).
 *
 * Every string here is invented for layout review. It is NOT statistics, NOT a
 * real incident, and MUST NOT be copied into a live screen as a default.
 *
 * Shapes follow `src/types/api.ts`, which is transcribed from the running
 * routers — so an actor is a user id plus a resolved name, activity is a
 * separate paginated collection, and an evidence link expiry is not the asset
 * retention date.
 * ---------------------------------------------------------------------------
 */
import type {
  DashboardSummary,
  DeviceListItem,
  EvidenceAsset,
  IncidentActivityEntry,
  IncidentDetail,
  IncidentSummary,
  NotificationItem,
  NotificationPreferencesResponse,
  ProfileResponse,
  UserPermissions,
} from '../types/api';

export const FIXTURE_SENTINEL = 'FIXTURE_DATA__WATCHTOWER_PERSONNEL__NOT_LIVE';

const now = Date.now();
const iso = (minutesAgo: number) => new Date(now - minutesAgo * 60_000).toISOString();

/** `views.user_view()` — what `/auth/me` answers with, in full. */
export const fixtureUser: UserPermissions = {
  id: 12,
  username: 'a.ahiya',
  display_name: 'Ahmad Ahiya',
  email: 'a.ahiya@afit.example',
  phone: '+2348110000000',
  roles: ['security_operator'],
  // Exactly `ROLE_DEFINITIONS.security_operator`. A fixture that grants the demo user more than
  // the server does would show response buttons the real service answers with a 403.
  permissions: [
    'camera.list',
    'camera.view_live',
    'event.view',
    'event.review',
    'incident.view',
    'incident.create',
    'incident.acknowledge',
    'evidence.view',
  ],
  is_active: true,
  must_change_password: false,
  last_login_at: iso(400),
  camera_scope: { 'incident.view': 'all', 'evidence.view': 'all' },
};

/** A second, nameless actor so the detail screen can show "someone else did this". */
export const fixtureSiti: UserPermissions = {
  ...fixtureUser,
  id: 9,
  username: 's.rahayu',
  display_name: 'Siti Rahayu',
  roles: ['security_supervisor'],
  permissions: [
    ...fixtureUser.permissions,
    'health.view',
    'incident.assign',
    'incident.escalate',
    'incident.resolve',
    'evidence.export',
    'report.operational',
  ],
};

export const fixtureDevices: DeviceListItem[] = [
  {
    id: 41,
    installation_id: '3f9c0000-0000-4000-8000-000000000001',
    platform: 'android',
    model: 'Pixel 7',
    os_version: '14',
    app_version: '1.0.0',
    push_state: 'active',
    push_capable: true,
    registered_at: iso(60 * 24 * 9),
    last_seen_at: iso(2),
  },
  {
    id: 38,
    installation_id: '3f9c0000-0000-4000-8000-000000000002',
    platform: 'android',
    model: 'SM-A525F',
    os_version: '13',
    app_version: '0.9.4',
    // `revoked`, because that is the only value DELETE /devices produces — an
    // inactive flag would render a chip state the service can never send.
    push_state: 'revoked',
    push_capable: false,
    registered_at: iso(60 * 24 * 71),
    last_seen_at: iso(60 * 26),
  },
];

export const fixturePreferences: NotificationPreferencesResponse = {
  min_severity: 'medium',
  kinds: {
    'incident.created': true,
    'incident.escalated': true,
    'incident.resolved': true,
    'camera.health': true,
    'event.new': false,
  },
  quiet_hours: { enabled: true, start: '22:00', end: '06:00' },
  sound: 'default',
  forced: ['critical', 'incident.escalated'],
  updated_at: iso(60 * 3),
};

/**
 * GET /profile — `user_view` plus the three profile-only keys. Declared after
 * the devices and preferences it embeds: these are `const`s, and a profile that
 * referenced them earlier would throw at module load.
 */
export const fixtureProfile: ProfileResponse = {
  ...fixtureUser,
  roles_with_descriptions: [
    {
      code: 'security_operator',
      name: 'Security Operator',
      description: 'Monitors assigned cameras, reviews alerts and records incident actions.',
    },
  ],
  devices: fixtureDevices,
  preferences: fixturePreferences,
};

export function fixtureDashboard(): DashboardSummary {
  // Derived from the mutable detail records so an acknowledge in fixture mode
  // moves the dashboard number, exactly as the real aggregate would.
  const rows = Object.values(fixtureIncidentDetails);
  const open = rows.filter((i) => i.status === 'open');
  const actionable = rows.filter((i) => i.status !== 'resolved' && i.status !== 'closed' && i.status !== 'false_positive');
  return {
    generated_at: new Date(now).toISOString(),
    incidents: {
      active: actionable.length,
      awaiting_acknowledgement: open.length,
      critical_open: open.filter((i) => i.severity === 'critical').length,
      high_open: open.filter((i) => i.severity === 'high').length,
      acknowledged_last_24h: rows.filter((i) => i.acknowledged_by !== null).length,
      resolved_last_24h: rows.filter((i) => i.status === 'resolved').length,
    },
    notifications: {
      unread: fixtureNotifications.filter((n) => !n.read_at).length,
      failed_delivery: fixtureNotifications.filter((n) => n.state === 'failed').length,
    },
    delivery: {
      outbox_pending: 0,
      outbox_failed: 0,
      last_successful_push_at: iso(6),
      active_devices: fixtureDevices.filter((d) => d.push_state === 'active').length,
    },
    personnel: {
      display_name: fixtureUser.display_name,
      roles: fixtureUser.roles,
      permissions: fixtureUser.permissions,
    },
  };
}

// ------------------------------------------------------------------ incidents

const PNG_1PX =
  'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==';

export const fixtureIncidents: IncidentSummary[] = [
  {
    id: 77,
    reference: 'WT-2026-0007',
    title: 'Restricted-zone entry at Main Gate',
    category: 'restricted_zone_entry',
    severity: 'critical',
    status: 'open',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000001',
    camera_name: 'Main Gate',
    campus_location: 'North entrance',
    occurred_at: iso(3),
    created_at: iso(3),
    detection_source: 'ai_candidate',
    confidence: 0.72,
    assigned_to: null,
    assigned_to_name: null,
    escalated_to: null,
    escalated_to_name: null,
    evidence: [
      { id: 5, kind: 'snapshot', content_type: 'image/jpeg', state: 'available' },
      { id: 6, kind: 'clip', content_type: 'video/mp4', state: 'available' },
    ],
  },
  {
    id: 76,
    reference: 'WT-2026-0006',
    title: 'Perimeter loitering — east fence',
    category: 'loitering',
    severity: 'high',
    status: 'investigating',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000002',
    camera_name: 'East Fence 03',
    campus_location: 'East perimeter',
    occurred_at: iso(22),
    created_at: iso(21),
    detection_source: 'ai_candidate',
    confidence: 0.41,
    assigned_to: null,
    assigned_to_name: null,
    escalated_to: null,
    escalated_to_name: null,
    evidence: [{ id: 7, kind: 'snapshot', content_type: 'image/jpeg', state: 'available' }],
  },
  {
    id: 75,
    reference: 'WT-2026-0005',
    title: 'Camera offline — Warehouse 2',
    category: 'camera_health',
    severity: 'medium',
    status: 'open',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000003',
    camera_name: 'Warehouse 2',
    campus_location: 'Logistics yard',
    occurred_at: iso(90),
    created_at: iso(90),
    // `detection_source_for()` only ever answers ai_candidate or manual. A
    // health alert has no model score, so it is not a candidate event.
    detection_source: 'manual',
    confidence: null,
    assigned_to: null,
    assigned_to_name: null,
    escalated_to: null,
    escalated_to_name: null,
    evidence: [],
  },
  {
    id: 74,
    reference: 'WT-2026-0004',
    title: 'Vehicle gate blocked by delivery van',
    category: 'obstruction',
    severity: 'low',
    status: 'resolved',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000004',
    camera_name: 'Vehicle Gate',
    campus_location: 'West drive',
    occurred_at: iso(60 * 6),
    created_at: iso(60 * 6),
    detection_source: 'manual',
    confidence: null,
    assigned_to: 9,
    assigned_to_name: 'Siti Rahayu',
    escalated_to: 9,
    escalated_to_name: 'Siti Rahayu',
    evidence: [{ id: 8, kind: 'snapshot', content_type: 'image/jpeg', state: 'deleted' }],
  },
];

export const fixtureIncidentDetails: Record<number, IncidentDetail> = {
  77: {
    ...fixtureIncidents[0],
    summary:
      'Model flagged a person crossing the restricted line at the main gate turnstile outside the staffed window. Candidate only — no human has judged this frame yet.',
    resolution: null,
    outcome: null,
    resolved_at: null,
    updated_at: iso(3),
    origin_event_id: 4412,
    acknowledged_by: null,
    acknowledgements: [],
  },
  76: {
    ...fixtureIncidents[1],
    summary: 'Repeated presence at the east fence line for more than four minutes.',
    resolution: null,
    outcome: null,
    resolved_at: null,
    updated_at: iso(14),
    origin_event_id: 4388,
    acknowledged_by: 12,
    acknowledgements: [
      {
        user_id: 12,
        display_name: 'Ahmad Ahiya',
        source: 'mobile_app',
        note: 'Dispatched patrol on foot.',
        acknowledged_at: iso(14),
      },
    ],
  },
  75: {
    ...fixtureIncidents[2],
    summary: 'Heartbeat missing for 3 consecutive polls. Coverage gap on the logistics yard.',
    resolution: null,
    outcome: null,
    resolved_at: null,
    updated_at: iso(90),
    origin_event_id: null,
    acknowledged_by: null,
    acknowledgements: [],
  },
  74: {
    ...fixtureIncidents[3],
    summary: 'Delivery van parked across the gate lane. Gate cleared by the driver.',
    resolution: 'Gate lane cleared, vehicle moved under escort.',
    outcome: 'resolved_no_action',
    resolved_at: iso(60 * 6 - 40),
    updated_at: iso(320),
    origin_event_id: null,
    acknowledged_by: 9,
    acknowledgements: [
      {
        user_id: 9,
        display_name: 'Siti Rahayu',
        source: 'monitoring_console',
        note: null,
        acknowledged_at: iso(330),
      },
    ],
  },
};

/**
 * `GET /incidents/{id}/activity` is its own paginated route, so the fixture
 * store keeps the history apart from the detail body — same as the service.
 * Newest first, matching `ORDER BY id DESC`.
 */
export const fixtureActivity: Record<number, IncidentActivityEntry[]> = {
  77: [
    {
      id: 900,
      action: 'created_from_event',
      note: 'Ingested from monitoring host WT-MON-01.',
      actor_id: null,
      actor_name: null,
      created_at: iso(3),
    },
  ],
  76: [
    {
      id: 881,
      action: 'acknowledged',
      note: 'Dispatched patrol on foot.',
      actor_id: 12,
      actor_name: 'Ahmad Ahiya',
      created_at: iso(14),
    },
    {
      id: 880,
      action: 'created_from_event',
      note: null,
      actor_id: null,
      actor_name: null,
      created_at: iso(21),
    },
  ],
  75: [
    {
      id: 860,
      action: 'created',
      note: null,
      actor_id: null,
      actor_name: null,
      created_at: iso(90),
    },
  ],
  74: [
    {
      id: 841,
      action: 'resolved',
      note: 'Driver present, vehicle moved.',
      actor_id: 9,
      actor_name: 'Siti Rahayu',
      created_at: iso(320),
    },
    {
      id: 840,
      action: 'created',
      note: null,
      actor_id: null,
      actor_name: null,
      created_at: iso(360),
    },
  ],
};

export function fixtureEvidence(incidentId: number): EvidenceAsset[] {
  if (incidentId === 77) {
    return [
      {
        id: 5,
        kind: 'snapshot',
        content_type: 'image/png',
        byte_size: 68,
        captured_at: iso(3),
        state: 'available',
        url: PNG_1PX,
        // Retention runs for days; the signed link runs for minutes. Two
        // different numbers on purpose so the panel cannot mix them up.
        expires_at: iso(-60 * 27),
        sha256: '0000000000000000000000000000000000000000000000000000000000000000',
        expires_at_token: iso(-10),
      },
      {
        id: 6,
        kind: 'clip',
        content_type: 'video/mp4',
        byte_size: null,
        captured_at: iso(3),
        // Deliberately `processing`: fixture mode cannot demonstrate real
        // range-request video. This exercises the honest "still uploading"
        // state instead of pretending a clip exists.
        state: 'processing',
        url: null,
        expires_at: null,
        sha256: null,
        expires_at_token: null,
      },
    ];
  }
  if (incidentId === 74) {
    return [
      {
        id: 8,
        kind: 'snapshot',
        content_type: 'image/png',
        byte_size: 68,
        captured_at: iso(360),
        state: 'expired',
        url: null,
        expires_at: iso(300),
        sha256: null,
        expires_at_token: null,
      },
    ];
  }
  return [];
}

// ------------------------------------------------------------------ notifications

export const fixtureNotifications: NotificationItem[] = [
  {
    id: 812,
    kind: 'incident.created',
    title: 'Restricted-zone entry at Main Gate',
    body: 'AI candidate, 72% confidence. Acknowledge or escalate.',
    severity: 'critical',
    state: 'delivered',
    read_at: null,
    acknowledged_at: null,
    delivered_at: iso(3),
    created_at: iso(3),
    incident_id: 77,
    incident_reference: 'WT-2026-0007',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000001',
    camera_name: 'Main Gate',
    campus_location: 'North entrance',
    failure_reason: null,
    deep_link: 'watchtower://incidents/77',
  },
  {
    id: 811,
    kind: 'incident.escalated',
    title: 'Escalated: perimeter loitering — east fence',
    body: 'Unacknowledged for 180s, raised to security_supervisor.',
    severity: 'high',
    state: 'read',
    read_at: iso(10),
    acknowledged_at: iso(14),
    delivered_at: iso(15),
    created_at: iso(15),
    incident_id: 76,
    incident_reference: 'WT-2026-0006',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000002',
    camera_name: 'East Fence 03',
    campus_location: 'East perimeter',
    failure_reason: null,
    deep_link: 'watchtower://incidents/76',
  },
  {
    id: 809,
    kind: 'camera.health',
    title: 'Camera offline — Warehouse 2',
    body: 'No heartbeat for 3 polls.',
    severity: 'medium',
    state: 'delivered',
    read_at: null,
    acknowledged_at: null,
    delivered_at: iso(90),
    created_at: iso(90),
    incident_id: 75,
    incident_reference: 'WT-2026-0005',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000003',
    camera_name: 'Warehouse 2',
    campus_location: 'Logistics yard',
    failure_reason: null,
    deep_link: 'watchtower://incidents/75',
  },
  {
    id: 800,
    kind: 'incident.resolved',
    title: 'Resolved: vehicle gate blocked',
    body: 'Closed as resolved_no_action.',
    severity: 'low',
    state: 'failed',
    read_at: iso(60 * 7),
    acknowledged_at: null,
    delivered_at: null,
    created_at: iso(60 * 7),
    incident_id: 74,
    incident_reference: 'WT-2026-0004',
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000004',
    camera_name: 'Vehicle Gate',
    campus_location: 'West drive',
    // Exercises the failed-delivery rendering path — `failure_reason` is the
    // only place the service explains a non-delivery.
    failure_reason: 'Unavailable — device offline 41m',
    deep_link: 'watchtower://incidents/74',
  },
  {
    // No incident: `deep_link` is absent from this body, which is the case the
    // notification screen must survive.
    id: 795,
    kind: 'event.new',
    title: 'Motion event reviewed',
    body: 'Two candidate events on East Fence 03 were closed as false positives.',
    severity: 'low',
    state: 'pending',
    read_at: null,
    acknowledged_at: null,
    delivered_at: null,
    created_at: iso(200),
    incident_id: null,
    incident_reference: null,
    camera_id: '2f1e9b3a-1c11-4b1a-9a0d-000000000002',
    camera_name: 'East Fence 03',
    campus_location: 'East perimeter',
    failure_reason: null,
  },
];
