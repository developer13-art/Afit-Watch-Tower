/**
 * Dashboard (§4.1).
 *
 * Every figure is a server aggregate filtered by the caller's camera-group
 * scope. Nothing on this screen has a hardcoded default: a number that cannot
 * be fetched is shown as a failed state, never as zero.
 *
 * The status block reports three things that are actually measurable — whether the
 * service is reachable, whether the live channel is carrying frames, and what the
 * outbox says about delivery. It deliberately does not show the kind of green
 * "database connected" tile a phone cannot know: the app never talks to the database,
 * and an indicator that is always green is an indicator nobody reads.
 */
import { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { dashboardApi, incidentsApi, notificationsApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import { AsyncBoundary, ErrorState } from '../components/States';
import { ActionButton, IconBadge, SectionCard, SeverityChip, Spinner, StatTile } from '../components/ui';
import { ScreenHeader } from '../components/Shell';
import { formatDateTime, timeAgo } from '../lib/time';
import type { DashboardSummary } from '../types/api';
import { useSession } from '../auth/SessionProvider';
import { env } from '../config/env';
import { severityRank } from '../lib/severity';
import { IconAlert, IconBell, IconCheckCircle, IconGauge, IconInfo, IconRefresh, IconShield } from '../components/icons';

/** Real connectivity, computed from the delivery block. */
export function deliveryHealth(delivery: DashboardSummary['delivery']): {
  tone: 'ok' | 'warn' | 'bad';
  label: string;
  detail: string;
} {
  if (delivery.outbox_failed > 0 && delivery.outbox_pending > 0) {
    return {
      tone: 'bad',
      label: 'Delivery degraded',
      detail: `${delivery.outbox_failed} failed and ${delivery.outbox_pending} pending in the cloud outbox. Alerts may be delayed.`,
    };
  }
  if (delivery.outbox_failed > 0) {
    return { tone: 'bad', label: 'Delivery failing', detail: `${delivery.outbox_failed} send(s) failed in the outbox.` };
  }
  if (delivery.outbox_pending > 0) {
    return { tone: 'warn', label: 'Delivery queued', detail: `${delivery.outbox_pending} send(s) waiting for FCM acceptance.` };
  }
  if (!delivery.last_successful_push_at) {
    return { tone: 'warn', label: 'No push observed', detail: 'The outbox is empty and no successful push is recorded yet.' };
  }
  return {
    tone: 'ok',
    label: 'Notification service reachable',
    detail: `Last successful push ${timeAgo(delivery.last_successful_push_at)}.`,
  };
}

/** One measured fact, with the state it is in. Used by the status block and the header pill. */
function StatusLine({
  tone,
  label,
  detail,
  icon,
}: {
  tone: 'ok' | 'warn' | 'bad' | 'neutral';
  label: string;
  detail: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="flex items-start gap-3 border-b border-surface-line px-4 py-3 last:border-b-0">
      <IconBadge tone={tone === 'neutral' ? 'brand' : tone}>{icon}</IconBadge>
      <div className="min-w-0 flex-1">
        <p
          className={`text-[0.86rem] font-semibold ${
            tone === 'ok' ? 'text-state-ok' : tone === 'warn' ? 'text-sev-medium' : tone === 'bad' ? 'text-sev-critical' : 'text-ink'
          }`}
        >
          {label}
        </p>
        <p className="mt-0.5 text-[0.75rem] leading-snug text-ink-muted">{detail}</p>
      </div>
    </div>
  );
}

export function DeliveryIndicator({ summary }: { summary: DashboardSummary }) {
  const health = deliveryHealth(summary.delivery);
  return (
    <div data-testid="delivery-indicator" className="grid grid-cols-3 gap-2 border-t border-surface-line px-4 py-3 text-center">
      {[
        { k: 'Pending', v: summary.delivery.outbox_pending },
        { k: 'Failed', v: summary.delivery.outbox_failed },
        { k: 'Unread', v: summary.notifications.unread },
      ].map((cell) => (
        <div key={cell.k}>
          <p className="section-title">{cell.k}</p>
          <p className={`tabular text-[1.05rem] font-semibold ${cell.v > 0 && cell.k !== 'Unread' ? 'text-sev-critical' : 'text-ink'}`}>
            {cell.v}
          </p>
        </div>
      ))}
      <p className="col-span-3 pt-1 text-[0.72rem] leading-snug text-ink-faint">{health.detail}</p>
    </div>
  );
}

export function DashboardScreen() {
  const navigate = useNavigate();
  const { setUnreadCount, state, notificationRevision, activityRevision, liveStatus } = useSession();
  // The summary answers "what is on duty right now", which moves on either kind of event, so both
  // counters feed it. The alert strip only ever moves on a new notification.
  const summaryRevision = notificationRevision + activityRevision;
  const summary = useAsync<DashboardSummary>(() => dashboardApi.summary(), [state.revision], {
    pollMs: env.alertPollMs,
    liveRevision: summaryRevision,
  });

  const active = useAsync(
    () => incidentsApi.list({ status: ['open', 'investigating'], limit: 4 }),
    [state.revision],
    { isEmpty: (r) => r.items.length === 0, liveRevision: summaryRevision },
  );

  const alerts = useAsync(
    () =>
      notificationsApi
        .list({ limit: 5 })
        .then((res) => {
          setUnreadCount(res.total_unread);
          return res;
        })
        .then((res) => ({ ...res, items: [...res.items].sort((a, b) => severityRank(b.severity) - severityRank(a.severity)).slice(0, 5) })),
    [state.revision],
    { isEmpty: (r) => r.items.length === 0, pollMs: env.alertPollMs, liveRevision: notificationRevision },
  );

  const generated = useMemo(() => (summary.data ? formatDateTime(summary.data.generated_at) : ''), [summary.data]);

  const liveCopy =
    liveStatus === 'live'
      ? { tone: 'ok' as const, label: 'Live updates connected', detail: 'New alerts appear on this screen as they are recorded.' }
      : liveStatus === 'connecting' || liveStatus === 'reconnecting'
        ? { tone: 'warn' as const, label: 'Live updates reconnecting', detail: `Alerts still arrive by refresh, up to ${Math.round(env.alertPollMs / 1000)}s behind.` }
        : liveStatus === 'off'
          ? { tone: 'neutral' as const, label: 'Live updates idle', detail: 'The channel opens once this session is authorised.' }
          : { tone: 'bad' as const, label: 'Live updates unavailable', detail: `This session is falling back to refresh, up to ${Math.round(env.alertPollMs / 1000)}s behind.` };

  const connection = state.online
    ? { tone: 'ok' as const, label: 'Connected to the service', detail: `Personnel API at ${env.apiUrl}` }
    : { tone: 'bad' as const, label: 'Offline', detail: 'Showing the last response the service returned; it may be out of date.' };

  return (
    <div className="screen">
      <ScreenHeader
        title="AFIT Watch Tower"
        subtitle={summary.data ? `Aggregated ${generated}, scoped to your camera groups` : 'Scoped to your camera groups'}
        actions={
          <ActionButton variant="ghost" onClick={() => void Promise.all([summary.reload(), active.reload(), alerts.reload()])} aria-label="Refresh">
            <IconRefresh size={19} />
          </ActionButton>
        }
      />

      <AsyncBoundary
        state={summary}
        loadingLabel="Loading duty figures"
        emptyTitle="No open incidents"
        emptyBody="Nothing is active in your scope right now, and you have no unread alerts."
      >
        {(data) => (
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-3">
              <StatTile label="Critical" value={data.incidents.critical_open} tone="critical" icon={<IconAlert size={18} />} />
              <StatTile label="High" value={data.incidents.high_open} tone="high" icon={<IconAlert size={18} />} />
              <StatTile label="Total" value={data.incidents.active} tone="info" icon={<IconInfo size={18} />} />
            </div>

            <SectionCard
              title="Active Incidents"
              action={
                <button
                  type="button"
                  onClick={() => navigate('/incidents')}
                  className="text-[0.76rem] font-semibold text-brand"
                  data-testid="view-all-incidents"
                >
                  View All
                </button>
              }
            >
              {active.status === 'loading' ? (
                <div className="p-4">
                  <Spinner label="Loading incidents" />
                </div>
              ) : null}
              {active.status === 'error' && active.error ? (
                <div className="p-4">
                  <ErrorState error={active.error} onRetry={() => void active.reload()} />
                </div>
              ) : null}
              {active.status === 'empty' ? (
                <p className="px-4 py-5 text-[0.8rem] text-ink-muted">
                  No incident is open or under investigation in your scope right now.
                </p>
              ) : null}
              {active.data && active.data.items.length > 0 ? (
                <ul>
                  {active.data.items.map((incident) => (
                    <li key={incident.id}>
                      <button
                        type="button"
                        onClick={() => navigate(`/incidents/${incident.id}`)}
                        className="flex w-full items-center gap-3 border-b border-surface-line px-4 py-3 text-left last:border-b-0 active:bg-surface-overlay"
                        data-testid={`active-incident-${incident.id}`}
                      >
                        <IconBadge tone={severityRank(incident.severity) >= 4 ? 'bad' : 'warn'}>
                          <IconShield size={18} />
                        </IconBadge>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <span className="tabular truncate text-[0.8rem] font-semibold text-ink">{incident.reference}</span>
                            <SeverityChip severity={incident.severity} size="sm" />
                          </div>
                          <p className="mt-0.5 truncate text-[0.84rem] text-ink">{incident.title}</p>
                          <p className="truncate text-[0.72rem] text-ink-faint">
                            {incident.camera_name ?? 'No camera attached'} · {timeAgo(incident.occurred_at)}
                          </p>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </SectionCard>

            <SectionCard title="System Status">
              <StatusLine tone={connection.tone} label={connection.label} detail={connection.detail} icon={<IconCheckCircle size={18} />} />
              <StatusLine tone={liveCopy.tone} label={liveCopy.label} detail={liveCopy.detail} icon={<IconGauge size={18} />} />
              <StatusLine
                tone={deliveryHealth(data.delivery).tone}
                label={deliveryHealth(data.delivery).label}
                detail="Derived from the cloud outbox, not from a ping."
                icon={<IconBell size={18} />}
              />
              <DeliveryIndicator summary={data} />
            </SectionCard>

            {data.notifications.failed_delivery > 0 ? (
              <div role="alert" className="card border-sev-critical/50 bg-sev-critical/10 p-3 text-[0.78rem] text-sev-critical">
                {data.notifications.failed_delivery} notification(s) failed delivery to your devices. They remain in the alert
                centre.
              </div>
            ) : null}

            <SectionCard
              title="Latest alerts"
              action={
                <button
                  type="button"
                  onClick={() => navigate('/notifications')}
                  className="text-[0.76rem] font-semibold text-brand"
                >
                  Notification centre
                </button>
              }
            >
              {alerts.status === 'loading' ? (
                <div className="p-4">
                  <Spinner label="Loading alerts" />
                </div>
              ) : null}
              {alerts.status === 'error' && alerts.error ? (
                <div className="p-4">
                  <ErrorState error={alerts.error} onRetry={() => void alerts.reload()} />
                </div>
              ) : null}
              {alerts.status === 'empty' ? (
                <p className="px-4 py-5 text-[0.8rem] text-ink-muted">No notifications delivered to this account yet.</p>
              ) : null}
              {alerts.data && alerts.data.items.length > 0 ? (
                <ul>
                  {alerts.data.items.map((n) => (
                    <li key={n.id}>
                      <button
                        type="button"
                        onClick={() => navigate(n.incident_id ? `/incidents/${n.incident_id}` : '/notifications')}
                        className="flex w-full items-start gap-3 border-b border-surface-line px-4 py-3 text-left last:border-b-0 active:bg-surface-overlay"
                      >
                        <IconBadge tone={severityRank(n.severity) >= 4 ? 'bad' : severityRank(n.severity) >= 3 ? 'warn' : 'brand'}>
                          <IconAlert size={17} />
                        </IconBadge>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2">
                            <SeverityChip severity={n.severity} size="sm" />
                            <span className="tabular shrink-0 text-[0.68rem] text-ink-faint">{timeAgo(n.created_at)}</span>
                            {!n.read_at ? <span aria-label="unread" className="ml-auto h-2 w-2 shrink-0 rounded-full bg-brand" /> : null}
                          </div>
                          <p className="mt-1 truncate text-[0.86rem] font-medium text-ink">{n.title}</p>
                          <p className="truncate text-[0.74rem] text-ink-faint">{n.camera_name ?? n.kind}</p>
                        </div>
                      </button>
                    </li>
                  ))}
                </ul>
              ) : null}
            </SectionCard>

            <SectionCard title="Last 24 hours">
              <div className="grid grid-cols-3 gap-2 px-4 py-3 text-center">
                {[
                  { k: 'Awaiting ack', v: data.incidents.awaiting_acknowledgement, warn: data.incidents.awaiting_acknowledgement > 0 },
                  { k: 'Acknowledged', v: data.incidents.acknowledged_last_24h, warn: false },
                  { k: 'Resolved', v: data.incidents.resolved_last_24h, warn: false },
                ].map((cell) => (
                  <div key={cell.k}>
                    <p className="section-title">{cell.k}</p>
                    <p className={`tabular text-[1.2rem] font-bold ${cell.warn ? 'text-sev-medium' : 'text-ink'}`}>{cell.v}</p>
                  </div>
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Your access">
              <div className="px-4 py-3">
                <p className="text-[0.9rem] font-semibold text-ink">{data.personnel.display_name}</p>
                <p className="text-[0.75rem] text-ink-muted">{data.personnel.roles.join(', ') || 'No roles assigned'}</p>
                <p className="mt-2 text-[0.72rem] leading-snug text-ink-faint">
                  {data.personnel.permissions.length} effective permission
                  {data.personnel.permissions.length === 1 ? '' : 's'}, resolved by the server on every request. Revoking a grant
                  takes effect on your next action, not on your next sign-in.
                </p>
              </div>
            </SectionCard>
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}
