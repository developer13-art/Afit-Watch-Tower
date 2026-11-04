/**
 * Notification centre (§5).
 *
 * Cursor-paginated, newest first, with severity / date-range / kind filters and
 * an explicit refresh action that also works on the web build (pull-to-refresh
 * is a native gesture; the requirement is "works on web too", so the primary
 * control is a button and the gesture is an enhancement).
 *
 * Reading is not acknowledging (§5.2) — the row states them separately and the
 * action labels never blur the two.
 *
 * The four quick chips (All · Unread · Critical · High) are the two filters most
 * often changed on a duty device, so they are one tap; kind and date range live in
 * the advanced panel underneath, because they are set rarely and explained better
 * with a label than with a chip.
 */
import { useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { notificationsApi } from '../api/endpoints';
import { useCursorList } from '../hooks/useCursorList';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import type { NotificationItem, Severity } from '../types/api';
import { SEVERITY, SEVERITY_ORDER, severityRank } from '../lib/severity';
import { ActionButton, Chip, FilterChip, IconBadge, Row, Select, Spinner, TextInput } from '../components/ui';
import { EmptyState, ErrorState, ForbiddenState, LoadingState, UnauthorizedState } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { useSession } from '../auth/SessionProvider';
import { env } from '../config/env';
import { formatDateTime, timeAgo, toQueryTimestamp } from '../lib/time';
import { IconAlert, IconCheck, IconInfo, IconRefresh, IconSliders } from '../components/icons';

const KIND_OPTIONS = [
  '',
  'incident.created',
  'incident.escalated',
  'incident.resolved',
  'camera.health',
  'event.new',
];

type QuickFilter = 'all' | 'unread' | 'critical' | 'high';

const QUICK: { id: QuickFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'unread', label: 'Unread' },
  { id: 'critical', label: 'Critical' },
  { id: 'high', label: 'High' },
];

export function NotificationsScreen() {
  const navigate = useNavigate();
  const { setUnreadCount, notificationRevision } = useSession();
  const [quick, setQuick] = useState<QuickFilter>('all');
  const [kind, setKind] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [advanced, setAdvanced] = useState(false);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);

  const severity = (quick === 'critical' ? 'critical' : quick === 'high' ? 'high' : '') as '' | Severity;
  const unreadOnly = quick === 'unread';

  const filterKey = useMemo(
    () => JSON.stringify({ quick, kind, from, to }),
    [quick, kind, from, to],
  );

  const fetchPage = useCallback(
    async (cursor: string | null) => {
      const res = await notificationsApi.list({
        severity: severity ? ([severity] as Severity[]) : undefined,
        kind: kind || undefined,
        from: toQueryTimestamp(from),
        to: toQueryTimestamp(to, true),
        unread_only: unreadOnly || undefined,
        cursor: cursor ?? undefined,
        limit: 25,
      });
      setUnreadCount(res.total_unread);
      return { items: res.items, next_cursor: res.next_cursor };
    },
    [severity, unreadOnly, kind, from, to, setUnreadCount],
  );

  const list = useCursorList<NotificationItem>(fetchPage, filterKey, {
    pollMs: env.alertPollMs,
    liveRevision: notificationRevision,
  });

  const markRead = async (n: NotificationItem) => {
    setBusyId(n.id);
    setActionError(null);
    try {
      await notificationsApi.markRead(n.id);
      list.patchItem(n.id, { state: 'read', read_at: new Date().toISOString() });
      setUnreadCount(Math.max(0, unreadCountOf(list.items) - 1));
    } catch (err) {
      setActionError(err instanceof ApiError ? err : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Could not mark as read.' }));
    } finally {
      setBusyId(null);
    }
  };

  const openIncident = async (n: NotificationItem) => {
    if (!n.read_at) void notificationsApi.markRead(n.id).catch(() => undefined);
    if (n.incident_id) navigate(`/incidents/${n.incident_id}`, { state: { notificationId: n.id } });
    else navigate('/incidents');
  };

  return (
    <div className="screen">
      <ScreenHeader
        title="Notifications"
        subtitle={`${list.items.length} loaded · newest first`}
        actions={
          list.loading ? (
            <Spinner />
          ) : (
            <ActionButton variant="ghost" onClick={() => void list.refresh()} data-testid="refresh-notifications" aria-label="Refresh">
              <IconRefresh size={18} />
            </ActionButton>
          )
        }
      />

      <div className="-mx-4 mb-3 flex gap-2 overflow-x-auto px-4 pb-1">
        {QUICK.map((chip) => (
          <FilterChip
            key={chip.id}
            active={quick === chip.id}
            onClick={() => setQuick(chip.id)}
            testId={`filter-${chip.id}`}
          >
            {chip.label}
          </FilterChip>
        ))}
      </div>

      <div className="card mb-3 p-3">
        <button
          type="button"
          onClick={() => setAdvanced((v) => !v)}
          aria-expanded={advanced}
          className="flex w-full items-center gap-2 text-[0.8rem] font-semibold text-ink-muted"
          data-testid="toggle-advanced-filters"
        >
          <IconSliders size={17} />
          Advanced filters
          {kind || from || to ? <Chip tone="brand">{[kind, from && `from ${from}`, to && `to ${to}`].filter(Boolean).join(' · ')}</Chip> : null}
        </button>

        {advanced ? (
          <div className="mt-3 grid grid-cols-2 gap-2">
            <label className="space-y-1">
              <span className="label">Severity</span>
              <Select
                value={severity}
                onChange={(e) => setQuick(e.target.value === '' ? 'all' : (e.target.value as 'critical' | 'high'))}
              >
                <option value="">Any</option>
                {SEVERITY_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {SEVERITY[s].label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-1">
              <span className="label">Kind</span>
              <Select value={kind} onChange={(e) => setKind(e.target.value)}>
                {KIND_OPTIONS.map((k) => (
                  <option key={k} value={k}>
                    {k === '' ? 'Any' : k}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-1">
              <span className="label">From</span>
              <TextInput type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
            </label>
            <label className="space-y-1">
              <span className="label">To</span>
              <TextInput type="date" value={to} onChange={(e) => setTo(e.target.value)} />
            </label>
            <label className="col-span-2 mt-1 flex items-center gap-2 text-[0.8rem] text-ink-muted">
              <input
                type="checkbox"
                checked={unreadOnly}
                onChange={(e) => setQuick(e.target.checked ? 'unread' : 'all')}
                className="h-4 w-4 accent-brand"
              />
              Unread only
            </label>
            <div className="col-span-2 mt-1 flex gap-2">
              <ActionButton
                variant="secondary"
                onClick={() => {
                  setQuick('all');
                  setKind('');
                  setFrom('');
                  setTo('');
                }}
              >
                Clear filters
              </ActionButton>
              <ActionButton
                variant="ghost"
                onClick={() =>
                  void notificationsApi
                    .markAllRead()
                    .then(() => list.refresh())
                    .catch((err) => setActionError(err instanceof ApiError ? err : null))
                }
              >
                Mark all read
              </ActionButton>
            </div>
          </div>
        ) : (
          <div className="mt-2 flex gap-2">
            <ActionButton
              variant="ghost"
              onClick={() =>
                void notificationsApi
                  .markAllRead()
                  .then(() => list.refresh())
                  .catch((err) => setActionError(err instanceof ApiError ? err : null))
              }
            >
              Mark all read
            </ActionButton>
          </div>
        )}
      </div>

      {actionError ? <ErrorState error={actionError} onRetry={() => setActionError(null)} /> : null}

      {list.status === 'loading' ? <LoadingState label="Loading alerts" /> : null}
      {list.status === 'unauthorized' ? <UnauthorizedState /> : null}
      {list.status === 'forbidden' ? <ForbiddenState permission="incident.view" /> : null}
      {list.status === 'error' && list.error ? <ErrorState error={list.error} onRetry={() => void list.refresh()} /> : null}
      {list.status === 'empty' ? (
        <EmptyState
          title="No alerts for this filter"
          body="Nothing matches the current severity, kind and date range. Clear the filters to see the full history."
        />
      ) : null}

      {list.status === 'success' ? (
        <>
          <ul className="panel">
            {list.items.map((n) => (
              <li key={n.id} className="relative">
                <Row onClick={() => void openIncident(n)} ariaLabel={`${n.title}, ${n.severity}`}>
                  <IconBadge tone={severityRank(n.severity) >= 4 ? 'bad' : severityRank(n.severity) >= 3 ? 'warn' : 'brand'}>
                    {n.state === 'failed' ? <IconAlert size={17} /> : n.acknowledged_at ? <IconCheck size={17} /> : <IconInfo size={17} />}
                  </IconBadge>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start gap-2">
                      <p className={`min-w-0 flex-1 truncate text-[0.88rem] ${n.read_at ? 'text-ink-muted' : 'font-semibold text-ink'}`}>
                        {n.title}
                      </p>
                      <span className="tabular shrink-0 text-[0.68rem] text-ink-faint">{timeAgo(n.created_at)}</span>
                      {!n.read_at ? <span aria-label="unread" className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-sev-critical" /> : null}
                    </div>
                    <p className="tabular mt-0.5 truncate text-[0.7rem] text-ink-faint">
                      {n.incident_reference ?? n.kind}
                      {n.camera_name ? ` · ${n.camera_name}` : ''}
                    </p>
                    <p className="mt-0.5 line-clamp-2 text-[0.76rem] text-ink-faint">{n.body}</p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
                      <Chip tone={n.state === 'failed' ? 'bad' : n.read_at ? 'neutral' : 'brand'}>
                        {n.state === 'failed' ? 'Delivery failed' : n.read_at ? 'Read' : 'Unread'}
                      </Chip>
                      {n.acknowledged_at ? <Chip tone="ok">Acknowledged</Chip> : null}
                      {n.state === 'failed' && n.failure_reason ? (
                        <span className="text-[0.7rem] text-sev-critical">Delivery: {n.failure_reason}</span>
                      ) : null}
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-col items-end justify-center gap-2">
                    {!n.read_at ? (
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          void markRead(n);
                        }}
                        disabled={busyId === n.id}
                        className="px-2 py-1 text-[0.68rem] font-semibold uppercase tracking-wider text-brand disabled:opacity-50"
                      >
                        {busyId === n.id ? '…' : 'Mark read'}
                      </button>
                    ) : null}
                    {n.incident_id ? (
                      <span className="text-[0.68rem] uppercase tracking-wider text-ink-faint">Open</span>
                    ) : (
                      <span className="text-[0.68rem] uppercase tracking-wider text-ink-faint">No link</span>
                    )}
                  </div>
                </Row>
              </li>
            ))}
          </ul>

          <div className="mt-3 flex items-center justify-between gap-3">
            <p className="tabular text-[0.7rem] text-ink-faint">
              {list.items.length} shown · {formatDateTime(list.items[0]?.created_at)} newest
            </p>
            {list.canLoadMore ? (
              <ActionButton variant="secondary" busy={list.loadingMore} onClick={() => void list.loadMore()}>
                Load older
              </ActionButton>
            ) : (
              <p className="text-[0.72rem] text-ink-faint">End of history</p>
            )}
          </div>
        </>
      ) : null}
    </div>
  );
}

function unreadCountOf(items: NotificationItem[]): number {
  return items.filter((i) => !i.read_at).length;
}
