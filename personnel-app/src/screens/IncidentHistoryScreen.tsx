/**
 * Incident history (§6.1).
 *
 * Search covers reference, title and summary per the contract's `q` parameter.
 * Filters are sent to the server — the client never filters a page locally and
 * calls it a search, because a locally filtered page hides rows the operator is
 * entitled to see.
 */
import { useCallback, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { incidentsApi } from '../api/endpoints';
import { useSession } from '../auth/SessionProvider';
import { useCursorList } from '../hooks/useCursorList';
import type { IncidentStatus, IncidentSummary, Severity } from '../types/api';
import { SEVERITY, SEVERITY_ORDER, STATUS, STATUS_ORDER, severityRank } from '../lib/severity';
import { ActionButton, DetectionChip, FilterChip, IconBadge, Row, Select, SeverityChip, Spinner, StatusChip, TextInput } from '../components/ui';
import { EmptyState, ErrorState, ForbiddenState, LoadingState, UnauthorizedState } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { IconShield } from '../components/icons';
import { formatDateTime, timeAgo, toQueryTimestamp } from '../lib/time';
import { env } from '../config/env';

/**
 * The brief carries `available` and `deleted` refs. Counting both would advertise evidence that
 * can no longer be opened, so the queue badge counts only what the detail screen can render.
 */
function evidenceCount(incident: IncidentSummary): number {
  return (incident.evidence ?? []).filter((asset) => asset.state === 'available').length;
}

export function IncidentHistoryScreen() {
  const navigate = useNavigate();
  const { activityRevision } = useSession();
  const [q, setQ] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [status, setStatus] = useState<'' | IncidentStatus>('');
  const [severity, setSeverity] = useState<'' | Severity>('');
  const [category, setCategory] = useState('');
  const [location, setLocation] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [showFilters, setShowFilters] = useState(false);

  const filterKey = useMemo(
    () => JSON.stringify({ submittedQuery, status, severity, category, location, from, to }),
    [submittedQuery, status, severity, category, location, from, to],
  );

  const fetchPage = useCallback(
    async (cursor: string | null) => {
      const res = await incidentsApi.list({
        q: submittedQuery || undefined,
        status: status ? [status] : undefined,
        severity: severity ? [severity] : undefined,
        category: category || undefined,
        location: location || undefined,
        // `since`/`until` here; the notifications route names the same idea
        // `from`/`to`, and a shared helper would send a parameter this one ignores.
        since: toQueryTimestamp(from),
        until: toQueryTimestamp(to, true),
        cursor: cursor ?? undefined,
        limit: 25,
      });
      return { items: res.items, next_cursor: res.next_cursor };
    },
    [submittedQuery, status, severity, category, location, from, to],
  );

  const list = useCursorList<IncidentSummary>(fetchPage, filterKey, {
    pollMs: env.alertPollMs,
    liveRevision: activityRevision,
  });

  return (
    <div className="screen">
      <ScreenHeader
        title="Incident history"
        subtitle="Scoped to your camera groups"
        actions={
          <div className="flex items-center gap-2">
            <ActionButton variant="ghost" onClick={() => setShowFilters((v) => !v)} aria-expanded={showFilters}>
              Filters
            </ActionButton>
            <ActionButton variant="ghost" onClick={() => void list.refresh()} data-testid="refresh-incidents">
              {list.loading ? <Spinner /> : 'Refresh'}
            </ActionButton>
          </div>
        }
      />

      <div className="-mx-4 mb-3 flex gap-2 overflow-x-auto px-4 pb-1">
        {([
          { id: '', label: 'All' },
          { id: 'critical', label: 'Critical' },
          { id: 'high', label: 'High' },
          { id: 'medium', label: 'Medium' },
        ] as const).map((chip) => (
          <FilterChip
            key={chip.id}
            active={severity === chip.id}
            onClick={() => setSeverity(chip.id as '' | Severity)}
            testId={`severity-${chip.id || 'all'}`}
          >
            {chip.label}
          </FilterChip>
        ))}
      </div>

      <form
        className="mb-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          setSubmittedQuery(q.trim());
        }}
      >
        <TextInput
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Reference, title or summary"
          aria-label="Search incidents"
        />
        <ActionButton variant="primary" type="submit" disabled={!q.trim()}>
          Search
        </ActionButton>
      </form>

      {showFilters ? (
        <div className="card mb-3 p-3">
          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-1">
              <span className="label">Status</span>
              <Select value={status} onChange={(e) => setStatus(e.target.value as '' | IncidentStatus)}>
                <option value="">Any</option>
                {STATUS_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {STATUS[s].label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-1">
              <span className="label">Severity</span>
              <Select value={severity} onChange={(e) => setSeverity(e.target.value as '' | Severity)}>
                <option value="">Any</option>
                {SEVERITY_ORDER.map((s) => (
                  <option key={s} value={s}>
                    {SEVERITY[s].label}
                  </option>
                ))}
              </Select>
            </label>
            <label className="space-y-1">
              <span className="label">Category</span>
              <TextInput value={category} onChange={(e) => setCategory(e.target.value)} placeholder="restricted_zone_entry" />
            </label>
            <label className="space-y-1">
              <span className="label">Location</span>
              <TextInput value={location} onChange={(e) => setLocation(e.target.value)} placeholder="North entrance" />
            </label>
            <label className="space-y-1">
              <span className="label">From</span>
              <TextInput type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
            </label>
            <label className="space-y-1">
              <span className="label">To</span>
              <TextInput type="date" value={to} onChange={(e) => setTo(e.target.value)} />
            </label>
          </div>
          <div className="mt-3 flex gap-2">
            <ActionButton
              variant="secondary"
              onClick={() => {
                setQ('');
                setSubmittedQuery('');
                setStatus('');
                setSeverity('');
                setCategory('');
                setLocation('');
                setFrom('');
                setTo('');
              }}
            >
              Clear
            </ActionButton>
            <ActionButton variant="primary" onClick={() => void list.refresh()}>
              Apply
            </ActionButton>
          </div>
        </div>
      ) : null}

      {list.status === 'loading' ? <LoadingState label="Loading incidents" /> : null}
      {list.status === 'unauthorized' ? <UnauthorizedState /> : null}
      {list.status === 'forbidden' ? <ForbiddenState permission="incident.view" /> : null}
      {list.status === 'error' && list.error ? <ErrorState error={list.error} onRetry={() => void list.refresh()} /> : null}
      {list.status === 'empty' ? (
        <EmptyState
          title="No incidents match"
          body="No record in your assigned scope matches this search. A record you are not authorised to see returns the same answer as one that does not exist — that is by design (§1)."
        />
      ) : null}

      {list.status === 'success' ? (
        <>
          <ul className="panel">
            {list.items.map((i) => (
              <li key={i.id}>
                <Row onClick={() => navigate(`/incidents/${i.id}`)} ariaLabel={`${i.reference} ${i.title}`}>
                  <IconBadge tone={severityRank(i.severity) >= 4 ? 'bad' : severityRank(i.severity) >= 3 ? 'warn' : 'brand'}>
                    <IconShield size={17} />
                  </IconBadge>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="tabular text-[0.72rem] font-semibold text-ink-muted">{i.reference}</p>
                        <p className="truncate text-[0.88rem] font-medium text-ink">{i.title}</p>
                      </div>
                      <span className="tabular shrink-0 text-[0.68rem] text-ink-faint">{timeAgo(i.occurred_at)}</span>
                    </div>
                    <p className="truncate text-[0.74rem] text-ink-faint">
                      {formatDateTime(i.occurred_at)}
                      {i.campus_location ? ` · ${i.campus_location}` : ''}
                    </p>
                    <div className="mt-1.5 flex flex-wrap items-center gap-2">
                      <SeverityChip severity={i.severity} size="sm" />
                      <StatusChip status={i.status} />
                      <DetectionChip source={i.detection_source} confidence={i.confidence} />
                      <span className="text-[0.66rem] uppercase tracking-wider text-ink-faint">
                        {evidenceCount(i) > 0 ? `${evidenceCount(i)} evidence` : 'No evidence'}
                      </span>
                    </div>
                  </div>
                </Row>
              </li>
            ))}
          </ul>
          <div className="mt-3 flex items-center justify-between">
            <p className="tabular text-[0.7rem] text-ink-faint">{list.items.length} loaded</p>
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
