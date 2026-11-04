/**
 * Investigation notes (§6.4) — the write path for `POST /incidents/{id}/note`.
 *
 * A note is not an acknowledgement and does not move the status machine; the
 * screen says so because the two are confused in the field. Evidence is
 * read-only here by design: the contract has no upload route, so the mockup's
 * "Attach Evidence" is rendered as a link to the assets the monitoring station
 * already captured, never as a button that would do nothing.
 */
import { useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { incidentsApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import type { IncidentActivityEntry, IncidentDetail as IncidentDetailType } from '../types/api';
import { activityActionLabel, statusMeta } from '../lib/severity';
import { PERMISSION, actionable } from '../auth/permissions';
import { useSession } from '../auth/SessionProvider';
import { ActionButton, Chip, FilterChip, IconBadge, SectionCard, SeverityChip, Spinner, StatusChip } from '../components/ui';
import { ErrorState, ForbiddenState, LoadingState, UnauthorizedState } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { IconAlert, IconCamera, IconCheck, IconChevronRight, IconEscalate, IconNote, IconShield, IconUser } from '../components/icons';
import { formatDateTime, timeAgo } from '../lib/time';

const MAX_NOTE = 2000;

/** The glyph an officer learns to scan for: status moves, notes, and things that paged someone. */
function entryIcon(entry: IncidentActivityEntry) {
  if (entry.action === 'note') return <IconNote size={17} />;
  if (entry.action === 'acknowledged') return <IconCheck size={17} />;
  if (entry.action === 'escalated' || entry.action === 'reopened') return <IconEscalate size={17} />;
  if (entry.action === 'resolved' || entry.action === 'closed') return <IconShield size={17} />;
  if (entry.action === 'assigned') return <IconUser size={17} />;
  return <IconAlert size={17} />;
}

function entryTone(entry: IncidentActivityEntry): 'ok' | 'bad' | 'brand' | 'neutral' {
  if (entry.action === 'resolved') return 'ok';
  if (entry.action === 'escalated' || entry.action === 'reopened' || entry.action === 'dismissed') return 'bad';
  if (entry.action === 'note') return 'brand';
  return 'neutral';
}

export function InvestigationNotesScreen() {
  const params = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { state: sessionState, refreshMe, activityRevision } = useSession();
  const incidentId = Number(params.id);

  const [draft, setDraft] = useState('');
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<ApiError | null>(null);
  const [saved, setSaved] = useState(false);
  const [notesOnly, setNotesOnly] = useState(false);

  const detail = useAsync<IncidentDetailType>(
    () => incidentsApi.detail(incidentId),
    [incidentId, sessionState.revision],
    { liveRevision: activityRevision },
  );

  const activity = useAsync(
    () => incidentsApi.activity(incidentId, undefined, 50),
    [incidentId, sessionState.revision],
    { liveRevision: activityRevision },
  );

  const mayNote = actionable(sessionState.user, 'note');

  const entries = useMemo(() => {
    const items = activity.data?.items ?? [];
    return notesOnly ? items.filter((e) => e.action === 'note') : items;
  }, [activity.data, notesOnly]);

  const save = async () => {
    const text = draft.trim();
    if (!text) return;
    setSaving(true);
    setSaveError(null);
    try {
      const updated = await incidentsApi.note(incidentId, { note: text });
      detail.setData(() => updated);
      setDraft('');
      // The row we just wrote is not in the local list yet; the reload brings it, which is what
      // the "just saved" confirmation points at.
      void activity.reload();
      void refreshMe();
      setSaved(true);
    } catch (err) {
      const apiError = err instanceof ApiError ? err : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'The note was not saved.' });
      setSaveError(apiError);
      if (apiError.status === 403) void refreshMe();
      if (apiError.status === 409) {
        void detail.reload();
        void activity.reload();
      }
    } finally {
      setSaving(false);
    }
  };

  if (!Number.isSafeInteger(incidentId) || incidentId <= 0) {
    return (
      <div className="screen">
        <ScreenHeader title="Investigation notes" back="/incidents" />
        <ErrorState
          error={new ApiError({ code: ERROR_CODES.VALIDATION_FAILED, message: 'The link does not name a valid incident.', requestId: null })}
        />
      </div>
    );
  }

  const availableEvidence = (detail.data?.evidence ?? []).filter((a) => a.state === 'available').length;

  return (
    <div className="screen">
      <ScreenHeader
        title="Investigation notes"
        subtitle={detail.data?.reference}
        back={`/incidents/${incidentId}`}
        actions={
          activity.refreshing ? (
            <Spinner />
          ) : (
            <button
              type="button"
              onClick={() => void activity.reload()}
              aria-label="Reload notes"
              className="flex h-11 w-11 items-center justify-center rounded-full text-ink-muted active:bg-surface-overlay"
            >
              <IconNote size={19} />
            </button>
          )
        }
      />

      {detail.status === 'loading' ? <LoadingState label="Loading incident" /> : null}
      {detail.status === 'unauthorized' ? <UnauthorizedState onRetry={() => void detail.reload()} /> : null}
      {detail.status === 'forbidden' ? <ForbiddenState permission={PERMISSION.incidentView} /> : null}
      {detail.status === 'error' && detail.error ? <ErrorState error={detail.error} onRetry={() => void detail.reload()} /> : null}

      {detail.data ? (
        <section className="panel overflow-hidden">
          <div className="p-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip severity={detail.data.severity} size="sm" />
              <StatusChip status={detail.data.status} />
              <span className="tabular ml-auto text-[0.68rem] text-ink-faint">{timeAgo(detail.data.occurred_at)}</span>
            </div>
            <h2 className="mt-2 text-[0.98rem] font-semibold leading-snug text-ink">{detail.data.title}</h2>
            <p className="mt-1.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-[0.75rem] text-ink-muted">
              <IconCamera size={15} aria-hidden />
              {detail.data.camera_name ?? 'Camera not recorded'}
              {detail.data.campus_location ? <span className="text-ink-faint">· {detail.data.campus_location}</span> : null}
            </p>
            <p className="mt-1 text-[0.72rem] leading-snug text-ink-faint">
              {statusMeta(detail.data.status).terminal
                ? 'This incident is closed to status changes. A note still enters the audit history.'
                : 'A note records what you observed. It is not an acknowledgement and does not change the status.'}
            </p>
          </div>

          <button
            type="button"
            onClick={() => navigate(`/incidents/${incidentId}`)}
            data-testid="open-evidence"
            className="menu-row border-t border-surface-line"
          >
            <span aria-hidden className="shrink-0 text-brand">
              <IconCamera size={18} />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block font-medium text-ink">Evidence</span>
              <span className="mt-0.5 block text-[0.74rem] font-normal text-ink-faint">
                {availableEvidence > 0
                  ? `${availableEvidence} asset${availableEvidence === 1 ? '' : 's'} captured by the monitoring station`
                  : (detail.data?.evidence ?? []).length > 0
                    ? 'An asset was captured but the service will no longer serve it (past retention or deleted)'
                    : 'No asset stored for this incident'}
                {' — evidence is recorded at the camera, not uploaded from a phone'}
              </span>
            </span>
            <span aria-hidden className="shrink-0 text-ink-faint">
              <IconChevronRight size={18} />
            </span>
          </button>
        </section>
      ) : null}

      {/* ------------------------------------------------------------ composer */}
      {mayNote ? (
        <SectionCard title="New note" className="mt-3">
          <div className="p-4">
            <textarea
              id="investigation-note"
              className="field-input min-h-[132px]"
              value={draft}
              onChange={(e) => {
                setDraft(e.target.value.slice(0, MAX_NOTE));
                setSaved(false);
              }}
              placeholder="What you saw, who you spoke to, what you did and when."
              maxLength={MAX_NOTE}
              data-testid="note-input"
            />
            <div className="mt-2 flex items-center justify-between">
              <p className="tabular text-[0.68rem] text-ink-faint">{draft.trim().length}/{MAX_NOTE}</p>
              <p className="text-[0.68rem] text-ink-faint">Signed with your name and the server clock.</p>
            </div>
            <ActionButton
              variant="primary"
              full
              className="mt-3"
              busy={saving}
              disabled={draft.trim().length === 0}
              onClick={() => void save()}
              data-testid="save-note"
            >
              Save note
            </ActionButton>
            {saved ? (
              <p
                role="status"
                className="mt-2 rounded-card border border-state-ok/50 bg-state-ok/10 p-2.5 text-[0.75rem] leading-snug text-state-ok"
                data-testid="note-saved"
              >
                Saved. The note is in the activity history below and on the incident record.
              </p>
            ) : null}
            {saveError ? (
              <div role="alert" className="mt-2 rounded-card border border-sev-critical/50 bg-sev-critical/10 p-2.5">
                <p className="text-[0.8rem] font-semibold text-sev-critical">The note was not saved</p>
                <p className="mt-1 text-[0.74rem] leading-snug text-ink-muted">{saveError.userMessage}</p>
                <p className="mt-1 text-[0.74rem] leading-snug text-ink-muted">
                  {saveError.status === 403
                    ? 'Your account no longer holds the permission for this. Your text is still in the box — nothing was sent.'
                    : saveError.status === 409
                      ? 'The incident moved while you were writing. The record has been reloaded; check it before saving again.'
                      : 'Nothing was stored. Keep the text and try again, or report the request id if it repeats.'}
                </p>
                {saveError.requestId ? (
                  <p className="tabular mt-1.5 text-[0.68rem] text-ink-faint">request {saveError.requestId} · code {saveError.code}</p>
                ) : null}
              </div>
            ) : null}
          </div>
        </SectionCard>
      ) : (
        <div className="panel mt-4 p-4 text-[0.78rem] leading-snug text-ink-muted">
          Your account does not hold {PERMISSION.incidentView}, which is what the note route requires, so nothing can be
          written here. The history below is still complete.
        </div>
      )}

      {/* ------------------------------------------------------------ history */}
      <SectionCard
        title="Activity"
        className="mt-3"
        action={
          <div className="flex gap-1.5">
            <FilterChip active={!notesOnly} onClick={() => setNotesOnly(false)} testId="activity-all">
              All
            </FilterChip>
            <FilterChip active={notesOnly} onClick={() => setNotesOnly(true)} testId="activity-notes">
              Notes
            </FilterChip>
          </div>
        }
      >
        {activity.status === 'loading' ? (
          <div className="p-4">
            <LoadingState label="Loading activity" />
          </div>
        ) : null}
        {activity.status === 'error' && activity.error ? (
          <div className="p-4">
            <ErrorState error={activity.error} onRetry={() => void activity.reload()} />
          </div>
        ) : null}
        {activity.status === 'forbidden' ? <ForbiddenState permission={PERMISSION.incidentView} /> : null}

        {activity.status === 'success' && entries.length === 0 ? (
          <p className="p-4 text-[0.78rem] leading-snug text-ink-muted">
            {notesOnly
              ? 'No notes yet — the first one you save appears here.'
              : 'No actions recorded on this incident yet.'}
          </p>
        ) : null}

        {entries.length > 0 ? (
          <ol className="divide-y divide-surface-line">
            {entries.map((entry) => (
              <li key={entry.id} className="flex items-start gap-3 p-4">
                <IconBadge tone={entryTone(entry)}>{entryIcon(entry)}</IconBadge>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-[0.86rem] font-semibold text-ink">{activityActionLabel(entry.action)}</p>
                    <Chip tone={entryTone(entry) === 'neutral' ? 'neutral' : entryTone(entry)}>
                      {entry.actor_name ?? 'service'}
                    </Chip>
                    <span className="tabular ml-auto text-[0.66rem] text-ink-faint">{timeAgo(entry.created_at)}</span>
                  </div>
                  {entry.note ? (
                    <p className="mt-1.5 whitespace-pre-wrap text-[0.82rem] leading-relaxed text-ink">{entry.note}</p>
                  ) : (
                    <p className="mt-1 text-[0.75rem] text-ink-faint">No note attached to this action.</p>
                  )}
                  <p className="tabular mt-1 text-[0.66rem] text-ink-faint">{formatDateTime(entry.created_at)}</p>
                </div>
              </li>
            ))}
          </ol>
        ) : null}
      </SectionCard>

      <p className="mt-3 text-[0.7rem] leading-snug text-ink-faint">
        Notes are append-only. Nothing here deletes or edits an entry: a correction is another note, which is what keeps the
        history readable in an enquiry.
      </p>
    </div>
  );
}
