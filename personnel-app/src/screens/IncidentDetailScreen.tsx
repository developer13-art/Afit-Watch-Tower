/**
 * Incident details + response actions (§6.2, §6.3, §6.4, §7).
 *
 * Authorization is display-only: the action set is rendered from the real
 * permission list from /auth/me, but a 403 (grant revoked a moment ago) and a
 * 409 (another operator advanced the status machine) are both handled from the
 * server's answer. Hidden buttons are never the security model.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { useLocation, useNavigate, useParams } from 'react-router-dom';
import { incidentsApi, notificationsApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import type { IncidentDetail as IncidentDetailType, IncidentOutcome } from '../types/api';
import {
  DETECTION_SOURCE,
  SEVERITY,
  activityActionLabel,
  detectionMeta,
  formatConfidence,
  severityMeta,
  statusMeta,
} from '../lib/severity';
import { ESCALATION_ROLES, PERMISSION, actionable } from '../auth/permissions';
import { useSession } from '../auth/SessionProvider';
import { EvidencePanel } from '../components/EvidencePanel';
import {
  ActionButton,
  Chip,
  DetectionChip,
  Field,
  InfoRow,
  SectionCard,
  Select,
  Sheet,
  Spinner,
  StatusChip,
} from '../components/ui';
import { ErrorState, ForbiddenState, LoadingState, UnauthorizedState } from '../components/States';
import { ConfirmationMark, ScreenHeader } from '../components/Shell';
import {
  IconAlert,
  IconCamera,
  IconChevronRight,
  IconClock,
  IconEscalate,
  IconEye,
  IconGauge,
  IconInfo,
  IconNote,
  IconPin,
  IconRefresh,
  IconShield,
  IconUser,
} from '../components/icons';
import { formatDateTime, timeAgo } from '../lib/time';

const OUTCOMES: Array<{ value: IncidentOutcome; label: string }> = [
  { value: 'confirmed_threat', label: 'Confirmed threat' },
  { value: 'false_alarm', label: 'False alarm' },
  { value: 'resolved_no_action', label: 'Resolved — no action needed' },
  { value: 'maintenance', label: 'Maintenance / test' },
];

type ActionKey = 'acknowledge' | 'investigating' | 'note' | 'escalate' | 'resolve' | 'reopen';

interface PendingAction {
  kind: ActionKey;
  title: string;
  blurb: string;
  needsNote: boolean;
  noteRequired: boolean;
}

/** The three rail buttons the brief is read for; everything else sits underneath them. */
const RAIL: ActionKey[] = ['acknowledge', 'investigating', 'escalate'];

const ACTION_ICON: Record<ActionKey, ReactNode> = {
  acknowledge: <IconShield size={18} />,
  investigating: <IconEye size={18} />,
  note: <IconNote size={18} />,
  escalate: <IconEscalate size={18} />,
  resolve: <IconCheckGlyph />,
  reopen: <IconAlert size={18} />,
};

function IconCheckGlyph() {
  return (
    <svg aria-hidden width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="m5 12.5 4.5 4.5L19 7.5" />
    </svg>
  );
}

export function IncidentDetailScreen() {
  const params = useParams<{ id: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const { state: sessionState, refreshMe, activityRevision } = useSession();
  const incidentId = Number(params.id);

  const [pending, setPending] = useState<PendingAction | null>(null);
  const [note, setNote] = useState('');
  const [outcome, setOutcome] = useState<IncidentOutcome>('confirmed_threat');
  const [escalateRole, setEscalateRole] = useState('security_supervisor');
  /**
   * `ResolveBody.false_positive` — it is what moves the incident to the `false_positive` status
   * rather than `resolved`, so it is a decision the operator makes deliberately, not a label on
   * the outcome dropdown.
   */
  const [falsePositive, setFalsePositive] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [conflict, setConflict] = useState<string | null>(null);
  /** The acknowledgement receipt. It is a fact about the write that just succeeded, not a toast. */
  const [acknowledged, setAcknowledged] = useState(false);

  const activityRef = useRef<HTMLDivElement>(null);

  const detail = useAsync<IncidentDetailType>(
    () => incidentsApi.detail(incidentId),
    [incidentId, sessionState.revision],
    // Another officer's acknowledge or resolve changes this brief: the status rail, the version
    // the next write must send, and the buttons that follow from either.
    { liveRevision: activityRevision },
  );

  // §5.3 — report the open only once the incident actually rendered.
  const notificationId = (location.state as { notificationId?: number } | null)?.notificationId ?? null;
  const reported = useRef<string | null>(null);
  useEffect(() => {
    if (!notificationId || detail.status !== 'success') return;
    const key = `${incidentId}:${notificationId}`;
    if (reported.current === key) return;
    reported.current = key;
    void notificationsApi.reportOpen(notificationId).catch(() => undefined);
  }, [notificationId, detail.status, incidentId]);

  // The detail body does not carry the history: `GET /incidents/{id}/activity` is its own
  // paginated route (§6.4). `runAction` reloads it explicitly after a write.
  const activity = useAsync(
    () => incidentsApi.activity(incidentId),
    [incidentId, sessionState.revision],
    { liveRevision: activityRevision },
  );

  const actorLabel = useCallback((entry: { actor_name: string | null }) => {
    // A null actor is the service acting — an automatic escalation, or the ingest worker that
    // opened the incident from a candidate event — not a person who forgot to sign in.
    return entry.actor_name ?? 'WATCH TOWER service';
  }, []);

  const runAction = async (kind: ActionKey) => {
    setConflict(null);
    setActionError(null);
    setSubmitting(true);
    try {
      let updated: IncidentDetailType;
      switch (kind) {
        case 'acknowledge':
          updated = await incidentsApi.acknowledge(incidentId, note.trim() || undefined);
          break;
        case 'investigating':
          updated = await incidentsApi.investigating(incidentId, note.trim() || undefined);
          break;
        case 'note':
          updated = await incidentsApi.note(incidentId, { note: note.trim() });
          break;
        case 'escalate':
          updated = await incidentsApi.escalate(incidentId, { reason: note.trim(), to_role: escalateRole });
          break;
        case 'resolve':
          updated = await incidentsApi.resolve(incidentId, {
            outcome,
            resolution: note.trim(),
            false_positive: falsePositive,
          });
          break;
        case 'reopen':
          updated = await incidentsApi.reopen(incidentId, { reason: note.trim() });
          break;
        default:
          throw new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Unknown action.' });
      }
      detail.setData(() => updated);
      void activity.reload();
      // Permissions may have changed server-side while we worked (§2.5).
      void refreshMe();
      setPending(null);
      setNote('');
      if (kind === 'acknowledge') setAcknowledged(true);
    } catch (err) {
      const apiError = err instanceof ApiError ? err : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Action failed.' });
      if (apiError.status === 409) {
        setConflict(
          apiError.code === ERROR_CODES.ALREADY_RESOLVED ||
            apiError.code === ERROR_CODES.NOT_RESOLVED ||
            apiError.code === ERROR_CODES.INVALID_STATE ||
            apiError.code === ERROR_CODES.INCIDENT_NOT_ACTIONABLE
            // The service's own words, because it knows which state it refused on.
            ? `${apiError.userMessage} The server’s state is authoritative — the record has been reloaded below.`
            : 'Another operator changed this incident while you were working. Your action was rejected. Review the current state before acting again.',
        );
        void detail.reload();
        void activity.reload();
      } else if (apiError.status === 403) {
        setActionError(apiError);
        // A revoked grant takes effect immediately; refresh the local set.
        void refreshMe();
      } else if (apiError.status === 404) {
        setActionError(apiError);
      } else {
        setActionError(apiError);
      }
    } finally {
      setSubmitting(false);
    }
  };

  const openSheet = (action: PendingAction) => {
    setNote('');
    setFalsePositive(false);
    setPending(action);
    setConflict(null);
    setActionError(null);
  };

  const status = detail.data?.status ?? 'open';
  const terminal = statusMeta(status).terminal;

  const availableActions = useMemo(() => {
    const list: PendingAction[] = [];
    if (!terminal) {
      if (actionable(sessionState.user, 'acknowledge') && status === 'open') {
        list.push({
          kind: 'acknowledge',
          title: 'Acknowledge',
          blurb: 'Claims this incident. Sets status to Under investigation, records you as the acknowledging actor, and marks your notification acknowledged (§6.3).',
          needsNote: true,
          noteRequired: false,
        });
      }
      if (actionable(sessionState.user, 'investigating') && status === 'open') {
        list.push({
          kind: 'investigating',
          title: 'Investigate',
          blurb: 'Advances the status without an acknowledgement claim — use it when you are looking but not yet owning.',
          needsNote: true,
          noteRequired: false,
        });
      }
      if (actionable(sessionState.user, 'escalate')) {
        list.push({
          kind: 'escalate',
          title: 'Escalate',
          blurb: 'Notifies the target role and records the escalation. A critical incident left unacknowledged escalates automatically after the configured window; doing it early does not lose the audit trail.',
          needsNote: true,
          noteRequired: true,
        });
      }
      if (actionable(sessionState.user, 'resolve')) {
        list.push({
          kind: 'resolve',
          title: 'Resolve',
          blurb: 'Closes the incident with an outcome and a written resolution. The outcome is what the next shift reads.',
          needsNote: true,
          noteRequired: true,
        });
      }
    }
    // `IncidentService.reopen()` accepts only `resolved` and `closed`, so a false positive is
    // offered no reopen button here — it would only be refused with `not_resolved`.
    if ((status === 'resolved' || status === 'closed') && actionable(sessionState.user, 'resolve')) {
      list.push({
        kind: 'reopen',
        title: 'Reopen',
        blurb: 'Returns the incident to Under investigation with a stated reason, and clears the outcome. Both ends stay in the activity history.',
        needsNote: true,
        noteRequired: true,
      });
    }
    if (actionable(sessionState.user, 'note')) {
      list.push({
        kind: 'note',
        title: 'Add note',
        blurb: 'Writes an activity note. Does not change status and is not an acknowledgement.',
        needsNote: true,
        noteRequired: true,
      });
    }
    return list;
  }, [sessionState.user, status, terminal]);

  if (!Number.isSafeInteger(incidentId) || incidentId <= 0) {
    return (
      <div className="screen">
        <ScreenHeader title="Incident" back="/incidents" />
        <ErrorState
          error={new ApiError({ code: ERROR_CODES.VALIDATION_FAILED, message: 'The link does not name a valid incident.', requestId: null })}
        />
      </div>
    );
  }

  const sev = severityMeta(detail.data?.severity);
  const railActions = availableActions.filter((a) => RAIL.includes(a.kind));
  const restActions = availableActions.filter((a) => !RAIL.includes(a.kind));

  return (
    <div className="screen">
      <ScreenHeader
        title={detail.data?.reference ?? `Incident ${incidentId}`}
        subtitle={statusMeta(status).label}
        back="/incidents"
        actions={
          detail.refreshing ? (
            <Spinner />
          ) : (
            <button
              type="button"
              onClick={() => void detail.reload()}
              aria-label="Reload incident"
              className="flex h-11 w-11 items-center justify-center rounded-full text-ink-muted active:bg-surface-overlay"
            >
              <IconRefresh size={20} />
            </button>
          )
        }
      />

      {detail.status === 'loading' ? <LoadingState label="Loading incident" /> : null}
      {detail.status === 'unauthorized' ? <UnauthorizedState onRetry={() => void detail.reload()} /> : null}
      {detail.status === 'forbidden' ? <ForbiddenState permission={PERMISSION.incidentView} /> : null}
      {detail.status === 'error' && detail.error ? (
        <ErrorState error={detail.error} onRetry={() => void detail.reload()} />
      ) : null}

      {detail.data ? (
        <>
          {/* ------------------------------------------------------------ severity banner */}
          <section className="panel overflow-hidden">
            <div className={`flex items-center gap-2 px-4 py-2.5 ${sev.solid}`}>
              <span aria-hidden className={sev.solidFg}>
                <IconAlert size={17} />
              </span>
              <p className={`text-[0.78rem] font-bold uppercase tracking-[0.16em] ${sev.solidFg}`}>{sev.label}</p>
              <span className={`ml-auto text-[0.68rem] font-semibold uppercase tracking-wider ${sev.solidFg}`}>
                {timeAgo(detail.data.occurred_at)}
              </span>
            </div>

            <div className="p-4">
              <div className="flex flex-wrap items-center gap-2">
                <StatusChip status={detail.data.status} />
                <DetectionChip source={detail.data.detection_source} confidence={detail.data.confidence} />
                <span className="tabular ml-auto text-[0.68rem] text-ink-faint">{detail.data.reference}</span>
              </div>

              <h2 className="mt-2.5 text-[1.05rem] font-semibold leading-snug text-ink">{detail.data.title}</h2>

              {detectionMeta(detail.data.detection_source).isCandidate ? (
                <p className="mt-2.5 rounded-card border-l-2 border-brand bg-brand-soft p-2.5 text-[0.76rem] leading-snug text-ink-muted">
                  {DETECTION_SOURCE[detail.data.detection_source].hint} — {formatConfidence(detail.data.confidence)}.
                </p>
              ) : null}

              {detail.data.summary ? (
                <p className="mt-2.5 text-[0.85rem] leading-relaxed text-ink-muted">{detail.data.summary}</p>
              ) : null}
            </div>
          </section>

          {/* ------------------------------------------------------------ brief */}
          <SectionCard title="Incident information" className="mt-3">
            <InfoRow icon={<IconCamera size={18} />} label="Camera" value={detail.data.camera_name ?? 'Camera not recorded'} />
            <InfoRow icon={<IconPin size={18} />} label="Location" value={detail.data.campus_location ?? 'Location not recorded'} />
            <InfoRow icon={<IconClock size={18} />} label="Occurred" value={`${formatDateTime(detail.data.occurred_at)} · ${timeAgo(detail.data.occurred_at)}`} />
            {detail.data.confidence != null ? (
              <InfoRow
                icon={<IconGauge size={18} />}
                label="Model confidence"
                value={`${detail.data.confidence.toFixed(2)} — ${formatConfidence(detail.data.confidence)}`}
              />
            ) : null}
            <InfoRow
              icon={<IconInfo size={18} />}
              label="Category"
              value={
                <span className="flex flex-wrap items-center gap-2">
                  <span className="tabular">{detail.data.category}</span>
                  <span className="text-[0.7rem] text-ink-faint">recorded {formatDateTime(detail.data.created_at)}</span>
                </span>
              }
            />
            <InfoRow
              icon={<IconUser size={18} />}
              label="Acknowledged by"
              value={
                detail.data.acknowledgements.length > 0
                  ? [detail.data.acknowledgements[0]?.display_name ?? `user ${detail.data.acknowledgements[0]?.user_id}`,
                     ...detail.data.acknowledgements.slice(1).map((a) => a.display_name ?? `user ${a.user_id}`)].join(', ')
                  : 'Not acknowledged'
              }
            />
            <InfoRow
              icon={<IconShield size={18} />}
              label="Assigned to"
              value={
                detail.data.assigned_to_name ??
                (detail.data.assigned_to ? `user ${detail.data.assigned_to}` : 'Unassigned')
              }
            />
            {detail.data.escalated_to ? (
              <InfoRow
                icon={<IconEscalate size={18} />}
                label="Escalated to"
                value={detail.data.escalated_to_name ?? `user ${detail.data.escalated_to}`}
              />
            ) : null}
            {detail.data.resolved_at ? (
              <InfoRow
                icon={<IconCheckGlyph />}
                label="Resolved"
                value={formatDateTime(detail.data.resolved_at) + (detail.data.outcome ? ` · ${detail.data.outcome}` : '')}
              />
            ) : null}
          </SectionCard>

          {detail.data.resolution ? (
            <SectionCard title="Resolution" className="mt-3">
              <p className="p-4 text-[0.85rem] leading-relaxed text-ink">{detail.data.resolution}</p>
            </SectionCard>
          ) : null}

          {/* ------------------------------------------------------------ actions */}
          <section className="mt-4" aria-labelledby="response-heading">
            <h2 id="response-heading" className="section-title mb-2">
              Response
            </h2>

            {conflict ? (
              <div role="alert" className="mb-2 rounded-card border border-sev-medium/60 bg-sev-medium/10 p-3 text-[0.78rem] leading-snug text-sev-medium">
                {conflict}
              </div>
            ) : null}
            {actionError ? <ErrorState error={actionError} onRetry={() => setActionError(null)} /> : null}

            {availableActions.length === 0 ? (
              <div className="panel p-4 text-[0.78rem] leading-snug text-ink-muted">
                Your account holds none of the response permissions for this incident
                ({PERMISSION.incidentAcknowledge}, {PERMISSION.incidentEscalate}, {PERMISSION.incidentResolve}). The record
                above is still complete, and viewing it is itself audited.
              </div>
            ) : (
              <>
                <div className="grid grid-cols-3 gap-2">
                  {railActions.map((a) => (
                    <ActionButton
                      key={a.kind}
                      variant={a.kind === 'acknowledge' ? 'primary' : a.kind === 'escalate' ? 'danger' : 'secondary'}
                      onClick={() => openSheet(a)}
                      data-testid={`action-${a.kind}`}
                      className="min-h-[64px] flex-col gap-1 px-1 text-[0.72rem] leading-tight"
                    >
                      <span aria-hidden className="flex justify-center">
                        {ACTION_ICON[a.kind]}
                      </span>
                      {a.title}
                    </ActionButton>
                  ))}
                </div>
                {restActions.length > 0 ? (
                  <div className="mt-2 grid grid-cols-2 gap-2">
                    {restActions.map((a) => (
                      <ActionButton
                        key={a.kind}
                        variant={a.kind === 'reopen' ? 'danger' : 'ghost'}
                        onClick={() => openSheet(a)}
                        data-testid={`action-${a.kind}`}
                      >
                        <span aria-hidden className="mr-1.5 inline-flex align-[-3px]">
                          {ACTION_ICON[a.kind]}
                        </span>
                        {a.title}
                      </ActionButton>
                    ))}
                  </div>
                ) : null}
              </>
            )}

            <p className="mt-2 text-[0.7rem] leading-snug text-ink-faint">
              Buttons appear because of your permission set, but the server decides every action. If a grant was removed or
              another operator advanced this incident first, the request is rejected and you will see exactly that above the
              history.
            </p>

            {detail.data.status === 'false_positive' ? (
              <p className="mt-2 rounded-card border border-surface-line bg-surface-raised p-3 text-[0.74rem] leading-snug text-ink-muted">
                A false positive is a final decision in this database: the server refuses to reopen this state for any
                account. If the behaviour is seen again, raise a new incident that points at this record.
              </p>
            ) : null}
          </section>

          {/* ------------------------------------------------------------ evidence */}
          <EvidencePanel incidentId={incidentId} />

          {/* ------------------------------------------------------------ activity */}
          <div ref={activityRef}>
            <section className="mt-4" aria-labelledby="activity-heading">
              <div className="mb-2 flex items-center justify-between gap-2">
                <h2 id="activity-heading" className="section-title">
                  Activity history
                </h2>
                <button
                  type="button"
                  onClick={() => navigate(`/incidents/${incidentId}/notes`)}
                  data-testid="open-notes"
                  className="flex items-center gap-1 text-[0.72rem] font-semibold uppercase tracking-wider text-brand"
                >
                  <IconNote size={15} />
                  Investigation notes
                </button>
              </div>

              {activity.status === 'loading' ? <LoadingState label="Loading history" /> : null}
              {activity.status === 'error' && activity.error ? (
                <ErrorState error={activity.error} onRetry={() => void activity.reload()} />
              ) : null}

              {activity.data ? (
                activity.data.items.length === 0 ? (
                  <div className="panel p-4 text-[0.78rem] leading-snug text-ink-muted">
                    No recorded actions on this incident. Every acknowledgement, note, escalation and
                    decision the service accepts appears here with its author.
                  </div>
                ) : (
                  <ol className="panel divide-y divide-surface-line">
                    {/* Newest first, which is what the route returns: `ORDER BY id DESC`. */}
                    {activity.data.items.map((entry) => (
                      <li key={entry.id} className="p-3.5">
                        <div className="flex flex-wrap items-center gap-2">
                          <Chip
                            tone={
                              entry.action === 'resolved'
                                ? 'ok'
                                : entry.action === 'escalated' || entry.action === 'reopened'
                                  ? 'bad'
                                  : 'neutral'
                            }
                          >
                            {activityActionLabel(entry.action)}
                          </Chip>
                          <span className="tabular ml-auto text-[0.66rem] text-ink-faint">
                            {timeAgo(entry.created_at)}
                          </span>
                        </div>
                        <p className="mt-1.5 text-[0.78rem] leading-snug text-ink">
                          <span className="font-semibold">{actorLabel(entry)}</span>
                          {entry.note ? <span className="text-ink-muted"> — {entry.note}</span> : null}
                        </p>
                        <p className="tabular mt-0.5 text-[0.64rem] text-ink-faint">
                          {formatDateTime(entry.created_at)}
                        </p>
                      </li>
                    ))}
                  </ol>
                )
              ) : null}
            </section>
          </div>

          <div className="mt-4 flex items-center justify-between border-t border-surface-line pt-3 text-[0.7rem] text-ink-faint">
            <span className="tabular">
              sev {detail.data.severity} · {SEVERITY[detail.data.severity]?.label ?? 'Unclassified'}
            </span>
            <span className="tabular">{detail.data.reference}</span>
          </div>
        </>
      ) : null}

      {/* ------------------------------------------------------------ action sheet */}
      {pending ? (
        <Sheet title={pending.title} onClose={() => setPending(null)} testId={`sheet-${pending.kind}`}>
          <p className="text-[0.78rem] leading-snug text-ink-muted">{pending.blurb}</p>

          {pending.kind === 'resolve' ? (
            <div className="mt-4 space-y-3">
              <Field label="Outcome" htmlFor="outcome">
                <Select id="outcome" value={outcome} onChange={(e) => setOutcome(e.target.value as IncidentOutcome)}>
                  {OUTCOMES.map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </Select>
              </Field>
              <label className="flex items-start gap-2 text-[0.76rem] leading-snug text-ink-muted">
                <input
                  type="checkbox"
                  className="mt-0.5 h-4 w-4 accent-brand"
                  checked={falsePositive}
                  onChange={(e) => setFalsePositive(e.target.checked)}
                  data-testid="false-positive"
                />
                <span>
                  Record as a false positive. The service then closes the incident in the{' '}
                  <span className="tabular">false_positive</span> state rather than{' '}
                  <span className="tabular">resolved</span>, which is what keeps an AI candidate
                  that was never real out of the confirmed-incident statistics.
                </span>
              </label>
            </div>
          ) : null}

          {pending.kind === 'escalate' ? (
            <div className="mt-4">
              <Field
                label="Escalate to role"
                htmlFor="to_role"
                hint="The server picks the first active account holding that role, other than you. A role nobody holds is refused, not silently skipped."
              >
                <Select id="to_role" value={escalateRole} onChange={(e) => setEscalateRole(e.target.value)}>
                  {ESCALATION_ROLES.map((code) => (
                    <option key={code} value={code}>
                      {code}
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
          ) : null}

          <div className="mt-4">
            <Field
              label={pending.kind === 'resolve' ? 'Resolution' : pending.kind === 'escalate' ? 'Reason' : 'Note'}
              htmlFor="action-note"
              hint={pending.noteRequired ? 'Required — this text becomes part of the record.' : 'Optional.'}
            >
              <textarea
                id="action-note"
                className="field-input min-h-[96px]"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                maxLength={2000}
              />
            </Field>
          </div>

          <div className="mt-4 flex gap-2">
            <ActionButton
              variant={pending.kind === 'escalate' || pending.kind === 'reopen' ? 'danger' : 'primary'}
              full
              busy={submitting}
              disabled={pending.noteRequired && note.trim().length === 0}
              onClick={() => void runAction(pending.kind)}
              data-testid="confirm-action"
            >
              Confirm
            </ActionButton>
            <ActionButton variant="ghost" onClick={() => setPending(null)} disabled={submitting}>
              Cancel
            </ActionButton>
          </div>
        </Sheet>
      ) : null}

      {/* ------------------------------------------------------------ acknowledgement receipt */}
      {acknowledged && !pending ? (
        <Sheet title="Acknowledged" onClose={() => setAcknowledged(false)} testId="acknowledgement-sheet">
          <ConfirmationMark />
          <p className="mt-3 text-center text-[1rem] font-semibold text-ink">Acknowledgement sent</p>
          <p className="mt-1 text-center text-[0.78rem] leading-snug text-ink-muted">
            Recorded against <span className="tabular">{detail.data?.reference}</span>, which is now{' '}
            {statusMeta(detail.data?.status ?? 'investigating').label}. The acknowledgement and its timestamp are held in the
            incident record, not on this device.
          </p>

          <div className="mt-5">
            <p className="section-title mb-1">Next actions</p>
            <div className="panel divide-y divide-surface-line">
              <button
                type="button"
                onClick={() => {
                  setAcknowledged(false);
                  navigate(`/incidents/${incidentId}/notes`);
                }}
                data-testid="next-notes"
                className="menu-row"
              >
                <span aria-hidden className="shrink-0 text-brand">
                  <IconNote size={18} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block font-medium text-ink">Add investigation notes</span>
                  <span className="mt-0.5 block text-[0.74rem] font-normal text-ink-faint">
                    What you saw, what you did, who you spoke to
                  </span>
                </span>
                <span aria-hidden className="shrink-0 text-ink-faint">
                  <IconChevronRight size={18} />
                </span>
              </button>
              {actionable(sessionState.user, 'escalate') ? (
                <button
                  type="button"
                  onClick={() => {
                    setAcknowledged(false);
                    const escalate = availableActions.find((a) => a.kind === 'escalate');
                    if (escalate) openSheet(escalate);
                  }}
                  data-testid="next-escalate"
                  className="menu-row text-sev-critical"
                >
                  <span aria-hidden className="shrink-0">
                    <IconEscalate size={18} />
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block font-medium">Escalate to a supervisor</span>
                    <span className="mt-0.5 block text-[0.74rem] font-normal text-ink-faint">
                      If this needs rank behind it
                    </span>
                  </span>
                  <span aria-hidden className="shrink-0 text-ink-faint">
                    <IconChevronRight size={18} />
                  </span>
                </button>
              ) : null}
              <button
                type="button"
                onClick={() => {
                  setAcknowledged(false);
                  activityRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' });
                }}
                data-testid="next-timeline"
                className="menu-row"
              >
                <span aria-hidden className="shrink-0 text-brand">
                  <IconClock size={18} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block font-medium text-ink">View the timeline</span>
                  <span className="mt-0.5 block text-[0.74rem] font-normal text-ink-faint">
                    Every action on this incident, newest first
                  </span>
                </span>
                <span aria-hidden className="shrink-0 text-ink-faint">
                  <IconChevronRight size={18} />
                </span>
              </button>
            </div>
          </div>

          <ActionButton variant="primary" full className="mt-5" onClick={() => setAcknowledged(false)} data-testid="ack-done">
            Done
          </ActionButton>
        </Sheet>
      ) : null}
    </div>
  );
}
