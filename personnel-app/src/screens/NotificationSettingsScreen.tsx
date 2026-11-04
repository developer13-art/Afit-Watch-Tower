/**
 * Notification settings (§8.2).
 *
 * The `forced` array from the server is the whole point of this screen: a duty
 * alert that a user could quietly switch off is not a duty alert. Forced
 * toggles are rendered greyed-out with the reason. Nothing is rewritten on the
 * way out, because the server exempts a forced alert from the severity floor,
 * the kind toggles and quiet hours before it reads any of them
 * (`cloud/targeting.py apply_preferences`) — so the form sends exactly what the
 * officer chose and a forced alert arrives whatever they chose.
 *
 * Only the four fields `PUT /profile/preferences` accepts are editable here —
 * `min_severity`, `kinds`, `quiet_hours`, `sound`. The mockup's digest mode,
 * per-channel (e-mail/SMS) switches and "system update" alerts have no backing
 * in the contract, so they are absent rather than decorative.
 */
import { useEffect, useMemo, useState } from 'react';
import { profileApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import type { NotificationPreferencesResponse, Severity } from '../types/api';
import { SEVERITY, SEVERITY_ORDER, soundOptionsFor } from '../lib/severity';
import { ActionButton, FilterChip, IconBadge, SectionCard, Select, Spinner, TextInput, Toggle } from '../components/ui';
import { AsyncBoundary, ErrorState } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { isValidHhmm } from '../lib/time';
import { IconAlert, IconBell, IconClock, IconGauge, IconRefresh } from '../components/icons';

/** The six kinds the service recognises (`profile.py KNOWN_KINDS`); anything else shows its raw key. */
const KIND_LABELS: Record<string, string> = {
  'incident.created': 'New incidents raised',
  'incident.assigned': 'Incidents assigned to me',
  'incident.escalated': 'Escalations to me',
  'incident.resolved': 'Resolution notices',
  'camera.health': 'Camera health alerts',
  'event.new': 'Raw detection events',
};

const KIND_NOTES: Record<string, string> = {
  'camera.health': 'A camera going quiet or failing its test pattern.',
  'event.new': 'Every candidate detection, not only those raised as incidents. Noisy: switch it off unless you review detections directly.',
};

/**
 * The six kinds the service recognises (`profile.py KNOWN_KINDS`), in the order they are listed.
 *
 * `GET /profile/preferences` returns only the kinds this account has overridden, and delivery
 * suppresses a kind only when it is present and `false` (`cloud/targeting.py`), so an absent kind
 * is an enabled one. The vocabulary therefore lives here instead of arriving with the response —
 * rendering the stored map alone would show an officer who had never touched the screen an empty
 * list of switches and imply the service offered none. A kind the server starts sending that is
 * not on this list still gets a row, under its raw key, so an addition is visible rather than
 * silently dropped.
 */
const KIND_ORDER = [
  'incident.created',
  'incident.assigned',
  'incident.escalated',
  'incident.resolved',
  'camera.health',
  'event.new',
];

export function kindRows(kinds: Record<string, boolean> | undefined) {
  const stored = kinds ?? {};
  return [...KIND_ORDER, ...Object.keys(stored).filter((kind) => !KIND_ORDER.includes(kind))].map(
    (kind) => ({ kind, enabled: stored[kind] !== false }),
  );
}

export function NotificationSettingsScreen() {
  const prefs = useAsync<NotificationPreferencesResponse>(() => profileApi.preferences(), []);
  const [draft, setDraft] = useState<NotificationPreferencesResponse | null>(null);
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<ApiError | null>(null);
  const [savedAt, setSavedAt] = useState<string | null>(null);

  useEffect(() => {
    if (prefs.data) setDraft(structuredClone(prefs.data));
  }, [prefs.data]);

  const forced = useMemo(() => new Set(draft?.forced ?? prefs.data?.forced ?? []), [draft, prefs.data]);
  const isForcedSeverity = (s: Severity) => forced.has(s);
  const forcedSeverities = SEVERITY_ORDER.filter((s) => forced.has(s));

  if (!draft) {
    return (
      <div className="screen">
        <ScreenHeader title="Notification preferences" back="/profile" />
        <AsyncBoundary state={prefs} loadingLabel="Loading preferences">
          {() => <Spinner label="Preparing form" />}
        </AsyncBoundary>
      </div>
    );
  }

  const dirty = JSON.stringify(draft) !== JSON.stringify(prefs.data);

  const save = async () => {
    if (!draft) return;
    setSaving(true);
    setSaveError(null);
    try {
      // What the officer chose is sent unchanged. A forced severity or kind is delivered by the
      // server before it ever reads the floor, the toggles or quiet hours
      // (`cloud/targeting.py apply_preferences`), so raising the floor cannot hide a duty alert
      // and there is nothing here for the form to re-assert on the server's behalf.
      const body = {
        min_severity: draft.min_severity,
        kinds: { ...draft.kinds },
        quiet_hours: draft.quiet_hours,
        sound: draft.sound,
      };
      const res = await profileApi.savePreferences(body);
      setDraft(structuredClone(res));
      prefs.setData(() => res);
      setSavedAt(new Date().toISOString());
    } catch (err) {
      setSaveError(
        err instanceof ApiError ? err : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Could not save preferences.' }),
      );
    } finally {
      setSaving(false);
    }
  };

  const quietInvalid = draft.quiet_hours.enabled && (!isValidHhmm(draft.quiet_hours.start) || !isValidHhmm(draft.quiet_hours.end));

  return (
    <div className="screen">
      <ScreenHeader
        title="Notification preferences"
        subtitle="Applies to this account on every device"
        back="/profile"
        actions={
          prefs.refreshing ? (
            <Spinner />
          ) : (
            <button
              type="button"
              onClick={() => void prefs.reload()}
              aria-label="Reload preferences"
              className="flex h-11 w-11 items-center justify-center rounded-full text-ink-muted active:bg-surface-overlay"
            >
              <IconRefresh size={19} />
            </button>
          )
        }
      />

      {saveError ? <ErrorState error={saveError} onRetry={() => setSaveError(null)} /> : null}
      {savedAt && !dirty ? (
        <p
          role="status"
          className="mb-3 flex items-center gap-2 rounded-card border border-state-ok/50 bg-state-ok/10 px-3 py-2.5 text-[0.78rem] text-state-ok"
        >
          <IconBell size={16} aria-hidden />
          Saved. The server confirmed your effective preferences.
        </p>
      ) : null}

      {draft.forced.length > 0 ? (
        <div
          role="note"
          data-testid="forced-explanation"
          className="mb-3 flex items-start gap-3 rounded-card border border-sev-medium/50 bg-sev-medium/10 p-3"
        >
          <span aria-hidden className="mt-[2px] shrink-0 text-sev-medium">
            <IconAlert size={18} />
          </span>
          <div className="min-w-0">
            <p className="text-[0.8rem] font-bold uppercase tracking-wider text-sev-medium">Mandatory alerts</p>
            <p className="mt-1 text-[0.76rem] leading-snug text-ink-muted">
              Switched on by the organisation&apos;s notification policy and not yours to turn off: {draft.forced.join(', ')}.
              They stay greyed out below so you always know which alerts are yours to control and which are a duty
              obligation.
            </p>
          </div>
        </div>
      ) : null}

      <AsyncBoundary state={prefs} loadingLabel="Loading preferences">
        {(current) => (
          <div className="space-y-3">
            <SectionCard
              title="Minimum severity"
              action={<IconBadge tone="brand"><IconAlert size={17} /></IconBadge>}
            >
              <div className="p-4">
                <div className="flex flex-wrap gap-2">
                  {SEVERITY_ORDER.map((s) => (
                    <FilterChip
                      key={s}
                      active={draft.min_severity === s}
                      testId={`min-severity-${s}`}
                      onClick={() => setDraft({ ...draft, min_severity: s })}
                    >
                      {SEVERITY[s].label}
                      {isForcedSeverity(s) ? ' · forced' : ''}
                    </FilterChip>
                  ))}
                </div>
                <p className="mt-3 text-[0.75rem] leading-snug text-ink-faint">
                  Anything below this band is not pushed to your devices; it stays in the alert
                  centre.{' '}
                  {forcedSeverities.length > 0
                    ? `${forcedSeverities.map((s) => SEVERITY[s].label).join(' and ')} alerts are delivered whatever this is set to, so choosing a higher band quiets the rest, not those.`
                    : 'No severity is forced by policy on this deployment.'}
                </p>
              </div>
            </SectionCard>

            <SectionCard title="What reaches you" action={<IconBadge tone="brand"><IconBell size={17} /></IconBadge>}>
              <div className="px-4 pb-2 pt-1">
                {kindRows(draft.kinds).map(({ kind, enabled }) => (
                  <Toggle
                    key={kind}
                    label={KIND_LABELS[kind] ?? kind}
                    description={KIND_NOTES[kind] ?? kind}
                    checked={forced.has(kind) ? true : enabled}
                    disabled={forced.has(kind)}
                    disabledReason="Delivered regardless of your choice."
                    testId={`toggle-${kind}`}
                    onChange={(next) => setDraft({ ...draft, kinds: { ...draft.kinds, [kind]: next } })}
                  />
                ))}
              </div>
            </SectionCard>

            <SectionCard title="Quiet hours" action={<IconBadge tone="neutral"><IconClock size={17} /></IconBadge>}>
              <div className="px-4 pb-4 pt-1">
                <Toggle
                  label="Suppress non-mandatory alerts in a window"
                  description="Critical and escalated alerts ignore this completely."
                  checked={draft.quiet_hours.enabled}
                  testId="toggle-quiet-hours"
                  onChange={(next) => setDraft({ ...draft, quiet_hours: { ...draft.quiet_hours, enabled: next } })}
                />
                {draft.quiet_hours.enabled ? (
                  <div className="mt-3">
                    <div className="grid grid-cols-2 gap-2">
                      <label className="block">
                        <span className="label">Start</span>
                        <TextInput
                          type="time"
                          value={draft.quiet_hours.start}
                          onChange={(e) => setDraft({ ...draft, quiet_hours: { ...draft.quiet_hours, start: e.target.value } })}
                        />
                        {!isValidHhmm(draft.quiet_hours.start) ? (
                          <span className="mt-1 block text-[0.74rem] text-sev-critical">Use 24-hour HH:mm.</span>
                        ) : null}
                      </label>
                      <label className="block">
                        <span className="label">End</span>
                        <TextInput
                          type="time"
                          value={draft.quiet_hours.end}
                          onChange={(e) => setDraft({ ...draft, quiet_hours: { ...draft.quiet_hours, end: e.target.value } })}
                        />
                        {!isValidHhmm(draft.quiet_hours.end) ? (
                          <span className="mt-1 block text-[0.74rem] text-sev-critical">Use 24-hour HH:mm.</span>
                        ) : null}
                      </label>
                    </div>
                    <p className="mt-2 text-[0.7rem] leading-snug text-ink-faint">
                      Measured on the server&apos;s clock in UTC (WAT is UTC+1), because that is the clock the delivery
                      worker compares these two times against. Set the window an hour ahead of the hours you mean locally.
                    </p>
                  </div>
                ) : null}
              </div>
            </SectionCard>

            <SectionCard title="Sound" action={<IconBadge tone="neutral"><IconGauge size={17} /></IconBadge>}>
              <div className="p-4">
                <span className="label">Ring tone policy</span>
                <Select
                  value={draft.sound}
                  onChange={(e) => setDraft({ ...draft, sound: e.target.value })}
                  className="mt-1"
                >
                  {soundOptionsFor(draft.sound).map((o) => (
                    <option key={o.value} value={o.value}>
                      {o.label}
                    </option>
                  ))}
                </Select>
                <p className="mt-2 text-[0.72rem] leading-snug text-ink-faint">
                  A silent choice is applied by the server to every alert your account is allowed to quiet. A critical or
                  escalated alert is sent with sound regardless, and the tone for each severity band is set in
                  Android&apos;s own notification settings.
                </p>
              </div>
            </SectionCard>

            <div className="flex items-center gap-2">
              <ActionButton variant="primary" full busy={saving} disabled={!dirty || quietInvalid} onClick={() => void save()}>
                Save preferences
              </ActionButton>
              <ActionButton variant="ghost" disabled={saving || !dirty} onClick={() => setDraft(structuredClone(current))}>
                Discard
              </ActionButton>
            </div>
            {dirty ? (
              <p className="text-[0.72rem] text-ink-faint">
                Unsaved changes on this device only — nothing is delivered differently until you save.
              </p>
            ) : null}
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}
