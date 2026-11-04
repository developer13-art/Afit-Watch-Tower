/**
 * Device status (§8.1, §11).
 *
 * The mockup's "FCM Connected" badge is not rendered, because nothing in this
 * build can know that. What is shown instead is the three facts the app really
 * holds: the platform's answer about notification permission, whether a push
 * token was obtained, and what the service has recorded for this installation.
 * When Firebase is unconfigured the screen says so and points at the two paths
 * that still deliver alerts — the foreground poll and the live channel.
 */
import { useState } from 'react';
import { devicesApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import type { DeviceListItem } from '../types/api';
import { ActionButton, Chip, IconBadge, InfoRow, SectionCard } from '../components/ui';
import { ErrorState, LoadingState } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { useSession } from '../auth/SessionProvider';
import { env, firebaseWebConfig } from '../config/env';
import { formatDateTime, timeAgo } from '../lib/time';
import { IconAlert, IconBell, IconCheck, IconDevice, IconSignal } from '../components/icons';

function pushTone(registered: boolean, permission: string): 'ok' | 'warn' | 'bad' {
  if (permission === 'denied') return 'bad';
  if (registered && permission === 'granted') return 'ok';
  return 'warn';
}

export function DeviceStatusScreen() {
  const { state, app, enablePush, logout } = useSession();
  const devices = useAsync(() => devicesApi.list(), [state.revision]);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [confirmForget, setConfirmForget] = useState(false);

  const firebase = firebaseWebConfig();
  const here = app?.installationId ?? null;
  const rows = devices.data?.items ?? [];
  const thisRow = rows.find((d) => d.installation_id === here) ?? null;

  const revoke = async (device: DeviceListItem) => {
    setBusyId(device.installation_id);
    setActionError(null);
    try {
      await devicesApi.revoke(device.installation_id);
      // `revoked` is what the server persists — `deactivate()` sets `PushState.REVOKED`,
      // not an "inactive" flag.
      devices.setData((current) =>
        current
          ? {
              ...current,
              items: current.items.map((d) =>
                d.installation_id === device.installation_id
                  ? { ...d, push_state: 'revoked' as const, push_capable: false }
                  : d,
              ),
            }
          : current,
      );
    } catch (err) {
      setActionError(
        err instanceof ApiError ? err : new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Could not revoke the device.' }),
      );
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="screen">
      <ScreenHeader
        title="Device status"
        subtitle={here ? `Installation ${here.slice(0, 8)}` : 'This build has no installation id yet'}
        back="/profile"
        actions={
          <button
            type="button"
            onClick={() => void devices.reload()}
            aria-label="Reload devices"
            className="flex h-11 w-11 items-center justify-center rounded-full text-ink-muted active:bg-surface-overlay"
          >
            <IconSignal size={19} />
          </button>
        }
      />

      {actionError ? <ErrorState error={actionError} onRetry={() => setActionError(null)} /> : null}

      {/* ------------------------------------------------------------ this handset */}
      <SectionCard title="This handset">
        <div className="flex items-start gap-3 p-4">
          <IconBadge tone={pushTone(state.push.registered, state.push.permission)}>
            <IconBell size={18} />
          </IconBadge>
          <div className="min-w-0 flex-1">
            <p className="text-[0.92rem] font-semibold text-ink">
              {state.push.permission === 'denied'
                ? 'Notifications are turned off for this app'
                : state.push.registered
                  ? 'Registered for duty alerts'
                  : state.push.registering
                    ? 'Registering this device…'
                    : 'Not registered for push'}
            </p>
            <p className="mt-1 text-[0.76rem] leading-snug text-ink-muted">
              {state.push.permission === 'unsupported'
                ? 'This platform gives the app no push service to register with — the web build, or a handset without Google Play services.'
                : state.push.permission === 'denied'
                  ? 'Android will not deliver duty alerts until they are enabled: Settings → Apps → AFIT WATCH TOWER → Notifications → Allow.'
                  : state.push.registrationError
                    ? `Last registration attempt: ${state.push.registrationError}`
                    : state.push.registered
                      ? 'The service holds a token for this installation and will target it for your scope.'
                      : 'Alerts still reach you while the app is open, through the live channel and the foreground refresh.'}
            </p>
            {!state.push.registered && state.push.permission !== 'unsupported' && state.push.permission !== 'denied' ? (
              <ActionButton variant="secondary" className="mt-2.5" onClick={() => void enablePush()}>
                Enable notifications
              </ActionButton>
            ) : null}
          </div>
        </div>

        <InfoRow
          icon={<IconDevice size={18} />}
          label="Push service configuration"
          value={
            firebase
              ? `A Firebase project is configured (${firebase.projectId}). Whether a delivery has reached a handset is the server's answer, not this screen's.`
              : env.liveFeedEnabled
                ? 'No Firebase project is configured in this build, so no push token exists and none is claimed here. Alerts reach an open app through the live channel and the refresh poll.'
                : 'No Firebase project is configured in this build, so no push token exists and none is claimed here. Alerts reach an open app only through the foreground refresh.'
          }
        />
        <InfoRow
          icon={<IconSignal size={18} />}
          label="Live updates"
          value={
            state.online
              ? liveCopy(state.push.registered)
              : 'This device is offline. The values on this screen are from the last successful read.'
          }
        />
        <InfoRow
          icon={<IconAlert size={18} />}
          label="Foreground refresh"
          value={
            env.alertPollMs > 0
              ? `Every ${Math.round(env.alertPollMs / 1000)}s while the app is open, against ${env.apiUrl}.`
              : 'Disabled (VITE_ALERT_POLL_SECONDS=0): the lists only move on pull-to-refresh and the Refresh button.'
          }
        />
        {state.storageWarning ? (
          <InfoRow icon={<IconAlert size={18} />} label="Storage" value={state.storageWarning} />
        ) : null}
      </SectionCard>

      {/* ------------------------------------------------------------ registered devices */}
      <SectionCard title="Devices on your account" className="mt-3">
        {devices.status === 'loading' ? (
          <div className="p-4">
            <LoadingState label="Loading devices" />
          </div>
        ) : null}
        {devices.status === 'error' && devices.error ? (
          <div className="p-4">
            <ErrorState error={devices.error} onRetry={() => void devices.reload()} />
          </div>
        ) : null}
        {devices.status === 'forbidden' ? (
          <p className="p-4 text-[0.78rem] leading-snug text-ink-muted">
            Your account cannot read the device list. The status of this handset above is still what the app observed locally.
          </p>
        ) : null}

        {devices.data ? (
          rows.length === 0 ? (
            <p className="p-4 text-[0.78rem] leading-snug text-ink-muted">
              No device row has been recorded for this account. Signing in from the Android build creates the first one.
            </p>
          ) : (
            <ul className="divide-y divide-surface-line">
              {rows.map((d) => (
                <li key={d.id} className="flex items-start gap-3 p-4">
                  <IconBadge tone={d.push_state === 'active' && d.push_capable ? 'ok' : d.push_state === 'invalid' ? 'bad' : 'neutral'}>
                    <IconDevice size={17} />
                  </IconBadge>
                  <div className="min-w-0 flex-1">
                    <p className="text-[0.88rem] font-medium text-ink">
                      {d.model ?? d.platform}
                      {here && d.installation_id === here ? (
                        <span className="ml-2 text-[0.68rem] uppercase tracking-wider text-brand">this device</span>
                      ) : null}
                    </p>
                    <p className="tabular mt-0.5 text-[0.68rem] text-ink-faint">
                      {d.installation_id.slice(0, 13)}… · {d.platform} {d.os_version ?? ''} · app {d.app_version ?? '—'}
                    </p>
                    <p className="mt-1 text-[0.72rem] text-ink-muted">
                      Seen {timeAgo(d.last_seen_at)} · registered {formatDateTime(d.registered_at)}
                    </p>
                    <div className="mt-1.5 flex flex-wrap gap-1.5">
                      <Chip tone={d.push_state === 'active' ? 'ok' : d.push_state === 'invalid' ? 'bad' : 'neutral'}>
                        push {d.push_state}
                      </Chip>
                      <Chip tone={d.push_capable ? 'brand' : 'neutral'}>
                        {d.push_capable ? 'token on file' : 'no token'}
                      </Chip>
                    </div>
                  </div>
                  {d.push_state === 'active' ? (
                    <ActionButton
                      variant="danger"
                      busy={busyId === d.installation_id}
                      onClick={() => void revoke(d)}
                      className="px-3 py-2 text-[0.72rem]"
                    >
                      Revoke
                    </ActionButton>
                  ) : null}
                </li>
              ))}
            </ul>
          )
        ) : null}

        <p className="border-t border-surface-line p-4 text-[0.72rem] leading-snug text-ink-faint">
          Revoking deactivates push targeting for that installation immediately and revokes the sessions minted from it; the
          row is kept for the audit trail.
        </p>
      </SectionCard>

      {/* ------------------------------------------------------------ forget this device */}
      <SectionCard title="Forget this handset" className="mt-3">
        <div className="p-4">
          {!confirmForget ? (
            <>
              <p className="text-[0.8rem] leading-snug text-ink-muted">
                Signs out and tells the service to stop targeting this installation, so the next person to hold the phone
                needs credentials before alerts resume.
              </p>
              <ActionButton variant="danger" full className="mt-3" onClick={() => setConfirmForget(true)}>
                Sign out and forget this device
              </ActionButton>
            </>
          ) : (
            <div role="alert">
              <p className="text-[0.85rem] font-semibold text-sev-critical">
                {thisRow ? `Forget ${thisRow.model ?? thisRow.platform}?` : 'Forget this installation?'}
              </p>
              <p className="mt-1 text-[0.76rem] leading-snug text-ink-muted">
                The session is revoked and this handset stops receiving push until it signs in again. Anyone using this phone
                will need the account credentials to restore alerts.
              </p>
              <div className="mt-3 grid grid-cols-2 gap-2">
                <ActionButton variant="ghost" onClick={() => setConfirmForget(false)}>
                  Cancel
                </ActionButton>
                <ActionButton variant="danger" onClick={() => void logout({ forgetDevice: true })} data-testid="confirm-forget">
                  <span className="inline-flex items-center gap-1.5">
                    <IconCheck size={16} aria-hidden />
                    Confirm
                  </span>
                </ActionButton>
              </div>
            </div>
          )}
        </div>
      </SectionCard>
    </div>
  );
}

/** Live-channel wording, without claiming a delivery this screen cannot observe. */
function liveCopy(registered: boolean): string {
  if (env.fixturesEnabled) {
    return 'This build reads scripted fixture data, so no service is being contacted and no live channel is open.';
  }
  if (!env.liveFeedEnabled) {
    return `Alerts on this device arrive through the foreground refresh against ${env.apiUrl}; the live channel is turned off in this build (VITE_LIVE_FEED=0).`;
  }
  const delivery = registered ? 'Push and the live channel are both available.' : 'The live channel is the fast path on this device.';
  return `Reads come from ${env.apiUrl}. ${delivery} A quiet screen therefore means nothing matched your scope, not that the link is down.`;
}
