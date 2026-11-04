/**
 * Application shell: header, banners, bottom tab bar, foreground alert stack.
 *
 * The banners are not decoration. Each one states a limitation the operator
 * must know before trusting what they see: fixture data, non-secure storage,
 * offline, an unregistered push device, or an insecure API host. Restyling them
 * changes their shape and never their wording: a warning that reads prettier but
 * says less is worse than no warning.
 */
import type { ReactNode } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { apiConfig, env, isInsecureApiHost } from '../config/env';
import { useSession } from '../auth/SessionProvider';
import { severityMeta } from '../lib/severity';
import { ActionButton } from './ui';
import { IconAlert, IconBell, IconCheck, IconChevronLeft, IconClose, IconHome, IconInfo, IconShield, IconUser } from './icons';

/** A banner body with its own leading glyph, so the icon never carries meaning alone. */
function Banner({
  tone,
  testId,
  title,
  children,
  dismissible,
}: {
  tone: 'warn' | 'bad' | 'info';
  testId?: string;
  title?: string;
  children: ReactNode;
  dismissible?: ReactNode;
}) {
  const look =
    tone === 'bad'
      ? 'border-sev-critical/50 bg-sev-critical/12 text-sev-critical'
      : tone === 'warn'
        ? 'border-sev-medium/50 bg-sev-medium/12 text-sev-medium'
        : 'border-surface-line bg-surface-card text-ink-muted';
  const Glyph = tone === 'info' ? IconInfo : IconAlert;
  return (
    <div
      role={tone === 'info' ? 'status' : 'alert'}
      data-testid={testId}
      className={`mx-auto mb-2 flex w-full max-w-[560px] items-start gap-2.5 rounded-card border px-3 py-2.5 text-[0.76rem] leading-snug ${look}`}
    >
      <span aria-hidden className="mt-[1px] shrink-0">
        <Glyph size={17} />
      </span>
      <div className="min-w-0 flex-1">
        {title ? <p className="font-bold uppercase tracking-wider">{title} — </p> : null}
        <span>{children}</span>
      </div>
      {dismissible}
    </div>
  );
}

export function FixtureBanner() {
  if (!env.fixturesEnabled) return null;
  return (
    <Banner tone="warn" testId="fixture-banner" title="Fixture data">
      not live — this build is reading scripted data, not the service
    </Banner>
  );
}

export function StorageBanner() {
  const { state } = useSession();
  if (!state.storageWarning) return null;
  return (
    <Banner tone="bad" testId="storage-banner" title="Storage warning">
      {state.storageWarning}
    </Banner>
  );
}

export function OfflineBanner() {
  const { state } = useSession();
  if (state.online) return null;
  return (
    <Banner tone="info" testId="offline-banner">
      Offline. The records below are the last response from the service; they may be out of date.
    </Banner>
  );
}

export function InsecureHostBanner() {
  if (apiConfig.state === 'unconfigured') {
    return (
      <Banner tone="bad" title="No server configured" testId="unconfigured-banner">
        This build has no cloud API endpoint, so it cannot sign anyone in or show any records.{' '}
        {apiConfig.reason}
      </Banner>
    );
  }
  if (!isInsecureApiHost()) return null;
  return (
    <Banner tone="bad" title="Insecure endpoint" testId="insecure-banner">
      {apiConfig.reason} Contract §0 requires HTTPS; do not sign in to real accounts on this build.
      {apiConfig.blocksSignIn ? ' Sign-in is blocked on this build.' : ''}
    </Banner>
  );
}

export function PushStatusBanner() {
  const { state, enablePush } = useSession();
  if (env.fixturesEnabled) return null;
  if (state.push.permission === 'granted' && state.push.registered) return null;

  if (state.push.permission === 'unsupported') {
    return (
      <Banner tone="info">
        Push delivery is unavailable on this platform. Duty alerts still appear in the notification
        centre while the app is open.
      </Banner>
    );
  }

  if (state.push.permission === 'denied') {
    return (
      <Banner tone="warn" title="Notifications off">
        <span className="block">Android will not deliver duty alerts until they are enabled: Settings → Apps → AFIT WATCH TOWER → Notifications → Allow.</span>
        <span className="mt-1 block">Critical alerts cannot be muted by policy, so a denied permission here means they are missed entirely.</span>
        <ActionButton variant="secondary" className="mt-2" onClick={() => void enablePush()}>
          Request again
        </ActionButton>
      </Banner>
    );
  }

  return (
    <Banner tone="info">
      <p>
        {state.push.registering
          ? 'Registering this device for duty alerts…'
          : state.push.registrationError
            ? `Push registration problem: ${state.push.registrationError}`
            : 'This device is not yet registered for duty alerts.'}
      </p>
      {!state.push.registering && !state.push.registered ? (
        <ActionButton variant="secondary" className="mt-2" onClick={() => void enablePush()}>
          Enable notifications
        </ActionButton>
      ) : null}
    </Banner>
  );
}

/**
 * The live channel's state, in one line (contract §10.8).
 *
 * It is never hidden, including when everything works. An officer who has learned that a red
 * banner means trouble has to be able to tell "live" from "quietly falling back to the poll", or
 * they will read an empty screen as "nothing happened" when it means "the service could not tell
 * me yet". The fallback is stated in seconds because that is the difference it makes to them.
 */
export function LiveChannelNotice() {
  const { liveStatus, state } = useSession();
  if (state.status !== 'authenticated') return null;
  if (!env.liveFeedEnabled) return null;

  const cadence = env.alertPollMs > 0 ? `${Math.round(env.alertPollMs / 1000)}s` : 'manual refresh';

  if (liveStatus === 'live') {
    return (
      <div
        data-testid="live-notice"
        className="mb-2 inline-flex items-center gap-1.5 rounded-full border border-state-ok/40 bg-state-ok/10 px-2.5 py-1 text-[0.68rem] font-bold uppercase tracking-[0.1em] text-state-ok"
      >
        <span aria-hidden className="h-1.5 w-1.5 rounded-full bg-state-ok" />
        Live
      </div>
    );
  }

  if (liveStatus === 'off' || liveStatus === 'connecting') return null;

  const copy =
    liveStatus === 'reconnecting'
      ? 'Live updates paused — reconnecting.'
      : liveStatus === 'unsupported'
        ? 'This service does not offer live updates.'
        : 'Live updates are unavailable for this session.';

  return (
    <Banner tone="warn" testId="live-notice">
      {copy} Alerts still arrive by refresh, up to {cadence} behind.
    </Banner>
  );
}

const TABS = [
  { to: '/dashboard', label: 'Home', icon: IconHome, badge: null },
  { to: '/notifications', label: 'Notifications', icon: IconBell, badge: 'unread' as const },
  { to: '/incidents', label: 'Incidents', icon: IconShield, badge: null },
  { to: '/profile', label: 'Profile', icon: IconUser, badge: null },
];

export function TabBar() {
  const { unreadCount } = useSession();
  return (
    <nav
      aria-label="Primary"
      className="fixed inset-x-0 bottom-0 z-20 border-t border-surface-line bg-surface-raised/95 backdrop-blur pb-[var(--safe-bottom)]"
    >
      <ul className="mx-auto flex max-w-[560px]">
        {TABS.map((tab) => (
          <li key={tab.to} className="flex-1">
            <NavLink
              to={tab.to}
              className={({ isActive }) =>
                `relative flex h-tab flex-col items-center justify-center gap-1 text-[0.62rem] font-semibold uppercase tracking-[0.06em] ${
                  isActive ? 'text-brand' : 'text-ink-faint'
                }`
              }
            >
              {({ isActive }) => {
                const Glyph = tab.icon;
                return (
                  <>
                    <span aria-hidden className="relative">
                      <Glyph size={22} />
                      {tab.badge === 'unread' && unreadCount > 0 ? (
                        <span
                          className="absolute -right-2.5 -top-1.5 min-w-[17px] rounded-full bg-sev-critical px-1 text-center text-[0.6rem] font-bold leading-[17px] text-white"
                          aria-label={`${unreadCount} unread alerts`}
                        >
                          {unreadCount > 99 ? '99+' : unreadCount}
                        </span>
                      ) : null}
                    </span>
                    <span>{tab.label}</span>
                    <span
                      aria-hidden
                      className={`absolute inset-x-5 top-0 h-[2px] rounded-full ${isActive ? 'bg-brand' : 'bg-transparent'}`}
                    />
                  </>
                );
              }}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}

/**
 * Screen header. `back` renders the chevron the mockup puts on every secondary screen;
 * without it the title sits centred like a tab root.
 */
export function ScreenHeader({
  title,
  subtitle,
  actions,
  back,
}: {
  title: string;
  subtitle?: ReactNode;
  actions?: ReactNode;
  back?: boolean | string;
}) {
  const navigate = useNavigate();
  return (
    <header className="mb-3 mt-1 grid min-h-[44px] grid-cols-[44px_1fr_44px] items-center gap-1">
      <div className="flex items-center">
        {back ? (
          <button
            type="button"
            onClick={() => (typeof back === 'string' ? navigate(back) : navigate(-1))}
            aria-label="Back"
            className="flex h-11 w-11 items-center justify-center rounded-full text-ink active:bg-surface-overlay"
          >
            <IconChevronLeft size={22} />
          </button>
        ) : null}
      </div>
      <div className="min-w-0 text-center">
        <h1 className="truncate text-[1rem] font-semibold text-ink">{title}</h1>
        {subtitle ? <p className="mt-0.5 truncate text-[0.72rem] text-ink-muted">{subtitle}</p> : null}
      </div>
      <div className="flex items-center justify-end gap-1">{actions}</div>
    </header>
  );
}

/** Wordmark used where the shield emblem is not shown. */
export function Brand({ compact }: { compact?: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <span aria-hidden className="flex h-7 w-7 items-center justify-center rounded-wt border border-brand/60 bg-brand/10">
        <span className="block h-3 w-3 rounded-wt bg-brand" />
      </span>
      <div className="leading-none">
        <p className="text-[0.7rem] font-bold uppercase tracking-[0.22em] text-brand">AFIT</p>
        <p className={`font-semibold uppercase tracking-[0.18em] text-ink ${compact ? 'text-[0.8rem]' : 'text-[1rem]'}`}>
          Watch Tower
        </p>
      </div>
    </div>
  );
}

export function ForegroundAlertStack() {
  const { foregroundAlerts, dismissForegroundAlert } = useSession();
  const navigate = useNavigate();
  if (foregroundAlerts.length === 0) return null;
  return (
    <div className="fixed inset-x-0 top-[var(--safe-top)] z-40 mx-auto max-w-[560px] space-y-2 p-3">
      {foregroundAlerts.slice(-3).map((alert) => {
        const meta = severityMeta(alert.severity);
        return (
          <div key={alert.id} className={`animate-slide-up panel border-l-4 p-3 ${meta.border} ${meta.bg}`}>
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p className={`flex items-center gap-1.5 text-[0.68rem] font-bold uppercase tracking-wider ${meta.fg}`}>
                  <IconAlert size={15} aria-hidden />
                  {meta.label}
                </p>
                <p className="mt-1 truncate text-[0.88rem] font-semibold text-ink">{alert.title}</p>
                {alert.body ? <p className="mt-0.5 line-clamp-2 text-[0.76rem] text-ink-muted">{alert.body}</p> : null}
              </div>
              <button
                type="button"
                onClick={() => dismissForegroundAlert(alert.id)}
                className="shrink-0 rounded-full p-1.5 text-ink-faint active:bg-surface-overlay"
                aria-label="Dismiss alert"
              >
                <IconClose size={18} />
              </button>
            </div>
            {alert.incidentId ? (
              <ActionButton
                variant="primary"
                className="mt-2"
                full
                onClick={() => {
                  dismissForegroundAlert(alert.id);
                  navigate(`/incidents/${alert.incidentId}`, { state: { notificationId: alert.notificationId } });
                }}
              >
                Open incident
              </ActionButton>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}

/** Green tick used by the confirmation states (acknowledgement sent, note saved). */
export function ConfirmationMark({ tone = 'ok' }: { tone?: 'ok' | 'bad' }) {
  return (
    <span
      aria-hidden
      className={`mx-auto flex h-16 w-16 animate-pop-in items-center justify-center rounded-full ${
        tone === 'ok' ? 'bg-state-ok text-white' : 'bg-sev-critical text-white'
      }`}
    >
      <IconCheck size={34} />
    </span>
  );
}
