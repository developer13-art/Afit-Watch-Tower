/**
 * About this build (§0, §10, §13).
 *
 * The screen exists so an officer can answer "which service am I actually
 * talking to, and what is not switched on" without opening a devtools console.
 * Every line is a value the running app holds; nothing here is a promise about
 * hardware the app cannot see. Push in particular is described by the token the
 * platform returned, never by a logo.
 */
import { healthApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import { InfoRow, SectionCard } from '../components/ui';
import { ScreenHeader } from '../components/Shell';
import { useSession } from '../auth/SessionProvider';
import { apiConfig, APP_VERSION, env, firebaseWebConfig } from '../config/env';
import { IconAlert, IconBell, IconGauge, IconInfo, IconKey, IconRefresh, IconShield, IconSliders } from '../components/icons';

/** The one place the live-channel vocabulary is turned into an officer's sentence. */
function liveSentence(status: string, detail: string | null): string {
  switch (status) {
    case 'live':
      return 'Connected — the service pushes changes to this screen as they are recorded.';
    case 'connecting':
      return 'Opening the stream…';
    case 'reconnecting':
      return `Dropped, retrying with backoff.${detail ? ` Last error: ${detail}` : ''}`;
    case 'unsupported':
      return 'This service does not offer the live channel. Lists refresh on their own cadence and when you pull.';
    case 'off':
      return env.fixturesEnabled
        ? 'Not opened — this build reads scripted fixture data, so there is no service to stream from.'
        : 'Turned off in this build (VITE_LIVE_FEED=0).';
    default:
      return `Unavailable for this session.${detail ? ` ${detail}` : ''}`;
  }
}

export function AboutScreen() {
  const { liveStatus, liveDetail, app } = useSession();
  const firebase = firebaseWebConfig();
  // /healthz is the service describing itself, which is the point of an about screen. It is
  // unauthenticated, so it answers even when the session has expired — and a failure to answer is
  // reported rather than hidden. Under fixtures there is no service to ask, so nothing is probed.
  const health = useAsync(() => healthApi.check(), [], { enabled: !env.fixturesEnabled });

  return (
    <div className="screen">
      <ScreenHeader title="About this build" back="/profile" />

      <SectionCard title="Application">
        <InfoRow icon={<IconShield size={18} />} label="App" value={`AFIT WATCH TOWER — Personnel (${env.androidAppId})`} />
        <InfoRow icon={<IconInfo size={18} />} label="Version" value={<span className="tabular">v{APP_VERSION}</span>} />
        <InfoRow
          icon={<IconSliders size={18} />}
          label="Build environment"
          value={`${env.appEnv}${env.fixturesEnabled ? ' — reading scripted fixture data, not the service' : ''}`}
        />
        <InfoRow
          icon={<IconKey size={18} />}
          label="Data endpoint"
          value={<span className="tabular break-all">{apiConfig.apiUrl || 'Not configured'}</span>}
        />
        <InfoRow
          icon={<IconGauge size={18} />}
          label="Request timeout"
          value={`${env.apiTimeoutMs / 1000}s for data calls, ${env.authTimeoutMs / 1000}s for sign-in`}
        />
        {app?.installationId ? (
          <InfoRow
            icon={<IconAlert size={18} />}
            label="Installation id"
            value={<span className="tabular break-all">{app.installationId}</span>}
          />
        ) : null}
      </SectionCard>

      <SectionCard title="Connections" className="mt-3">
        <InfoRow
          icon={<IconRefresh size={18} />}
          label="Live updates"
          value={liveSentence(liveStatus, liveDetail)}
        />
        <InfoRow
          icon={<IconBell size={18} />}
          label="Push notifications"
          value={
            firebase
              ? `A Firebase web project is configured (${firebase.projectId}). Delivery to a handset is only proven on that handset; this screen does not claim it.`
              : 'No Firebase project is configured, so this build sends no push. Alerts arrive while the app is open, through live updates and the refresh poll.'
          }
        />
        <InfoRow
          icon={<IconGauge size={18} />}
          label="Refresh cadence"
          value={env.alertPollMs > 0 ? `${Math.round(env.alertPollMs / 1000)}s while the app is in the foreground` : 'Manual only'}
        />
        <InfoRow
          icon={<IconAlert size={18} />}
          label="Transport"
          value={
            apiConfig.state === 'ready'
              ? 'TLS endpoint.'
              : apiConfig.state === 'unconfigured'
                ? 'No cloud endpoint is compiled into this build, so it cannot reach a service at all.'
                : `${apiConfig.reason} Contract §0 requires HTTPS; do not use real credentials on this build.`
          }
        />
        <InfoRow
          icon={<IconShield size={18} />}
          label="Service health"
          value={
            env.fixturesEnabled
              ? 'Not probed — this build reads scripted fixture data, so there is no service to ask.'
              : health.status === 'loading'
                ? 'Asking the service…'
                : health.error
                  ? `The health probe did not answer: ${health.error.userMessage}`
                  : health.data
                    ? `${health.data.status === 'ok' ? 'The service answers' : 'The service is degraded'} · database ${health.data.database} · push ${health.data.push} · live channel ${health.data.live_channel}`
                    : 'No answer recorded'
          }
        />
        {health.data ? (
          <InfoRow
            icon={<IconInfo size={18} />}
            label="Protocol"
            value={
              <span className="tabular">
                {health.data.service} v{health.data.protocol_version} · up {Math.round(health.data.uptime_seconds / 60)} min
              </span>
            }
          />
        ) : null}
      </SectionCard>

      <SectionCard title="How this app is meant to be used" className="mt-3">
        <ul className="space-y-2 p-4 text-[0.76rem] leading-snug text-ink-muted">
          <li>
            Accounts are created by an administrator in the monitoring console. There is no self-registration and no password
            mail: a forgotten password is reset by an administrator.
          </li>
          <li>
            A detection raised by the model is a candidate, not a confirmed offence. The confidence and the source are shown
            on every incident so a judgement is never made on an assumption about where the record came from.
          </li>
          <li>
            Evidence opens through a short-lived, single-asset link and is never stored on this device. There is no offline
            copy of a snapshot.
          </li>
          <li>
            Your permissions are resolved by the service on every request. If a grant is removed you see the refusal on your
            next action, not after a sign-out.
          </li>
        </ul>
      </SectionCard>

      <p className="mt-3 text-center text-[0.68rem] leading-snug text-ink-faint">
        AFIT WATCH TOWER · Air Force Institute of Technology, Kaduna
      </p>
    </div>
  );
}
