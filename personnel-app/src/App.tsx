/**
 * Routing and session gates.
 *
 * Bottom tabs are Dashboard · Alerts · Incidents · Profile. Incident response
 * actions live inside the incident screen, never in the navigation: an action
 * button has to be next to the evidence it refers to.
 *
 * `must_change_password` is a hard gate — the router renders the password
 * screen for any location while the flag stands, because the server will refuse
 * nothing but /auth/password with it set (§2.1).
 */
import { HashRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import type { ReactNode } from 'react';
import { SessionProvider, useSession } from './auth/SessionProvider';
import {
  FixtureBanner,
  ForegroundAlertStack,
  InsecureHostBanner,
  LiveChannelNotice,
  OfflineBanner,
  PushStatusBanner,
  ScreenHeader,
  StorageBanner,
  TabBar,
} from './components/Shell';
import { ActionButton } from './components/ui';
import { ErrorState } from './components/States';
import { BrandBackdrop, Emblem } from './components/Brand';
import { LoginScreen } from './screens/LoginScreen';
import { PasswordScreen } from './screens/PasswordScreen';
import { DashboardScreen } from './screens/DashboardScreen';
import { NotificationsScreen } from './screens/NotificationsScreen';
import { IncidentHistoryScreen } from './screens/IncidentHistoryScreen';
import { IncidentDetailScreen } from './screens/IncidentDetailScreen';
import { InvestigationNotesScreen } from './screens/InvestigationNotesScreen';
import { ProfileScreen } from './screens/ProfileScreen';
import { AccountInfoScreen } from './screens/AccountInfoScreen';
import { DeviceStatusScreen } from './screens/DeviceStatusScreen';
import { AboutScreen } from './screens/AboutScreen';
import { NotificationSettingsScreen } from './screens/NotificationSettingsScreen';
import { Brand } from './components/Shell';
import { ApiError } from './api/errors';
import { ERROR_CODES } from './types/api';

function BootScreen() {
  // The splash: the same emblem and tagline the operator saw at sign-in, with the real
  // reason for the wait underneath it. Nothing is claimed as connected at this point.
  return (
    <BrandBackdrop>
      <div className="flex min-h-full flex-col items-center justify-center gap-5 px-8 text-center">
        <Emblem size={132} />
        <div>
          <p className="text-[1.5rem] font-bold uppercase tracking-[0.18em] text-ink">AFIT</p>
          <p className="text-[1.5rem] font-bold uppercase tracking-[0.18em] text-ink">Watch Tower</p>
          <p className="mt-2 text-[0.78rem] text-ink-muted">Secure Today. Safer Tomorrow.</p>
        </div>
        <span
          aria-hidden
          className="h-7 w-7 animate-spin rounded-full border-2 border-surface-line-strong border-t-brand"
        />
        <p className="text-[0.7rem] text-ink-faint">Security Monitoring System</p>
      </div>
    </BrandBackdrop>
  );
}

function BootErrorScreen() {
  const { state, retryBoot } = useSession();
  return (
    <div className="mx-auto w-full max-w-[520px] px-4 py-10">
      <div className="mb-4">
        <Brand />
      </div>
      <ErrorState
        error={
          state.loginError ??
          new ApiError({ code: ERROR_CODES.NETWORK_OFFLINE, message: 'The service could not be reached at start-up.', kind: 'network' })
        }
        onRetry={retryBoot}
      />
      <p className="mt-3 text-[0.74rem] leading-snug text-ink-faint">
        Your stored session has not been discarded. If the service comes back, retry and you will still be signed in.
      </p>
    </div>
  );
}

function Shell({ children }: { children: ReactNode }) {
  return (
    <div className="min-h-full">
      <FixtureBanner />
      <StorageBanner />
      <InsecureHostBanner />
      <OfflineBanner />
      <PushStatusBanner />
      <LiveChannelNotice />
      <main>{children}</main>
      <TabBar />
      <ForegroundAlertStack />
    </div>
  );
}

function Protected({ children }: { children: ReactNode }) {
  const { state } = useSession();
  const location = useLocation();

  if (state.status === 'password_required') return <PasswordScreen forced />;
  if (state.status === 'anonymous' || state.status === 'boot_error') {
    // §12 — the destination is held by `LoginScreen` via router state; nothing
    // is written to storage, because the path names an incident.
    return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  }
  return <Shell>{children}</Shell>;
}

function Routes_() {
  const { state, ready } = useSession();

  if (!ready && state.status === 'booting') return <BootScreen />;
  if (state.status === 'boot_error') return <BootErrorScreen />;

  if (state.status === 'password_required') {
    return (
      <Routes>
        <Route path="/password" element={<PasswordScreen forced />} />
        <Route path="*" element={<PasswordScreen forced />} />
      </Routes>
    );
  }

  return (
    <Routes>
      <Route path="/login" element={<LoginScreen />} />
      <Route path="/password" element={<PasswordGate />} />
      <Route
        path="/dashboard"
        element={
          <Protected>
            <DashboardScreen />
          </Protected>
        }
      />
      <Route
        path="/notifications"
        element={
          <Protected>
            <NotificationsScreen />
          </Protected>
        }
      />
      <Route
        path="/incidents"
        element={
          <Protected>
            <IncidentHistoryScreen />
          </Protected>
        }
      />
      <Route
        path="/incidents/:id"
        element={
          <Protected>
            <IncidentDetailScreen />
          </Protected>
        }
      />
      <Route
        path="/incidents/:id/notes"
        element={
          <Protected>
            <InvestigationNotesScreen />
          </Protected>
        }
      />
      <Route
        path="/settings/notifications"
        element={
          <Protected>
            <NotificationSettingsScreen />
          </Protected>
        }
      />
      <Route
        path="/profile"
        element={
          <Protected>
            <ProfileScreen />
          </Protected>
        }
      />
      <Route
        path="/profile/account"
        element={
          <Protected>
            <AccountInfoScreen />
          </Protected>
        }
      />
      <Route
        path="/profile/devices"
        element={
          <Protected>
            <DeviceStatusScreen />
          </Protected>
        }
      />
      <Route
        path="/profile/about"
        element={
          <Protected>
            <AboutScreen />
          </Protected>
        }
      />
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="*" element={<NotFound />} />
    </Routes>
  );
}

/** Password change reached from the profile menu (not forced). */
function PasswordGate() {
  const { state } = useSession();
  if (state.status === 'anonymous') return <Navigate to="/login" replace />;
  return (
    <Shell>
      <PasswordScreen />
    </Shell>
  );
}

function NotFound() {
  const { state } = useSession();
  return (
    <Shell>
      <ScreenHeader title="Not found" />
      <div className="card p-4 text-[0.82rem] text-ink-muted">
        This link does not match a screen in the app.
        {state.pendingDestination ? <p className="tabular mt-2">held: {state.pendingDestination}</p> : null}
        <ActionButton variant="secondary" className="mt-3" onClick={() => window.location.assign('#/dashboard')}>
          Go to dashboard
        </ActionButton>
      </div>
    </Shell>
  );
}

export default function App() {
  return (
    <HashRouter>
      <SessionProvider>
        <Routes_ />
      </SessionProvider>
    </HashRouter>
  );
}
