/**
 * Login (§2.1).
 *
 * Deliberately absent: a "register" link (§13 — accounts are created by an
 * administrator). "Forgot password?" is present because the design asks for it, but
 * it opens the true statement rather than a flow that does not exist: there is no
 * mail gateway, so an administrator resets the credential in the console
 * (§13). A link that looked like a reset and did nothing would be worse than none.
 */
import { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { ERROR_CODES } from '../types/api';
import { useSession } from '../auth/SessionProvider';
import { ActionButton, Field, TextInput } from '../components/ui';
import { FixtureBanner, InsecureHostBanner, StorageBanner } from '../components/Shell';
import { BrandBackdrop, Emblem } from '../components/Brand';
import { IconEye, IconEyeOff, IconInfo, IconKey, IconUser } from '../components/icons';
import { apiConfig, APP_VERSION, env } from '../config/env';

export function LoginScreen() {
  const { state, login, consumeDestination, ready } = useSession();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [reveal, setReveal] = useState(false);
  const [resetHelp, setResetHelp] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();

  // The destination a push tap (or a protected route) held before login (§12).
  const heldDestination = state.pendingDestination ?? (location.state as { from?: string } | null)?.from ?? null;

  // An already-authenticated session must not be able to sit on this screen.
  useEffect(() => {
    if (!ready) return;
    if (state.status === 'authenticated') {
      const dest = consumeDestination();
      navigate(dest ?? '/dashboard', { replace: true });
    } else if (state.status === 'password_required') {
      navigate('/password', { replace: true });
    }
  }, [ready, state.status, navigate, consumeDestination, heldDestination]);

  // The endpoint decides whether a password may be sent at all. A packaged build pointing at a
  // loopback or plain-HTTP address would carry a real officer's credential to a host that cannot
  // exist for them, or send it in clear text; either way the refusal belongs here rather than in a
  // toast after the request has already left the phone.
  const endpointBlocked = apiConfig.blocksSignIn && !env.fixturesEnabled;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (endpointBlocked) return;
    if (!username.trim() || !password) return;
    const result = await login(username.trim(), password);
    if (result.ok) {
      const dest = consumeDestination();
      navigate(dest ?? '/dashboard', { replace: true });
    }
  };

  const error = state.loginError;
  const errorKind = (() => {
    if (!error) return null;
    if (error.code === ERROR_CODES.INVALID_CREDENTIALS)
      return { title: 'Sign-in refused', body: 'Username or password is incorrect. Failed attempts are counted; eight within a window locks the account for five minutes.' };
    if (error.code === ERROR_CODES.ACCOUNT_LOCKED)
      return { title: 'Account temporarily locked', body: 'Too many failed attempts. Wait five minutes, then try again — or ask a supervisor to unlock you in the monitoring console.' };
    if (error.code === ERROR_CODES.REFRESH_REUSED)
      return { title: 'Session revoked for security', body: 'A token replay was detected for this device, so the whole session family was invalidated. Sign in again to start a fresh family.' };
    if (error.isConnectivity)
      return { title: 'Cannot reach the service', body: `${error.userMessage} Endpoint: ${apiConfig.apiUrl}` };
    if (error.status === 429) return { title: 'Too many attempts', body: 'Rate limited by the service. Wait a moment.' };
    return { title: 'Sign-in failed', body: error.userMessage };
  })();

  return (
    <BrandBackdrop>
      <div className="min-h-full px-4 py-6">
        <FixtureBanner />
        <StorageBanner />
        <InsecureHostBanner />

        <div className="mx-auto w-full max-w-[420px]">
          <div className="flex flex-col items-center gap-2 pb-6 pt-4 text-center">
            <Emblem size={104} />
            <h1 className="text-[1.35rem] font-bold uppercase tracking-[0.16em] text-ink">AFIT Watch Tower</h1>
            <p className="text-[0.8rem] text-ink-muted">Personnel Login</p>
            <p className="text-[0.72rem] uppercase tracking-[0.14em] text-ink-faint">Access your security dashboard</p>
          </div>

          <div className="panel p-5">
            <form onSubmit={submit} className="space-y-4" data-testid="login-form">
              <Field label="Username or email" htmlFor="username">
                <div className="relative">
                  <span aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint">
                    <IconUser size={18} />
                  </span>
                  <TextInput
                    id="username"
                    name="username"
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    inputMode="email"
                    required
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="Username or email"
                    className="pl-10"
                  />
                </div>
              </Field>

              <Field label="Password" htmlFor="password">
                <div className="relative">
                  <span aria-hidden className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-ink-faint">
                    <IconKey size={18} />
                  </span>
                  <TextInput
                    id="password"
                    name="password"
                    autoComplete="current-password"
                    type={reveal ? 'text' : 'password'}
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Password"
                    className="pl-10 pr-12"
                  />
                  <button
                    type="button"
                    onClick={() => setReveal((v) => !v)}
                    aria-label={reveal ? 'Hide password' : 'Show password'}
                    aria-pressed={reveal}
                    className="absolute right-1 top-1/2 flex h-11 w-11 -translate-y-1/2 items-center justify-center text-ink-muted active:text-ink"
                  >
                    {reveal ? <IconEyeOff size={19} /> : <IconEye size={19} />}
                  </button>
                </div>
              </Field>

              {errorKind ? (
                <div role="alert" className="rounded-card border border-sev-critical/50 bg-sev-critical/10 p-3">
                  <p className="text-[0.85rem] font-semibold text-sev-critical">{errorKind.title}</p>
                  <p className="mt-1 text-[0.78rem] leading-snug text-ink-muted">{errorKind.body}</p>
                  {error?.requestId ? (
                    <p className="tabular mt-2 text-[0.7rem] text-ink-faint">request {error.requestId} · code {error.code}</p>
                  ) : null}
                </div>
              ) : null}

              {endpointBlocked ? (
                <p className="rounded-card border border-sev-critical/50 bg-sev-critical/10 p-3 text-[0.76rem] leading-snug text-ink-muted" data-testid="endpoint-blocked">
                  {apiConfig.reason}
                </p>
              ) : null}

              <ActionButton
                variant="primary"
                full
                type="submit"
                busy={state.loggingIn}
                disabled={endpointBlocked || !username.trim() || !password}
              >
                {endpointBlocked ? 'No secure server' : state.loggingIn ? 'Signing in…' : 'Login'}
              </ActionButton>

              <div className="pt-1 text-center">
                <button
                  type="button"
                  onClick={() => setResetHelp((v) => !v)}
                  aria-expanded={resetHelp}
                  className="text-[0.78rem] font-semibold text-brand"
                  data-testid="forgot-password"
                >
                  Forgot Password?
                </button>
                {resetHelp ? (
                  <p className="mt-2 flex items-start gap-2 rounded-card bg-surface-overlay p-3 text-left text-[0.76rem] leading-snug text-ink-muted">
                    <span aria-hidden className="mt-[1px] shrink-0 text-brand">
                      <IconInfo size={16} />
                    </span>
                    This system cannot send a password-reset mail. An administrator or supervisor must
                    reset your credential in the monitoring console, and you will be asked to set a new
                    one on the next sign-in.
                  </p>
                ) : null}
              </div>
            </form>
          </div>

          {heldDestination ? (
            <p className="mt-4 text-center text-[0.75rem] text-ink-muted" data-testid="held-destination">
              After signing in you will be taken to{' '}
              <span className="tabular">{destinationLabel(heldDestination)}</span>.
            </p>
          ) : null}

          <div className="mt-6 space-y-1 text-center text-[0.7rem] leading-relaxed text-ink-faint">
            <p>
              No account? A supervisor creates personnel accounts in the monitoring console. There is
              no self-registration.
            </p>
            <p className="text-[0.78rem] font-semibold uppercase tracking-[0.12em] text-ink-muted">
              Secure Today. Safer Tomorrow.
            </p>
            <p className="tabular pt-1">
              {apiConfig.apiUrl || 'no cloud endpoint'} · {env.appEnv} · v{APP_VERSION}
            </p>
          </div>
        </div>
      </div>
    </BrandBackdrop>
  );
}

/**
 * The held route in words. A raw path tells a duty officer nothing, but the word "incident"
 * in front of `/dashboard` would be a lie, so each route the app can hold gets its own label
 * and anything unknown is shown as the path it actually is.
 */
function destinationLabel(path: string): string {
  if (path.startsWith('/incidents/')) return `incident ${path.split('/').pop()}`;
  if (path.startsWith('/notifications')) return 'the notification centre';
  if (path.startsWith('/incidents')) return 'the incident queue';
  if (path.startsWith('/dashboard')) return 'the dashboard';
  if (path.startsWith('/profile')) return 'your profile';
  return path;
}
