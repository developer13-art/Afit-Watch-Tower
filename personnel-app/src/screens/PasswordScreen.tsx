/**
 * Password change (§2.4).
 *
 * Rendered as a gate when the server sets `must_change_password`: while that
 * flag is true this is the only screen the router will show. Minimum length is
 * 12 characters (§2.1) and is enforced client-side only to save the operator a
 * round-trip — the server is the authority and a 422 is still handled.
 *
 * The screen states the consequence honestly: changing the password rotates the
 * refresh token for every device, so other sessions stop working unless the
 * caller opts out.
 */
import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useSession } from '../auth/SessionProvider';
import { authApi } from '../api/endpoints';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import { ActionButton, Field, TextInput } from '../components/ui';
import { Brand } from '../components/Shell';
import { env } from '../config/env';

const MIN_LENGTH = 12;

export function strengthOf(value: string): { label: string; tone: 'bad' | 'warn' | 'ok' } {
  if (value.length < MIN_LENGTH) return { label: `Too short — ${MIN_LENGTH - value.length} more characters`, tone: 'bad' };
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^\w\s]/].filter((r) => r.test(value)).length;
  if (classes <= 1) return { label: 'Weak — mix cases, digits or symbols', tone: 'warn' };
  if (classes === 2) return { label: 'Acceptable', tone: 'warn' };
  return { label: 'Strong', tone: 'ok' };
}

export function PasswordScreen({ forced }: { forced?: boolean }) {
  const { state, logout, consumeDestination, refreshMe } = useSession();
  const navigate = useNavigate();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [reveal, setReveal] = useState(false);
  const [keepOtherSessions, setKeepOtherSessions] = useState(false);
  const [error, setError] = useState<ApiError | string | null>(null);
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && confirm !== next;
  const canSubmit = current.length > 0 && next.length >= MIN_LENGTH && confirm === next && !busy;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      // The contract's `/auth/password` accepts `keep_other_sessions`; the
      // client sends it explicitly so the default (false) is never accidental.
      const res = await submitPassword(current, next, keepOtherSessions);
      if (!res.ok) {
        setError(res.error);
        return;
      }
      await refreshMe();
      if (forced) {
        const dest = consumeDestination();
        navigate(dest ?? '/dashboard', { replace: true });
      } else {
        navigate('/profile', { replace: true });
      }
    } finally {
      setBusy(false);
    }
  };

  const strength = strengthOf(next);

  return (
    <div className="screen">
      {forced ? (
        <div className="mb-4 flex items-center justify-between">
          <Brand compact />
          <span className="text-[0.68rem] uppercase tracking-widest text-ink-faint">{env.appEnv}</span>
        </div>
      ) : null}

      <div className="card p-4">
        <h1 className="text-[1.05rem] font-semibold text-ink">
          {forced ? 'Set a new password to continue' : 'Change password'}
        </h1>
        <p className="mt-1 text-[0.78rem] leading-snug text-ink-muted">
          {forced
            ? 'This account is still using the password an administrator issued. No other screen is available until it is changed — this is the only way to stop a shared default credential staying in use.'
            : 'Changing your password rotates the refresh token for every device registered to this account.'}
        </p>

        <form className="mt-4 space-y-4" onSubmit={submit} data-testid="password-form">
          <Field label="Current password" htmlFor="current">
            <TextInput
              id="current"
              type={reveal ? 'text' : 'password'}
              autoComplete="current-password"
              value={current}
              onChange={(e) => setCurrent(e.target.value)}
            />
          </Field>

          <Field
            label="New password"
            htmlFor="next"
            hint={`At least ${MIN_LENGTH} characters. ${strength.label}.`}
          >
            <TextInput
              id="next"
              type={reveal ? 'text' : 'password'}
              autoComplete="new-password"
              value={next}
              onChange={(e) => setNext(e.target.value)}
            />
          </Field>

          <div className="h-1 w-full overflow-hidden rounded-wt bg-surface-overlay" aria-hidden>
            <div
              className={`h-full transition-all ${
                strength.tone === 'ok' ? 'bg-state-ok' : strength.tone === 'warn' ? 'bg-sev-medium' : 'bg-sev-critical'
              }`}
              style={{ width: `${Math.min(100, (next.length / 20) * 100)}%` }}
            />
          </div>

          <Field
            label="Confirm new password"
            htmlFor="confirm"
            error={mismatch ? 'The two entries do not match.' : null}
          >
            <TextInput
              id="confirm"
              type={reveal ? 'text' : 'password'}
              autoComplete="new-password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
          </Field>

          <label className="flex items-center gap-2 text-[0.78rem] text-ink-muted">
            <input
              type="checkbox"
              className="h-4 w-4 accent-brand"
              checked={keepOtherSessions}
              onChange={(e) => setKeepOtherSessions(e.target.checked)}
            />
            Keep other devices signed in
          </label>

          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setReveal((v) => !v)}
              className="text-[0.7rem] font-semibold uppercase tracking-wider text-ink-muted"
              aria-pressed={reveal}
            >
              {reveal ? 'Hide passwords' : 'Show passwords'}
            </button>
            {reveal ? <span className="text-[0.68rem] text-sev-medium">Visible on screen — check for onlookers.</span> : null}
          </div>

          {error ? (
            <div role="alert" className="border border-sev-critical/50 bg-sev-critical/10 p-3 text-[0.78rem] text-sev-critical">
              {typeof error === 'string' ? error : error.userMessage}
              {typeof error !== 'string' && error.requestId ? (
                <p className="tabular mt-1 text-[0.7rem] text-ink-faint">request {error.requestId} · code {error.code}</p>
              ) : null}
            </div>
          ) : null}

          <ActionButton variant="primary" full type="submit" busy={busy} disabled={!canSubmit} data-testid="submit-password">
            {busy ? 'Saving…' : 'Change password'}
          </ActionButton>

          {forced ? (
            <ActionButton variant="ghost" full type="button" onClick={() => void logout({ forgetDevice: false })}>
              Sign out instead
            </ActionButton>
          ) : null}
        </form>
      </div>

      {state.status === 'password_required' ? (
        <p className="mt-3 text-center text-[0.72rem] text-ink-faint">
          You cannot reach the dashboard, alerts or incidents until this is done.
        </p>
      ) : null}
    </div>
  );
}

/**
 * Kept separate so the screen does not import the client directly and the
 * `keep_other_sessions` field is sent in the contract's exact shape.
 */
async function submitPassword(current: string, next: string, keepOtherSessions: boolean) {
  try {
    await authApi.changePassword({
      current_password: current,
      new_password: next,
      keep_other_sessions: keepOtherSessions,
    });
    return { ok: true } as const;
  } catch (err) {
    return {
      ok: false,
      error:
        err instanceof ApiError
          ? err
          : new ApiError({
              code: ERROR_CODES.UNKNOWN,
              message: err instanceof Error ? err.message : 'Could not change the password.',
            }),
    } as const;
  }
}
