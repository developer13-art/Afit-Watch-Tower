/**
 * The five non-success states, defined once.
 *
 * Every data screen renders exactly one of these instead of a blank card. The
 * wording is deliberate: a duty officer must be able to tell "no incidents"
 * from "I cannot see incidents" from "the phone has no network" — those lead to
 * different actions, and collapsing them would be a safety defect.
 */
import type { ReactNode } from 'react';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import type { AsyncState } from '../hooks/useAsync';
import { ActionButton, Spinner } from './ui';

function Frame({ icon, title, body, children, tone = 'muted' }: { icon?: ReactNode; title: string; body: ReactNode; children?: ReactNode; tone?: 'muted' | 'warn' | 'bad' }) {
  const titleClass = tone === 'bad' ? 'text-sev-critical' : tone === 'warn' ? 'text-sev-medium' : 'text-ink';
  return (
    <div className="card my-3 p-4" role="status" aria-live="polite">
      <div className="flex items-start gap-3">
        {icon ? <span className="mt-0.5 text-lg leading-none text-ink-faint" aria-hidden>{icon}</span> : null}
        <div className="min-w-0 flex-1">
          <p className={`text-[0.95rem] font-semibold ${titleClass}`}>{title}</p>
          <div className="mt-1 text-[0.82rem] leading-relaxed text-ink-muted">{body}</div>
          {children ? <div className="mt-3">{children}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function LoadingState({ label = 'Loading' }: { label?: string }) {
  return (
    <div className="card my-3 flex items-center gap-3 p-4" role="status" aria-live="polite" data-testid="loading-state">
      <Spinner />
      <span className="text-[0.85rem] text-ink-muted">{label}…</span>
    </div>
  );
}

export function EmptyState({ title = 'Nothing to show', body, action }: { title?: string; body: ReactNode; action?: ReactNode }) {
  return (
    <div className="card my-3 p-4" role="status" data-testid="empty-state">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-[0.95rem] font-semibold text-ink">{title}</p>
          <div className="mt-1 text-[0.82rem] leading-relaxed text-ink-muted">{body}</div>
          {action ? <div className="mt-3">{action}</div> : null}
        </div>
      </div>
    </div>
  );
}

export function ErrorState({ error, onRetry }: { error: ApiError; onRetry?: () => void }) {
  const connectivity = error.isConnectivity;
  return (
    <Frame
      tone="bad"
      title={connectivity ? 'Cannot reach the WATCH TOWER service' : 'The request failed'}
      body={
        <>
          <p>{error.userMessage}</p>
          <p className="tabular mt-2 text-ink-faint">
            code {error.code}
            {error.status ? ` · http ${error.status}` : ''}
            {error.requestId ? ` · request ${error.requestId}` : ''}
          </p>
          {error.retryAfterSeconds ? (
            <p className="mt-1 text-ink-faint">Retry in about {error.retryAfterSeconds}s.</p>
          ) : null}
        </>
      }
    >
      {onRetry ? (
        <ActionButton variant="secondary" onClick={onRetry} busy={false}>
          Try again
        </ActionButton>
      ) : null}
    </Frame>
  );
}

export function UnauthorizedState({ onRetry, message }: { onRetry?: () => void; message?: string }) {
  return (
    <Frame
      tone="warn"
      title="Sign-in required"
      body={
        message ??
        'This session is no longer valid on the server. Sign in again to continue — your device and notification registration are restored automatically.'
      }
    >
      {onRetry ? (
        <ActionButton variant="secondary" onClick={onRetry}>
          Re-check session
        </ActionButton>
      ) : null}
    </Frame>
  );
}

export function ForbiddenState({ permission, body }: { permission?: string; body?: ReactNode }) {
  return (
    <Frame
      tone="warn"
      title="Not permitted"
      body={
        body ?? (
          <>
            <p>
              Your account does not hold {permission ? <code className="tabular">{permission}</code> : 'the permission'} required for
              this record. Access is decided by the server on every request, so a grant an administrator removes takes effect
              immediately.
            </p>
          </>
        )
      }
    />
  );
}

/** Generic renderer for a `useAsync` result. Keeps screens to one line. */
export function AsyncBoundary<T>({
  state,
  loadingLabel,
  emptyTitle,
  emptyBody,
  children,
  requiredPermission,
}: {
  state: AsyncState<T>;
  loadingLabel?: string;
  emptyTitle?: string;
  emptyBody?: ReactNode;
  children: (data: T) => ReactNode;
  requiredPermission?: string;
}) {
  if (state.status === 'loading') return <LoadingState label={loadingLabel} />;
  if (state.status === 'unauthorized') return <UnauthorizedState onRetry={() => void state.reload()} />;
  if (state.status === 'forbidden') return <ForbiddenState permission={requiredPermission} />;
  if (state.status === 'empty')
    return <EmptyState title={emptyTitle} body={emptyBody ?? 'The service returned no records for this query.'} />;
  if (state.status === 'error' || state.error) {
    const err = state.error ?? new ApiError({ code: ERROR_CODES.UNKNOWN, message: 'Unknown failure.' });
    return <ErrorState error={err} onRetry={() => void state.reload()} />;
  }
  if (state.data === null) return <LoadingState label={loadingLabel} />;
  return <>{children(state.data)}</>;
}
