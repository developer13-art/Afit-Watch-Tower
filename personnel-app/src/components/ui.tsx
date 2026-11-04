/**
 * Primitive controls. One definition each, so a button cannot look different
 * on the login screen than on the resolve sheet.
 */
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes } from 'react';
import type { Severity } from '../types/api';
import { detectionMeta, evidenceStateMeta, formatConfidence, severityMeta, statusMeta } from '../lib/severity';
import type { IncidentStatus } from '../types/api';

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-ink-muted" role="status" aria-live="polite">
      <span
        aria-hidden
        className="h-4 w-4 animate-spin rounded-full border-2 border-surface-line-strong border-t-brand"
      />
      {label ? <span className="text-[0.8rem]">{label}</span> : null}
    </span>
  );
}

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost';

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: 'btn-primary',
  secondary: 'btn-secondary',
  danger: 'btn-danger',
  ghost: 'btn-ghost',
};

export interface ActionButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  busy?: boolean;
  full?: boolean;
}

export function ActionButton({ variant = 'secondary', busy, full, className = '', children, disabled, ...rest }: ActionButtonProps) {
  return (
    <button
      type="button"
      className={`${VARIANT_CLASS[variant]} ${full ? 'w-full' : ''} ${className}`}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      {...rest}
    >
      {busy ? <Spinner /> : null}
      {children}
    </button>
  );
}

export function Field({
  label,
  hint,
  error,
  children,
  htmlFor,
}: {
  label: string;
  hint?: ReactNode;
  error?: string | null;
  children: ReactNode;
  htmlFor?: string;
}) {
  return (
    <div className="space-y-1.5">
      <label className="label" htmlFor={htmlFor}>
        {label}
      </label>
      {children}
      {error ? (
        <p className="text-[0.78rem] text-sev-critical" role="alert">
          {error}
        </p>
      ) : hint ? (
        <p className="text-[0.75rem] text-ink-faint">{hint}</p>
      ) : null}
    </div>
  );
}

export function TextInput({ className = '', ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={`field-input ${className}`} {...rest} />;
}

export function Select({ className = '', children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select className={`field-input appearance-none ${className}`} {...rest}>
      {children}
    </select>
  );
}

export function Toggle({
  checked,
  onChange,
  disabled,
  label,
  description,
  disabledReason,
  testId,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  label: string;
  description?: string;
  disabledReason?: string;
  testId?: string;
}) {
  return (
    <div
      className={`flex items-start justify-between gap-3 border-b border-surface-line py-3 last:border-b-0 ${
        disabled ? 'opacity-60' : ''
      }`}
    >
      <div className="min-w-0">
        <p className="text-[0.9rem] font-medium text-ink">{label}</p>
        {description ? <p className="mt-0.5 text-[0.75rem] text-ink-faint">{description}</p> : null}
        {disabled && disabledReason ? (
          <p className="mt-1 text-[0.72rem] leading-snug text-sev-medium">
            <span className="font-semibold uppercase tracking-wider">Forced by policy — </span>
            {disabledReason}
          </p>
        ) : null}
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        data-testid={testId}
        disabled={disabled}
        onClick={() => onChange(!checked)}
        className={`relative h-7 w-12 shrink-0 rounded-full border transition-colors ${
          checked ? 'border-accent/70 bg-accent/25' : 'border-surface-line-strong bg-surface-overlay'
        } ${disabled ? 'cursor-not-allowed' : ''}`}
      >
        <span
          className={`absolute top-[3px] h-[19px] w-[19px] rounded-full transition-all ${
            checked ? 'left-[24px] bg-accent' : 'left-[3px] bg-ink-faint'
          }`}
        />
      </button>
    </div>
  );
}

export function Chip({ tone, children, className = '' }: { tone: 'neutral' | 'brand' | 'warn' | 'bad' | 'ok'; children: ReactNode; className?: string }) {
  const tones: Record<string, string> = {
    neutral: 'border-surface-line-strong bg-surface-overlay text-ink-muted',
    brand: 'border-brand/50 bg-brand/10 text-brand',
    warn: 'border-sev-medium/50 bg-sev-medium/10 text-sev-medium',
    bad: 'border-sev-critical/50 bg-sev-critical/10 text-sev-critical',
    ok: 'border-state-ok/50 bg-state-ok/10 text-state-ok',
  };
  return <span className={`chip ${tones[tone]} ${className}`}>{children}</span>;
}

export function SeverityChip({ severity, size = 'md' }: { severity: Severity | string; size?: 'sm' | 'md' }) {
  const meta = severityMeta(severity);
  return (
    <span
      className={`chip ${meta.border} ${meta.bg} ${meta.fg} ${size === 'sm' ? 'text-[0.62rem] px-1.5 py-[2px]' : ''}`}
      data-testid={`severity-${String(severity)}`}
    >
      {meta.label}
    </span>
  );
}

export function StatusChip({ status }: { status: IncidentStatus | string }) {
  const meta = statusMeta(status);
  return <span className={`chip ${meta.border} ${meta.bg} ${meta.fg}`}>{meta.label}</span>;
}

export function DetectionChip({ source, confidence }: { source: string; confidence?: number | null }) {
  const meta = detectionMeta(source);
  return (
    <span
      className={`chip ${meta.isCandidate ? 'border-brand/50 bg-brand/10 text-brand' : 'border-surface-line-strong bg-surface-overlay text-ink-muted'}`}
      title={`${meta.hint}${confidence != null ? ` (${formatConfidence(confidence)})` : ''}`}
    >
      {meta.label}
    </span>
  );
}

export function EvidenceStateChip({ state }: { state: string }) {
  const meta = evidenceStateMeta(state);
  const tone =
    meta.tone === 'ok'
      ? 'border-state-ok/50 bg-state-ok/10 text-state-ok'
      : meta.tone === 'warn'
        ? 'border-sev-medium/50 bg-sev-medium/10 text-sev-medium'
        : meta.tone === 'bad'
          ? 'border-sev-critical/50 bg-sev-critical/10 text-sev-critical'
          : 'border-surface-line-strong bg-surface-overlay text-ink-muted';
  return <span className={`chip ${tone}`}>{meta.label}</span>;
}

/** Thin left rule used on list rows so severity reads at a glance in a pocket. */
export function SeverityRail({ severity }: { severity: Severity | string }) {
  const meta = severityMeta(severity);
  return <span aria-hidden className={`w-[3px] shrink-0 rounded-wt ${meta.solid}`} />;
}

export function Row({ children, onClick, testId, ariaLabel }: { children: ReactNode; onClick?: () => void; testId?: string; ariaLabel?: string }) {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      type={onClick ? 'button' : undefined}
      data-testid={testId}
      aria-label={ariaLabel}
      onClick={onClick}
      className={`flex w-full items-stretch gap-3 border-b border-surface-line bg-surface-card px-3 py-3 text-left last:border-b-0 ${
        onClick ? 'active:bg-surface-overlay' : ''
      }`}
    >
      {children}
    </Tag>
  );
}

export function Metric({ label, value, tone = 'neutral', sub }: { label: string; value: ReactNode; tone?: 'neutral' | 'bad' | 'warn' | 'ok'; sub?: string }) {
  const valueTone =
    tone === 'bad' ? 'text-sev-critical' : tone === 'warn' ? 'text-sev-medium' : tone === 'ok' ? 'text-state-ok' : 'text-ink';
  return (
    <div className="card p-3">
      <p className="section-title">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${valueTone}`}>{value}</p>
      {sub ? <p className="mt-0.5 text-[0.72rem] text-ink-faint">{sub}</p> : null}
    </div>
  );
}

/**
 * The three headline counts on the dashboard. Solid colour, not a tint: an officer
 * should be able to read "how many critical are open" from across a room, and these
 * numbers are the only severity colour allowed to fill a whole tile.
 */
export function StatTile({
  label,
  value,
  tone,
  icon,
  loading,
}: {
  label: string;
  value: number | null;
  tone: 'critical' | 'high' | 'info';
  icon: ReactNode;
  loading?: boolean;
}) {
  const fill =
    tone === 'critical'
      ? 'bg-sev-critical text-white'
      : tone === 'high'
        ? 'bg-sev-high text-surface-base'
        : 'bg-brand text-white';
  return (
    <div className={`flex min-h-[92px] flex-col justify-between rounded-tile bg-tile p-3 shadow-tile ${fill}`}>
      <div className="flex items-start justify-between gap-2">
        <span aria-hidden className="opacity-90">{icon}</span>
        <span className="tabular text-[1.6rem] font-bold leading-none">
          {loading || value == null ? '—' : value}
        </span>
      </div>
      <p className="text-[0.72rem] font-bold uppercase tracking-[0.1em]">{label}</p>
    </div>
  );
}

export function FilterChip({
  active,
  onClick,
  children,
  testId,
}: {
  active: boolean;
  onClick: () => void;
  children: ReactNode;
  testId?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      data-testid={testId}
      className={`filter-chip ${active ? 'filter-chip-active' : ''}`}
    >
      {children}
    </button>
  );
}

export function IconBadge({ tone = 'neutral', children }: { tone?: 'neutral' | 'brand' | 'warn' | 'bad' | 'ok'; children: ReactNode }) {
  const tones: Record<string, string> = {
    neutral: 'border-surface-line-strong bg-surface-overlay text-ink-muted',
    brand: 'border-brand/50 bg-brand/15 text-brand',
    warn: 'border-sev-medium/50 bg-sev-medium/15 text-sev-medium',
    bad: 'border-sev-critical/50 bg-sev-critical/15 text-sev-critical',
    ok: 'border-state-ok/50 bg-state-ok/15 text-state-ok',
  };
  return <span className={`icon-badge ${tones[tone]}`}>{children}</span>;
}

/** Card with a heading row and its own scroll-free content, as used across the redesign. */
export function SectionCard({
  title,
  action,
  children,
  className = '',
}: {
  title: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-head">
        <h2 className="text-[0.86rem] font-semibold text-ink">{title}</h2>
        {action}
      </div>
      {children}
    </section>
  );
}

/** Label/value line with a leading glyph — the incident brief and the device status screen. */
export function InfoRow({ icon, label, value }: { icon?: ReactNode; label: string; value: ReactNode }) {
  return (
    <div className="flex items-start gap-3 border-b border-surface-line px-4 py-3 last:border-b-0">
      {icon ? <span aria-hidden className="mt-[2px] shrink-0 text-ink-faint">{icon}</span> : null}
      <div className="min-w-0 flex-1">
        <p className="section-title">{label}</p>
        <p className="mt-0.5 text-[0.88rem] text-ink">{value}</p>
      </div>
    </div>
  );
}

/** A tappable line in the profile menu. `note` is the muted second row. */
export function MenuRow({
  icon,
  title,
  note,
  onClick,
  tone = 'default',
  testId,
  disabled,
  detail,
}: {
  icon?: ReactNode;
  title: string;
  note?: string;
  onClick?: () => void;
  tone?: 'default' | 'danger';
  testId?: string;
  disabled?: boolean;
  detail?: ReactNode;
}) {
  const Tag = onClick ? 'button' : 'div';
  return (
    <Tag
      type={onClick ? 'button' : undefined}
      onClick={onClick}
      disabled={disabled}
      data-testid={testId}
      className={`menu-row ${tone === 'danger' ? 'text-sev-critical' : ''}`}
    >
      {icon ? (
        <span aria-hidden className={`shrink-0 ${tone === 'danger' ? 'text-sev-critical' : 'text-brand'}`}>
          {icon}
        </span>
      ) : null}
      <span className="min-w-0 flex-1">
        <span className="block truncate font-medium">{title}</span>
        {note ? <span className="mt-0.5 block text-[0.74rem] font-normal text-ink-faint">{note}</span> : null}
      </span>
      {detail ?? null}
      {onClick ? (
        <span aria-hidden className="shrink-0 text-ink-faint">
          <IconChevronRightGlyph />
        </span>
      ) : null}
    </Tag>
  );
}

function IconChevronRightGlyph() {
  return (
    <svg aria-hidden width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9.5 6 15 12l-5.5 6" />
    </svg>
  );
}

export function Avatar({ initials, size = 56 }: { initials: string; size?: number }) {
  return (
    <span
      aria-hidden
      className="avatar"
      style={{ width: size, height: size, fontSize: Math.round(size * 0.34) }}
    >
      {initials}
    </span>
  );
}

/** Full-width modal used for the acknowledgement sheet and the action confirmations. */
export function Sheet({
  title,
  children,
  onClose,
  testId,
}: {
  title: string;
  children: ReactNode;
  onClose: () => void;
  testId?: string;
}) {
  return (
    <div className="fixed inset-0 z-50 flex items-end justify-center bg-black/70 p-0 sm:items-center sm:p-6">
      <div
        role="dialog"
        aria-modal="true"
        aria-label={title}
        data-testid={testId}
        className="animate-slide-up w-full max-w-[560px] rounded-t-tile bg-surface-card p-5 pb-[calc(var(--safe-bottom)+20px)] sm:rounded-tile sm:pb-5"
      >
        <div className="mb-3 flex items-start justify-between gap-3">
          <h2 className="text-[1rem] font-semibold text-ink">{title}</h2>
          <button type="button" onClick={onClose} aria-label="Close" className="px-2 py-1 text-ink-faint">
            <IconCloseGlyph />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}

function IconCloseGlyph() {
  return (
    <svg aria-hidden width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round">
      <path d="M6 6 18 18M18 6 6 18" />
    </svg>
  );
}


