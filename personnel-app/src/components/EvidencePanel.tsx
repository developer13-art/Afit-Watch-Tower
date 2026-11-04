/**
 * Evidence panel (§7).
 *
 * Rules enforced here:
 *   - The asset list is fetched with the session; the bytes are fetched with
 *     the short-lived single-asset URL only. The bearer token is never attached
 *     to a pre-signed URL — appending it would leak the session to the storage
 *     host.
 *   - `processing`, `expired`, `deleted` and `unavailable` are each rendered as
 *     their own state with the contract's meaning explained. A broken image
 *     icon is not an acceptable answer for "the monitoring station is still
 *     uploading".
 *   - When `expires_at` has passed the panel offers a re-fetch rather than
 *     showing a dead link.
 *   - Nothing is cached on the device: no service worker, no storage write.
 */
import { useState } from 'react';
import { evidenceApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import type { EvidenceAsset } from '../types/api';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';
import { ActionButton, Chip, EvidenceStateChip } from './ui';
import { EmptyState, ErrorState, ForbiddenState, LoadingState, UnauthorizedState } from './States';
import { evidenceStateMeta } from '../lib/severity';
import { formatDateTime, isExpired } from '../lib/time';
import { useSession } from '../auth/SessionProvider';
import { PERMISSION } from '../auth/permissions';

function ImageAsset({ asset }: { asset: EvidenceAsset }) {
  const [failed, setFailed] = useState(false);
  if (failed) {
    return (
      <div role="alert" className="border border-sev-critical/50 bg-sev-critical/10 p-3 text-[0.78rem] text-sev-critical">
        The image bytes could not be fetched. The link may have lapsed — use Refetch link below.
      </div>
    );
  }
  return (
    <img
      src={asset.url ?? ''}
      alt={`Evidence ${asset.id} for this incident (${asset.content_type})`}
      onError={() => setFailed(true)}
      className="w-full rounded-wt border border-surface-line object-contain"
      loading="lazy"
      decoding="async"
    />
  );
}

function VideoAsset({ asset }: { asset: EvidenceAsset }) {
  const [failed, setFailed] = useState(false);
  if (failed) {
    return (
      <div role="alert" className="border border-sev-critical/50 bg-sev-critical/10 p-3 text-[0.78rem] text-sev-critical">
        This clip could not be played. Range requests may be unsupported by the serving host, or the link lapsed.
      </div>
    );
  }
  return (
    <video
      // `preload="metadata"` makes the first request a range request, which is
      // exactly what §7.2 requires for seeking on the Android WebView player.
      src={asset.url ?? ''}
      controls
      playsInline
      preload="metadata"
      onError={() => setFailed(true)}
      className="w-full border border-surface-line"
    />
  );
}

export function EvidencePanel({ incidentId }: { incidentId: number }) {
  const { can } = useSession();
  const mayView = can(PERMISSION.evidenceView);

  const state = useAsync(
    async () => {
      if (!mayView) throw new ApiError({ code: ERROR_CODES.FORBIDDEN, message: 'evidence.view is required.', status: 403 });
      return evidenceApi.list(incidentId);
    },
    [incidentId, mayView],
    { isEmpty: (r) => r.items.length === 0, enabled: mayView },
  );

  if (!mayView) {
    return (
      <section aria-labelledby="evidence-heading" className="mt-4">
        <h2 id="evidence-heading" className="section-title mb-2">
          Evidence
        </h2>
        <ForbiddenState
          permission={PERMISSION.evidenceView}
          body="Evidence is not shown for this incident because your account does not hold evidence.view. The incident record itself remains visible."
        />
      </section>
    );
  }

  // The *link* expiry, not the asset's retention date. An asset past retention is reported by
  // the server as state `expired` and never carries a URL, so checking `expires_at` here would
  // warn about a link that was already replaced by a state chip.
  const anyLinkExpired =
    state.data?.items.some((a) => a.state === 'available' && isExpired(a.expires_at_token)) ?? false;

  return (
    <section aria-labelledby="evidence-heading" className="mt-4">
      <div className="mb-2 flex items-center justify-between">
        <h2 id="evidence-heading" className="section-title">
          Evidence
        </h2>
        <ActionButton variant="ghost" busy={state.refreshing} onClick={() => void state.reload()} data-testid="refetch-evidence">
          Refetch links
        </ActionButton>
      </div>

      {anyLinkExpired ? (
        <p className="mb-2 border border-sev-medium/50 bg-sev-medium/10 p-2 text-[0.74rem] leading-snug text-sev-medium">
          One or more access links have passed their expiry. Use Refetch links to obtain new short-lived URLs. Nothing is
          stored on this device.
        </p>
      ) : null}

      {state.status === 'loading' ? <LoadingState label="Fetching evidence" /> : null}
      {state.status === 'unauthorized' ? <UnauthorizedState /> : null}
      {state.status === 'forbidden' ? <ForbiddenState permission={PERMISSION.evidenceView} /> : null}
      {state.status === 'empty' ? (
        <EmptyState
          title="No evidence attached"
          body="This incident has no stored asset. Candidate events can be recorded without a snapshot when the camera stream dropped."
        />
      ) : null}
      {state.status === 'error' && state.error ? <ErrorState error={state.error} onRetry={() => void state.reload()} /> : null}

      {state.data ? (
        <ul className="space-y-3">
          {state.data.items.map((asset) => {
            const meta = evidenceStateMeta(asset.state);
            const linkDead = asset.state === 'available' && isExpired(asset.expires_at_token);
            return (
              <li key={asset.id} className="card p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Chip tone="neutral">{asset.kind}</Chip>
                  <EvidenceStateChip state={asset.state} />
                  <span className="tabular ml-auto text-[0.66rem] text-ink-faint">
                    {asset.byte_size != null ? `${(asset.byte_size / 1024).toFixed(0)} KB` : 'size unknown'}
                  </span>
                </div>
                <p className="mt-1 text-[0.75rem] text-ink-muted">
                  Captured {formatDateTime(asset.captured_at)}
                  {/* The two expiries say different things and are shown separately: the link
                      lapses in minutes and can be re-minted, the retention date is the asset's
                      own and cannot. */}
                  {asset.expires_at_token
                    ? ` · link expires ${formatDateTime(asset.expires_at_token)}`
                    : ''}
                  {asset.expires_at ? ` · retained until ${formatDateTime(asset.expires_at)}` : ''}
                </p>
                <p className="mt-1 text-[0.76rem] leading-snug text-ink-faint">{meta.explanation}</p>

                {meta.renderable && !linkDead && asset.url ? (
                  <div className="mt-2">
                    {asset.content_type.startsWith('image/') ? (
                      <ImageAsset asset={asset} />
                    ) : asset.content_type.startsWith('video/') ? (
                      <VideoAsset asset={asset} />
                    ) : (
                      <a
                        href={asset.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className="btn-secondary w-full"
                      >
                        Open {asset.content_type}
                      </a>
                    )}
                  </div>
                ) : null}

                {linkDead ? (
                  <div className="mt-2">
                    {/* Not `EvidenceStateChip state="expired"`: that is the server's word for an
                        asset past retention, which cannot be recovered. This one can. */}
                    <Chip tone="warn">Link lapsed</Chip>
                    <p className="mt-1 text-[0.76rem] text-ink-muted">
                      The asset is still held; only this signed link has run out. Use Refetch links.
                    </p>
                  </div>
                ) : null}

                {asset.sha256 ? (
                  <p className="tabular mt-2 break-all text-[0.64rem] text-ink-faint" title="Integrity digest">
                    sha256 {asset.sha256}
                  </p>
                ) : null}
              </li>
            );
          })}
        </ul>
      ) : null}

      <p className="mt-2 text-[0.7rem] leading-snug text-ink-faint">
        Links are single-asset, expire in minutes and are audited as <span className="tabular">evidence.view</span> on every
        read. There is no permanent public URL for any of these files.
      </p>
    </section>
  );
}
