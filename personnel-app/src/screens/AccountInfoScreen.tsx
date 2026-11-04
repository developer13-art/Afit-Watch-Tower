/**
 * Account information (§3.2, §8.1) — the read-only record behind the profile hub.
 *
 * Roles, permissions and camera scope are what the server resolved for this
 * session, not what an administrator once typed: `views._scope()` answers per
 * permission, so the screen shows the scope of each grant it actually holds
 * rather than one merged "you can see everything".
 */
import { profileApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import type { GroupScope, ProfileResponse } from '../types/api';
import { ROLE_NAMES } from '../auth/permissions';
import { ActionButton, Avatar, Chip, InfoRow, MenuRow, SectionCard } from '../components/ui';
import { AsyncBoundary } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { IconDevice, IconInfo, IconKey, IconMail, IconShield, IconUser } from '../components/icons';
import { formatDateTime } from '../lib/time';
import { useNavigate } from 'react-router-dom';

function initialsOf(displayName: string, username: string): string {
  const parts = (displayName.trim() || username.trim()).split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return (displayName.trim() || username).slice(0, 2).toUpperCase();
}

/** `views._scope()` answers per permission with either `"all"` or a list of camera-group ids. */
function scopeText(scope: GroupScope | undefined): string {
  if (scope === undefined) return 'not granted';
  if (scope === 'all') return 'all camera groups';
  return `${scope.length} group${scope.length === 1 ? '' : 's'}`;
}

export function AccountInfoScreen() {
  const navigate = useNavigate();
  const profile = useAsync<ProfileResponse>(() => profileApi.get(), []);

  return (
    <div className="screen">
      <ScreenHeader title="Account information" back="/profile" />

      <AsyncBoundary state={profile} loadingLabel="Loading account">
        {(data) => (
          <div className="space-y-3">
            <section className="panel p-4">
              <div className="flex items-center gap-3.5">
                <Avatar initials={initialsOf(data.display_name, data.username)} size={54} />
                <div className="min-w-0">
                  <p className="truncate text-[1rem] font-semibold text-ink">{data.display_name}</p>
                  <p className="tabular truncate text-[0.76rem] text-ink-muted">{data.username}</p>
                </div>
              </div>
              {data.must_change_password ? (
                <div className="mt-3 rounded-card border border-sev-medium/50 bg-sev-medium/10 p-3">
                  <p className="text-[0.8rem] font-semibold text-sev-medium">Temporary password in use</p>
                  <p className="mt-1 text-[0.74rem] leading-snug text-ink-muted">
                    The service will refuse every other route until it is changed.
                  </p>
                  <ActionButton variant="secondary" className="mt-2" onClick={() => navigate('/password')}>
                    Change password now
                  </ActionButton>
                </div>
              ) : null}
            </section>

            <SectionCard title="Identity">
              <InfoRow icon={<IconUser size={18} />} label="Username" value={data.username} />
              <InfoRow icon={<IconInfo size={18} />} label="Display name" value={data.display_name} />
              <InfoRow
                icon={<IconMail size={18} />}
                label="Email"
                value={data.email ?? 'Not recorded — an administrator sets this in the monitoring console'}
              />
              <InfoRow
                icon={<IconDevice size={18} />}
                label="Phone"
                value={data.phone ?? 'Not recorded'}
              />
              <InfoRow
                icon={<IconKey size={18} />}
                label="Last sign-in"
                value={data.last_login_at ? formatDateTime(data.last_login_at) : 'This is your first recorded sign-in'}
              />
              <InfoRow icon={<IconShield size={18} />} label="User id" value={<span className="tabular">{data.id}</span>} />
            </SectionCard>

            <SectionCard title="Roles">
              {(data.roles_with_descriptions ?? []).length > 0 || (data.roles ?? []).length > 0 ? (
                <div className="flex flex-wrap gap-2 p-4">
                  {(data.roles_with_descriptions ?? []).map((r) => (
                    <Chip key={r.code} tone="brand">
                      {r.name || ROLE_NAMES[r.code] || r.code}
                    </Chip>
                  ))}
                  {(data.roles ?? [])
                    .filter((code) => !(data.roles_with_descriptions ?? []).some((r) => r.code === code))
                    .map((code) => (
                      <Chip key={code} tone="neutral">
                        {ROLE_NAMES[code] ?? code}
                      </Chip>
                    ))}
                </div>
              ) : (
                <p className="p-4 text-[0.78rem] text-ink-muted">
                  No role is attached to this account, which is why the permission list below is what actually decides what
                  you can open.
                </p>
              )}
              {(data.roles_with_descriptions ?? []).filter((r) => r.description).length > 0 ? (
                <ul className="border-t border-surface-line px-4 py-3 text-[0.72rem] leading-snug text-ink-faint">
                  {(data.roles_with_descriptions ?? [])
                    .filter((r) => r.description)
                    .map((r) => (
                      <li key={r.code} className="mt-1 first:mt-0">
                        <span className="font-semibold text-ink-muted">{r.name || r.code}:</span> {r.description}
                      </li>
                    ))}
                </ul>
              ) : null}
            </SectionCard>

            <SectionCard title="Camera scope">
              <InfoRow
                icon={<IconShield size={18} />}
                label="Incident records"
                value={scopeText(data.camera_scope?.['incident.view'])}
              />
              <InfoRow
                icon={<IconInfo size={18} />}
                label="Evidence"
                value={scopeText(data.camera_scope?.['evidence.view'])}
              />
              <p className="border-t border-surface-line p-4 text-[0.72rem] leading-snug text-ink-faint">
                A scope the service does not grant for a permission is shown as &quot;not granted&quot; rather than zero: an
                empty list and no list mean different things here, and the app is not permitted to guess.
              </p>
            </SectionCard>

            <SectionCard title={`Effective permissions (${(data.permissions ?? []).length})`}>
              <div className="flex flex-wrap gap-1.5 p-4">
                {(data.permissions ?? []).length === 0 ? (
                  <p className="text-[0.78rem] text-ink-muted">
                    The service granted this session no permissions. Sign-in still works; every action route will answer 403.
                  </p>
                ) : (
                  (data.permissions ?? []).map((p) => (
                    <span
                      key={p}
                      className="tabular rounded-wt border border-surface-line bg-surface-raised px-1.5 py-0.5 text-[0.66rem] text-ink-muted"
                    >
                      {p}
                    </span>
                  ))
                )}
              </div>
            </SectionCard>

            <MenuRow
              icon={<IconInfo size={19} />}
              title="Why this list can change without warning"
              note="Permissions are resolved from the database on every request (§2.5), so a revoked grant stops working on your next action — you do not need to sign out first."
            />
          </div>
        )}
      </AsyncBoundary>
    </div>
  );
}
