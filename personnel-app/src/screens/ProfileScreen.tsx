/**
 * Profile hub (§3.2, §8.1).
 *
 * The hub holds identity and navigation only; the account record, the handset
 * list and the build facts each have their own screen, because a duty officer
 * checking "is this phone actually registered" should not have to scroll past a
 * permission dump to find out.
 *
 * The proposal asks for a "personnel identifier where available". `User` has no staff-number
 * column — only `username`, which is already the identity line under the name — so no separate
 * identifier is invented for the sake of the layout.
 */
import { useNavigate } from 'react-router-dom';
import { profileApi } from '../api/endpoints';
import { useAsync } from '../hooks/useAsync';
import type { ProfileResponse } from '../types/api';
import { ActionButton, Avatar, Chip, MenuRow, SectionCard } from '../components/ui';
import { AsyncBoundary, ErrorState } from '../components/States';
import { ScreenHeader } from '../components/Shell';
import { ROLE_NAMES } from '../auth/permissions';
import { useSession } from '../auth/SessionProvider';
import { IconDevice, IconInfo, IconKey, IconLogout, IconShield, IconSliders, IconUser } from '../components/icons';

/** Two letters is what fits a 56px disc without becoming a postcode. */
function initialsOf(displayName: string, username: string): string {
  const source = displayName.trim() || username.trim();
  const parts = source.split(/[\s._-]+/).filter(Boolean);
  if (parts.length >= 2) return (parts[0][0] + parts[1][0]).toUpperCase();
  return source.slice(0, 2).toUpperCase();
}

export function ProfileScreen() {
  const navigate = useNavigate();
  const { state, logout, app } = useSession();
  const profile = useAsync<ProfileResponse>(() => profileApi.get(), [state.revision]);

  return (
    <div className="screen">
      <ScreenHeader
        title="Profile"
        subtitle={app?.installationId ? `Device ${app.installationId.slice(0, 8)}` : undefined}
        actions={
          <button
            type="button"
            onClick={() => void profile.reload()}
            aria-label="Reload profile"
            className="flex h-11 w-11 items-center justify-center rounded-full text-ink-muted active:bg-surface-overlay"
          >
            <IconUser size={19} />
          </button>
        }
      />

      <AsyncBoundary state={profile} loadingLabel="Loading profile">
        {(data) => {
          const status = accountStatus(data);
          const primaryRole = (data.roles_with_descriptions ?? [])[0] ?? (data.roles ?? [])[0];
          const roleLabel =
            typeof primaryRole === 'string'
              ? ROLE_NAMES[primaryRole] ?? primaryRole
              : primaryRole?.name || primaryRole?.code || 'No role assigned';
          return (
            <div className="space-y-3">
              <section className="panel p-4">
                <div className="flex items-center gap-3.5">
                  <Avatar initials={initialsOf(data.display_name, data.username)} size={58} />
                  <div className="min-w-0">
                    <p className="truncate text-[1.05rem] font-semibold text-ink">{data.display_name}</p>
                    <p className="tabular truncate text-[0.78rem] text-ink-muted">{data.username}</p>
                    <p className="mt-1 truncate text-[0.74rem] text-ink-faint">{roleLabel}</p>
                  </div>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-surface-line pt-3">
                  <Chip tone={status.tone}>{status.label}</Chip>
                  {(data.roles_with_descriptions ?? []).slice(1).map((r) => (
                    <Chip key={r.code} tone="brand">
                      {r.name || r.code}
                    </Chip>
                  ))}
                  <span className="tabular ml-auto text-[0.68rem] text-ink-faint">id {data.id}</span>
                </div>
              </section>

              {profile.error && profile.status === 'error' ? (
                <ErrorState error={profile.error} onRetry={() => void profile.reload()} />
              ) : null}

              <SectionCard title="Account">
                <MenuRow
                  icon={<IconInfo size={19} />}
                  title="Account information"
                  note="Name, contact, role, camera scope and your effective permissions"
                  onClick={() => navigate('/profile/account')}
                  testId="menu-account"
                />
                <MenuRow
                  icon={<IconSliders size={19} />}
                  title="Notification preferences"
                  note="Minimum severity, alert kinds, quiet hours, sound"
                  onClick={() => navigate('/settings/notifications')}
                  testId="menu-preferences"
                />
                <MenuRow
                  icon={<IconDevice size={19} />}
                  title="Device status"
                  note="Whether this handset is registered for duty alerts, and every device on your account"
                  onClick={() => navigate('/profile/devices')}
                  testId="menu-devices"
                />
                <MenuRow
                  icon={<IconShield size={19} />}
                  title="Incidents"
                  note="History, active queue and investigation notes"
                  onClick={() => navigate('/incidents')}
                  testId="menu-incidents"
                />
              </SectionCard>

              <SectionCard title="Security">
                <MenuRow
                  icon={<IconKey size={19} />}
                  title="Change password"
                  note="Rotates every refresh token on every device"
                  onClick={() => navigate('/password')}
                  testId="menu-password"
                />
                <MenuRow
                  icon={<IconInfo size={19} />}
                  title="About this build"
                  note="Version, service endpoint, live updates and what is not configured"
                  onClick={() => navigate('/profile/about')}
                  testId="menu-about"
                />
              </SectionCard>

              <section className="panel p-4">
                <p className="flex items-center gap-2 text-[0.88rem] font-semibold text-ink">
                  <IconLogout size={18} aria-hidden />
                  Sign out
                </p>
                <p className="mt-1 text-[0.75rem] leading-snug text-ink-muted">
                  Clears the token family stored on this device. Nothing about the incident record changes.
                </p>
                <div className="mt-3 grid grid-cols-2 gap-2">
                  <ActionButton variant="secondary" onClick={() => void logout({ forgetDevice: false })}>
                    Sign out
                  </ActionButton>
                  <ActionButton variant="danger" onClick={() => navigate('/profile/devices')}>
                    Forget this device
                  </ActionButton>
                </div>
                <p className="mt-2 text-[0.7rem] leading-snug text-ink-faint">
                  &quot;Forget this device&quot; is on the device screen, where the consequence is explained next to the row it
                  applies to.
                </p>
              </section>
            </div>
          );
        }}
      </AsyncBoundary>
    </div>
  );
}

/** §G "account status": derived, because the service returns two booleans and no status enum. */
function accountStatus(data: ProfileResponse): { label: string; tone: 'ok' | 'warn' | 'bad' } {
  if (!data.is_active) return { label: 'Account disabled', tone: 'bad' };
  if (data.must_change_password) return { label: 'Temporary password in use', tone: 'warn' };
  return { label: 'Account active', tone: 'ok' };
}
