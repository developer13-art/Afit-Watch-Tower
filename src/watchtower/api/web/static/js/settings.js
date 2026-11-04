/**
 * Settings for this console in this browser, plus the two things about the account itself that
 * belong on the same screen: the operator's own password, and the version of the server answering.
 *
 * Everything else here is a client setting: the interval this tab re-reads at, and whether this
 * tab beeps or raises a desktop notification when the server hands it a new alert. The server-side
 * alert preferences a person carries on their phone are edited in the personnel app, not here, and
 * this build has no console-side store for them.
 */

import { ApiError } from './api.js';
import {
  CAMERA_STATUS,
  fieldErrorSlot,
  gatingNotice,
  h,
  panel,
  render,
  showFieldError,
  statTile,
  statusChip,
} from './ui.js';
import { prefs, setPref } from './prefs.js';

const MIN_PASSWORD = 12;

const INTERVALS = [
  { value: 5000, label: '5 seconds' },
  { value: 10000, label: '10 seconds' },
  { value: 15000, label: '15 seconds' },
  { value: 20000, label: '20 seconds' },
  { value: 30000, label: '30 seconds' },
  { value: 60000, label: '1 minute' },
  { value: 120000, label: '2 minutes' },
];

export function mount(host, ctx) {
  const refreshHost = h('div.tab-content');
  const alertsHost = h('div.tab-content');
  const accountHost = h('div.tab-content');
  const devicesHost = h('div.tab-content');

  host.append(refreshHost, alertsHost, accountHost, devicesHost);

  paintRefresh();
  paintAlerts();
  paintAccount();
  paintDevices();

  function paintRefresh() {
    const select = h('select', { class: 'input', id: 'wt-pref-refresh', 'aria-label': 'Auto-refresh interval' });
    INTERVALS.forEach((option) => {
      select.append(h('option', { value: String(option.value), text: option.label, selected: option.value === prefs.refreshMs ? 'selected' : null }));
    });
    if (select.selectedIndex === -1) select.value = String(prefs.refreshMs);

    const apply = h('button', { type: 'button', class: 'btn primary', text: 'Apply interval' });
    apply.addEventListener('click', () => {
      const ms = Number(select.value);
      setPref('refreshMs', ms);
      ctx.setRefreshInterval(ms);
      ctx.toast(`Auto-refresh set to every ${Math.round(ms / 1000)}s in this browser.`, 'ok');
      paintRefresh();
    });

    render(refreshHost, panel('Refresh', [
      h('p.note', { text: 'Sections that poll the server - dashboard, cameras, live monitoring, incidents - re-read on this interval while the tab is visible.' }),
      h('div.form-field', [h('label', { for: 'wt-pref-refresh', text: 'Auto-refresh interval' }), select]),
      h('div.toolbar', [apply]),
      h('p.note', { text: `Stored in this browser only (currently ${describeInterval(prefs.refreshMs)}). The notification inbox is polled separately, every 30 seconds.` }),
    ]));
  }

  function paintAlerts() {
    const supported = typeof window.Notification === 'function';
    const permission = supported ? Notification.permission : 'unsupported';

    const soundToggle = toggleRow({
      id: 'wt-pref-sound',
      label: 'Sound alerts',
      checked: prefs.sound,
      detail: 'Plays a short tone in this tab when the server reports an alert this console has not already shown.',
      onChange: (value) => {
        setPref('sound', value);
        ctx.toast(value ? 'Alert sound armed for this browser.' : 'Alert sound off.', value ? 'ok' : 'muted');
      },
    });

    const desktopToggle = toggleRow({
      id: 'wt-pref-desktop',
      label: 'Desktop notifications',
      checked: prefs.desktop,
      detail: 'Raises a system notification outside the browser window for the same alerts.',
      onChange: (value, input) => {
        if (!value) {
          setPref('desktop', false);
          ctx.toast('Desktop notifications off.', 'muted');
          paintAlerts();
          return;
        }
        if (!supported) {
          input.checked = false;
          ctx.toast('This browser has no Notification API, so desktop alerts cannot be armed.', 'warn');
          return;
        }
        Notification.requestPermission().then((outcome) => {
          if (outcome === 'granted') {
            setPref('desktop', true);
            ctx.toast('Desktop notifications armed for this browser.', 'ok');
          } else {
            input.checked = false;
            setPref('desktop', false);
            ctx.toast(`The browser reported "${outcome}" for notification permission, so desktop alerts stay off.`, 'warn');
          }
          paintAlerts();
        });
      },
    });

    const test = h('button', { type: 'button', class: 'btn', text: 'Test both now' });
    test.addEventListener('click', () => {
      ctx.announceAlert({ title: 'WATCH TOWER test alert', body: 'If you can see and hear this, the console will announce real alerts the same way.' });
    });

    render(alertsHost, panel('Alerts in this tab', [
      h('p.note', { text: 'These fire only while this console is open in a browser. A closed tab cannot be alerted: the personnel mobile app is what carries alerts to a phone, on the server-side preferences that app edits.' }),
      soundToggle,
      desktopToggle,
      h('p.note', { text: supported ? `Browser permission: ${permission}.` : 'This browser does not expose a Notification API, so desktop alerts are unavailable here.' }),
      h('div.toolbar', [test]),
    ]));
  }

  function paintAccount() {
    const identity = ctx.identity;
    const current = passwordField('wt-pw-current', 'current_password', 'current-password');
    const next = passwordField('wt-pw-new', 'new_password', 'new-password');
    const again = passwordField('wt-pw-confirm', 'confirm_password', 'new-password');
    const outcome = h('p.note', { role: 'status' });
    const submit = h('button', { type: 'submit', class: 'btn primary', text: 'Change password' });

    // `novalidate` so the field messages below are the ones the operator reads: the browser's own
    // bubble would say "please fill out this field" in place of the sentence that explains why.
    const form = h('form.password-form', { novalidate: true }, [
      formField('current_password', 'Current password', current, 'Proves this is your own session; it is never stored.'),
      formField('new_password', 'New password', next, `At least ${MIN_PASSWORD} characters. The server hashes it and nothing here repeats it back.`),
      formField('confirm_password', 'Repeat the new password', again, null),
      h('div.toolbar', [submit]),
      outcome,
    ]);

    form.addEventListener('submit', (event) => {
      event.preventDefault();
      showFieldError(form, null, '');
      outcome.textContent = '';
      outcome.classList.remove('tone-fg-bad', 'tone-fg-ok');

      // Presence and length only. The server owns the credential check, so this never guesses
      // whether the current password is right - it only refuses an obviously unfinished form.
      if (!current.value) {
        showFieldError(form, 'current_password', 'Enter the password you are using now.');
        current.focus();
        return;
      }
      if (next.value.length < MIN_PASSWORD) {
        showFieldError(form, 'new_password', `Use at least ${MIN_PASSWORD} characters.`);
        next.focus();
        return;
      }
      if (next.value !== again.value) {
        showFieldError(form, 'confirm_password', 'The two entries do not match.');
        again.focus();
        return;
      }

      submit.disabled = true;
      submit.textContent = 'Changing...';
      // The call is made *inside* the chain. A helper that is missing - which is what a browser
      // holding one stale module out of the unhashed import graph produces - would otherwise throw
      // synchronously here, and the cleanup below would never run: the operator would be left with
      // a dead button and no sentence explaining it.
      Promise.resolve()
        .then(() => ctx.api.auth.changePassword(current.value, next.value))
        .then(() => {
          [current, next, again].forEach((input) => { input.value = ''; });
          outcome.classList.add('tone-fg-ok');
          outcome.textContent = 'Password changed. This browser keeps working on a freshly issued session; the token this request arrived with has been retired, so a copied cookie cannot outlive the change.';
        })
        .catch((error) => {
          outcome.classList.add('tone-fg-bad');
          outcome.textContent = error instanceof ApiError
            ? error.display
            : 'The password could not be changed. Nothing was saved.';
          current.select();
        })
        .finally(() => {
          submit.disabled = false;
          submit.textContent = 'Change password';
        });
    });

    render(accountHost, panel('Account and security', [
      h('div.counter-grid', [
        statTile({ label: 'Signed in as', value: identity.display_name, tone: 'info', note: `@${identity.username}`, icon: '☰' }),
        statTile({ label: 'Permissions granted', value: ctx.permissions.size, tone: 'muted', note: 'Resolved from every role grant this account holds.' }),
        statTile({ label: 'Role type', value: identity.is_administrative ? 'Administrative' : 'Operational', tone: identity.is_administrative ? 'warn' : 'ok', note: 'Administrative roles can change configuration; operational roles watch the post.' }),
        statTile({ label: 'Console version', value: identity.version || 'not reported', tone: 'muted', note: 'Answered by the server process this tab is talking to. This deployment publishes a version number and no separate build identifier.' }),
      ]),
      h('p.note', { text: 'Changing your password here affects this account only, and it is the password for the monitoring console. The personnel mobile app signs in through the cloud service.' }),
      form,
      h('div.toolbar', [
        h('button', { type: 'button', class: 'btn danger', text: 'Sign out', on: { click: () => ctx.signOut() } }),
      ]),
      ctx.permissions.size === 0
        ? h('p.note.tone-fg-warn', { text: 'This account holds no permission, so every other section of the rail is locked. Sign-in works; nothing else does until an administrator grants a role.' })
        : null,
    ]));
  }

  function paintDevices() {
    if (!ctx.can('camera.list')) {
      render(devicesHost, panel('Devices', [
        gatingNotice('camera.list', 'The camera estate is a registry the server holds; a role that cannot list cameras cannot summarise it.'),
      ]));
      return;
    }
    const cameras = ctx.cameras();
    const online = cameras.filter((camera) => camera.status === 'online').length;
    render(devicesHost, panel('Devices', [
      h('div.counter-grid', [
        statTile({ label: 'Cameras you can see', value: cameras.length, tone: 'info', note: 'Counted from the registry with your role\'s camera group grant applied.' }),
        statTile({ label: 'Delivering frames', value: online, tone: online ? 'ok' : 'warn', note: 'Reported status, measured by the health loop rather than asserted by the camera.' }),
      ]),
      cameras.length
        ? h('div.device-list', cameras.slice(0, 8).map((camera) => h('div.device-row', [
          h('span.device-code.mono', { text: camera.code }),
          h('span.device-name', { text: camera.display_name }),
          h('span.dim', { text: camera.campus_location }),
          statusChip(camera.status, CAMERA_STATUS),
        ])))
        : h('p.note', { text: 'No camera is registered that your role can read. Registration happens in Hardware; nothing can be monitored until at least one camera is connected and verified.' }),
      cameras.length > 8
        ? h('p.note', { text: `Showing 8 of ${cameras.length}. The registry lists them all.` })
        : null,
      h('div.toolbar', [
        h('button', { type: 'button', class: 'btn', text: 'Open the camera registry', on: { click: () => ctx.navigate('cameras') } }),
      ]),
      h('p.note', { text: 'Adding, verifying and removing devices is done in the Cameras and Hardware sections, which hold the forms that write to the registry. This panel is a summary, not a second editor - two places to change one record is how a registry drifts.' }),
    ]));
  }

  return { autoRefreshMs: 0, refresh: null, teardown: null };
}

function passwordField(id, name, autocomplete) {
  return h('input', { class: 'input', type: 'password', id, name, autocomplete, required: 'required' });
}

function formField(name, labelText, input, hint) {
  return h('div.form-field', { 'data-field': name }, [
    h('label', { for: input.id, text: labelText }),
    input,
    hint ? h('span.hint', { text: hint }) : null,
    fieldErrorSlot(),
  ]);
}

function toggleRow({ id, label, checked, detail, onChange }) {
  const input = h('input', { type: 'checkbox', id, class: 'switch-input', checked: checked ? 'checked' : null });
  input.addEventListener('change', (event) => onChange(event.target.checked, event.target));
  return h('div.form-field.check-field', [
    h('label', { for: id }, [input, h('span', { text: label })]),
    h('span.hint', { text: detail }),
  ]);
}

function describeInterval(ms) {
  return ms < 60000 ? `every ${Math.round(ms / 1000)} seconds` : `every ${Math.round(ms / 60000)} minute(s)`;
}
