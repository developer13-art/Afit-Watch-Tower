/**
 * AFIT WATCH TOWER - sign-in page behaviour.
 *
 * The login endpoint is JSON (`POST /api/auth/login`) and sets an httpOnly cookie, so the
 * form cannot be a plain HTML submission; it is posted through the single apiFetch helper in
 * api.js. CSP forbids inline handlers, which is why this lives in its own module.
 *
 * The reason a person landed here is not always their own doing: a dashboard session that
 * expired bounces here and leaves a note in sessionStorage, and that note is shown rather
 * than making the operator guess whether their credentials were rejected.
 */

import { api, ApiError, takeSessionNotice } from './api.js';

const NOTICE = document.getElementById('login-notice');
const ERROR = document.getElementById('login-error');
const FORM = document.getElementById('login-form');
const SUBMIT = document.getElementById('login-submit');
const USERNAME = document.getElementById('username');
const PASSWORD = document.getElementById('password');

function showMessage(node, text) {
  if (!node) return;
  node.textContent = text || '';
  node.hidden = !text;
}

function setFieldError(name, message) {
  ['username', 'password'].forEach((field) => {
    const wrapper = document.querySelector(`[data-field="${field}"]`);
    if (!wrapper) return;
    const slot = wrapper.querySelector('.field-error');
    const isMatch = field === name && Boolean(message);
    wrapper.classList.toggle('has-error', isMatch);
    if (slot) slot.textContent = isMatch ? message : '';
  });
}

function setBusy(isBusy) {
  if (!SUBMIT) return;
  if (!SUBMIT.dataset.idleLabel) SUBMIT.dataset.idleLabel = SUBMIT.textContent;
  SUBMIT.disabled = isBusy;
  if (isBusy) SUBMIT.setAttribute('aria-busy', 'true');
  else SUBMIT.removeAttribute('aria-busy');
  SUBMIT.textContent = isBusy ? 'Signing in...' : SUBMIT.dataset.idleLabel;
}

async function submit(event) {
  event.preventDefault();
  setFieldError(null, null);
  showMessage(ERROR, '');

  const username = (USERNAME.value || '').trim();
  const password = PASSWORD.value || '';

  // Client-side presence only: the server owns the credential check and the lockout counter,
  // so nothing here tries to predict whether the password is correct.
  if (!username) {
    setFieldError('username', 'Enter your username.');
    USERNAME.focus();
    return;
  }
  if (!password) {
    setFieldError('password', 'Enter your password.');
    PASSWORD.focus();
    return;
  }

  setBusy(true);
  try {
    await api.auth.login(username, password);
    // The cookie is set by the response above; /dashboard then reads it via /api/auth/me.
    window.location.replace('/dashboard');
  } catch (error) {
    setBusy(false);
    if (error instanceof ApiError) {
      showMessage(ERROR, error.display);
      if (error.field) setFieldError(error.field, error.display);
      // A locked account will not benefit from another attempt straight away.
      if (error.code === 'account_locked') {
        setBusy(true);
        window.setTimeout(() => setBusy(false), 15000);
      }
    } else {
      showMessage(ERROR, 'Sign-in could not be completed. Check the console address and retry.');
    }
    PASSWORD.focus();
    PASSWORD.select();
  }
}

function init() {
  if (!FORM) return;

  const notice = takeSessionNotice();
  showMessage(NOTICE, notice || '');
  FORM.addEventListener('submit', submit);

  const first = notice ? PASSWORD : USERNAME;
  first.focus();
}

init();
