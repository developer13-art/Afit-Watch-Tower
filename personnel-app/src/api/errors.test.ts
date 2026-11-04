/**
 * Error normalisation: whatever the network layer hands back, the screens receive one `ApiError`
 * with a code the server really uses, a status, and text that does not leak.
 */
import { describe, expect, it } from 'vitest';

import { ApiError, codeForStatus, describeCode, errorFromResponse, networkError } from './errors';
import { ERROR_CODES } from '../types/api';

function response(init: { status: number; body?: string; contentType?: string; headers?: Record<string, string> }) {
  const headers: Record<string, string> = { ...(init.headers ?? {}) };
  if (init.contentType) headers['content-type'] = init.contentType;
  return new Response(init.body ?? null, { status: init.status, headers });
}

describe('codeForStatus', () => {
  it('uses the server word when a status has exactly one', () => {
    expect(codeForStatus(401)).toBe(ERROR_CODES.AUTHENTICATION_REQUIRED);
    expect(codeForStatus(403)).toBe(ERROR_CODES.FORBIDDEN);
    expect(codeForStatus(404)).toBe(ERROR_CODES.NOT_FOUND);
    expect(codeForStatus(422)).toBe(ERROR_CODES.VALIDATION_FAILED);
    expect(codeForStatus(429)).toBe(ERROR_CODES.RATE_LIMITED);
    expect(codeForStatus(500)).toBe(ERROR_CODES.INTERNAL_ERROR);
    expect(codeForStatus(503)).toBe(ERROR_CODES.STORAGE_UNAVAILABLE);
  });

  it('refuses to guess where one status carries several meanings', () => {
    // 409 is `incident_not_actionable`, `not_resolved`, `escalation_target_unavailable` or
    // `session_revoked`; naming one of them would make the app explain the wrong refusal.
    expect(codeForStatus(409)).toBe(ERROR_CODES.UNKNOWN);
    expect(codeForStatus(418)).toBe(ERROR_CODES.UNKNOWN);
  });
});

describe('errorFromResponse', () => {
  it('reads the contract envelope', async () => {
    const error = await errorFromResponse(
      response({
        status: 409,
        contentType: 'application/json',
        body: JSON.stringify({
          error: { code: ERROR_CODES.INCIDENT_NOT_ACTIONABLE, message: 'Already closed.', request_id: 'srv_1' },
        }),
      }),
      'req_local',
    );
    expect(error).toBeInstanceOf(ApiError);
    expect(error.code).toBe(ERROR_CODES.INCIDENT_NOT_ACTIONABLE);
    expect(error.message).toBe('Already closed.');
    // The server's own id wins: it is the one that finds the request in the logs.
    expect(error.requestId).toBe('srv_1');
    expect(error.status).toBe(409);
    expect(error.isConflict).toBe(true);
  });

  it('takes the request id from the header when the body has none', async () => {
    const error = await errorFromResponse(
      response({ status: 500, headers: { 'x-request-id': 'hdr_9' }, body: '' }),
      'req_local',
    );
    expect(error.requestId).toBe('hdr_9');
    expect(error.code).toBe(ERROR_CODES.INTERNAL_ERROR);
    // An empty body still produces operator-facing text, not the empty string.
    expect(error.userMessage).not.toBe('');
  });

  it('does not surface a proxy page', async () => {
    const error = await errorFromResponse(
      response({
        status: 502,
        contentType: 'text/html',
        body: '<html>502 Bad Gateway — upstream /api/v1/incidents on internal-host-7</html>',
      }),
      'req_5',
    );
    expect(error.kind).toBe('http');
    // An internal hostname or a gateway page is not something an operator can act on, and it is
    // a description of the private network the app must never reveal.
    expect(error.message).not.toMatch(/internal-host|Bad Gateway/);
  });

  it('carries retry-after for a throttled action', async () => {
    const error = await errorFromResponse(
      response({
        status: 429,
        contentType: 'application/json',
        headers: { 'retry-after': '37' },
        body: JSON.stringify({ error: { code: ERROR_CODES.TOO_MANY_ACTIONS, message: 'Slow down.' } }),
      }),
      'req_6',
    );
    expect(error.isRateLimited).toBe(true);
    expect(error.retryAfterSeconds).toBe(37);
  });

  it('understands FastAPI detail bodies as well as the envelope', async () => {
    const error = await errorFromResponse(
      response({ status: 422, contentType: 'application/json', body: JSON.stringify({ detail: 'field required' }) }),
      'req_7',
    );
    expect(error.code).toBe(ERROR_CODES.VALIDATION_FAILED);
    expect(error.message).toBe('field required');
  });
});

describe('describeCode', () => {
  it('explains the codes an operator can actually meet', () => {
    for (const code of [
      ERROR_CODES.PASSWORD_CHANGE_REQUIRED,
      ERROR_CODES.ACCOUNT_LOCKED,
      ERROR_CODES.TOO_MANY_ACTIONS,
      ERROR_CODES.ESCALATION_TARGET_UNAVAILABLE,
      ERROR_CODES.EVIDENCE_EXPIRED,
      ERROR_CODES.REFRESH_REUSED,
      ERROR_CODES.STORAGE_UNAVAILABLE,
    ]) {
      // Silence here means a screen renders the raw snake_case to a duty officer.
      expect(describeCode(code), code).not.toBe(code);
      expect(describeCode(code).length).toBeGreaterThan(8);
    }
  });

  it('does not invent a story for a code it has never seen', () => {
    expect(describeCode('made_up_code')).not.toMatch(/made.up/i);
  });
});

describe('networkError', () => {
  it('separates offline from a timeout and from a failed connection', () => {
    expect(networkError(new TypeError('Failed to fetch'), 'req_8', false, true).kind).toBe('offline');
    expect(networkError(new DOMException('aborted', 'AbortError'), 'req_8', true, false).kind).toBe('timeout');
    expect(networkError(new TypeError('Failed to fetch'), 'req_8', false, false).kind).toBe('network');
  });

  it('is retryable information, not a server fault', () => {
    const error = networkError(new TypeError('Failed to fetch'), 'req_8', false, true);
    expect(error.isConnectivity).toBe(true);
    expect(error.status).toBe(0);
    expect(error.userMessage).toMatch(/offline/i);
  });
});
