/**
 * The endpoint guard (contract §0, and the correction of 2026-11-03).
 *
 * A release build that resolves to a loopback address produced a phone that could not sign anybody
 * in and still looked like a working product; a release build that resolves to plain HTTP would
 * carry an officer's password across a café network. The login screen now reads these four fields
 * and decides whether to send anything at all, so the classification is asserted here rather than
 * discovered on a handset.
 *
 * Both configuration keys are exercised the way `env.ts` passes them: `apiUrl` is `VITE_API_URL`
 * verbatim, `apiBaseUrl` is `VITE_API_BASE_URL` verbatim, and this module appends the version prefix.
 */
import { describe, expect, it } from 'vitest';

import { resolveApiConfig } from './apiUrl';

const DEV = { isDev: true } as const;
const BUILT = { isDev: false } as const;

describe('the two configuration keys', () => {
  it('appends the contract version prefix to an origin', () => {
    expect(resolveApiConfig({ ...BUILT, apiBaseUrl: 'https://watchtower.example' }).apiUrl).toBe(
      'https://watchtower.example/api/v1',
    );
  });

  it('tolerates a trailing slash on the origin', () => {
    expect(resolveApiConfig({ ...BUILT, apiBaseUrl: 'https://watchtower.example/' }).apiUrl).toBe(
      'https://watchtower.example/api/v1',
    );
  });

  it('does not double the prefix when the full base is pasted into the origin key', () => {
    expect(resolveApiConfig({ ...BUILT, apiBaseUrl: 'https://watchtower.example/api/v1' }).apiUrl).toBe(
      'https://watchtower.example/api/v1',
    );
  });

  it('uses a full base verbatim, because a proxy may mount the API anywhere', () => {
    expect(resolveApiConfig({ ...BUILT, apiUrl: 'https://watchtower.example/gateway/mobile' }).apiUrl).toBe(
      'https://watchtower.example/gateway/mobile',
    );
  });

  it('prefers an explicit full base over the origin it was also given', () => {
    const config = resolveApiConfig({
      ...BUILT,
      apiUrl: 'https://api.example/api/v1',
      apiBaseUrl: 'https://other.example',
    });
    expect(config.apiUrl).toBe('https://api.example/api/v1');
  });
});

describe('nothing configured', () => {
  it('reports unconfigured instead of guessing a host', () => {
    const config = resolveApiConfig({ ...BUILT, apiUrl: '', apiBaseUrl: '' });
    expect(config.state).toBe('unconfigured');
    expect(config.apiUrl).toBe('');
    expect(config.apiOrigin).toBe('');
    expect(config.reason).toMatch(/No cloud API endpoint is configured/);
  });

  it('blocks sign-in in a development build too — an unset endpoint is not a local path', () => {
    expect(resolveApiConfig({ ...DEV, apiUrl: '', apiBaseUrl: '' }).blocksSignIn).toBe(true);
  });

  it('treats a host without a scheme as unconfigured, not as a relative path', () => {
    const config = resolveApiConfig({ ...BUILT, apiUrl: 'watchtower.example.afit.edu.ng/api/v1' });
    expect(config.state).toBe('unconfigured');
    expect(config.apiUrl).toBe('');
  });

  it('rejects a scheme that cannot carry a request', () => {
    expect(resolveApiConfig({ ...BUILT, apiUrl: 'ftp://watchtower.example/api/v1' }).state).toBe('unconfigured');
  });
});

describe('a cloud host over HTTPS', () => {
  it('is ready and sends credentials', () => {
    const config = resolveApiConfig({ ...BUILT, apiUrl: 'https://watchtower.example.afit.edu.ng/api/v1' });
    expect(config).toMatchObject({
      state: 'ready',
      apiUrl: 'https://watchtower.example.afit.edu.ng/api/v1',
      apiOrigin: 'https://watchtower.example.afit.edu.ng',
      blocksSignIn: false,
      reason: '',
    });
  });

  it('is ready in a development build as well', () => {
    expect(resolveApiConfig({ ...DEV, apiUrl: 'https://watchtower.example/api/v1' }).state).toBe('ready');
  });

  it('drops a trailing slash so the client never builds a double-slash path', () => {
    expect(resolveApiConfig({ ...BUILT, apiUrl: 'https://watchtower.example/api/v1/' }).apiUrl).toBe(
      'https://watchtower.example/api/v1',
    );
  });

  it('accepts a non-standard port — TLS on 8443 is still HTTPS', () => {
    expect(resolveApiConfig({ ...BUILT, apiUrl: 'https://watchtower.example:8443/api/v1' }).state).toBe('ready');
  });
});

describe('a loopback address', () => {
  for (const host of ['localhost', '127.0.0.1', '0.0.0.0', '[::1]', 'dev.watchtower.localhost']) {
    it(`is classified local for ${host}`, () => {
      expect(resolveApiConfig({ ...DEV, apiUrl: `http://${host}:8080/api/v1` }).state).toBe('local');
    });
  }

  it('keeps the labelled development path working', () => {
    expect(resolveApiConfig({ ...DEV, apiUrl: 'http://127.0.0.1:8080/api/v1' }).blocksSignIn).toBe(false);
  });

  it('blocks sign-in in a packaged build — the defect that shipped', () => {
    const config = resolveApiConfig({ ...BUILT, apiUrl: 'http://127.0.0.1:8080/api/v1' });
    expect(config.state).toBe('local');
    expect(config.blocksSignIn).toBe(true);
    expect(config.reason).toMatch(/only this computer or this LAN can reach/);
  });

  it('says which of the two addresses it is', () => {
    expect(resolveApiConfig({ ...BUILT, apiUrl: 'http://localhost:8080/api/v1' }).reason).toMatch(/loopback/);
    expect(resolveApiConfig({ ...BUILT, apiUrl: 'http://10.4.0.9:8080/api/v1' }).reason).toMatch(/private network/);
  });
});

describe('a private network address', () => {
  for (const host of ['10.0.0.5', '192.168.1.40', '172.16.0.2', '172.31.255.1', '100.64.0.1']) {
    it(`is local, not a production endpoint: ${host}`, () => {
      expect(resolveApiConfig({ ...BUILT, apiUrl: `http://${host}:8080/api/v1` }).state).toBe('local');
    });
  }

  it('does not mistake a public address that merely starts with those digits', () => {
    for (const host of ['10example.org', '192.1680.example', '172.15.0.1', '172.32.0.1', '100.63.0.1']) {
      expect(resolveApiConfig({ ...BUILT, apiUrl: `https://${host}/api/v1` }).state).toBe('ready');
    }
  });
});

describe('plain HTTP to a public host', () => {
  it('is insecure and blocks a packaged build', () => {
    const config = resolveApiConfig({ ...BUILT, apiUrl: 'http://watchtower.example/api/v1' });
    expect(config.state).toBe('insecure');
    expect(config.blocksSignIn).toBe(true);
    expect(config.reason).toMatch(/clear text/);
  });

  it('warns but still lets a development build run against a LAN test server', () => {
    expect(resolveApiConfig({ ...DEV, apiUrl: 'http://watchtower.example/api/v1' }).blocksSignIn).toBe(false);
  });
});
