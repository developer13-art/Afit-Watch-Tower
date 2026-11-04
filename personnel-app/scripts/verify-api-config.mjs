#!/usr/bin/env node
/**
 * Verifies that a production bundle carries a cloud endpoint a phone can actually use.
 *
 * Two things can go wrong here, and neither produces a type error:
 *
 *   1. A development address is compiled in. That is what shipped in 2026: Vite reads `.env.local`
 *      in every mode including `vite build`, so `http://127.0.0.1:8080` - correct for the laptop -
 *      went into the APK. A handset cannot resolve it and the officer sees "cannot reach the
 *      service" on a screen that looks like a working product.
 *   2. A plaintext or absent endpoint reaches a release. Either way the login screen would be
 *      asking a real officer for a real password with no chance of delivering it safely.
 *
 * So this checks the configuration each mode resolves AND the emitted bytes, because the bundle is
 * what the phone runs and the env files are only what somebody intended.
 *
 * The bundle check looks for this machine's *development* values rather than scanning for any URL
 * that looks local. A generic scan was tried first and is wrong: react-router embeds the literal
 * `http://localhost` as an origin placeholder and the SVG namespace is plain HTTP, so it reported
 * library internals as endpoints. What must not be in a release bundle is the address the dev server
 * uses - so that exact string is what is looked for.
 *
 * Usage:
 *   npm run verify:api-config              fails on a dev/plaintext endpoint; reports an
 *                                          unconfigured release build as a warning (that bundle
 *                                          refuses to sign in, which is the correct behaviour
 *                                          for a backend that has not been deployed)
 *   npm run verify:api-config -- --release fails on an unconfigured build too - use this when
 *                                          actually cutting an APK for personnel
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { loadEnv } from 'vite';

const args = process.argv.slice(2);
const DIST = args.find((a) => !a.startsWith('--')) ?? 'dist';
const RELEASE = args.includes('--release');

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) yield* walk(full);
    else if (/\.(js|mjs|css|html)$/.test(entry)) yield full;
  }
}

/** Mirrors pickConfiguredBase in src/config/apiUrl.ts. The two disagreeing is itself a finding. */
function resolveBase(env) {
  const full = (env.VITE_API_URL ?? '').trim();
  if (full) return full.replace(/\/+$/, '');
  const origin = (env.VITE_API_BASE_URL ?? '').trim();
  if (!origin) return '';
  const base = origin.replace(/\/+$/, '');
  return base.toLowerCase().endsWith('/api/v1') ? base : `${base}/api/v1`;
}

/** Same rule as src/config/apiUrl.ts, restated here so the two can disagree visibly. */
function classify(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { kind: 'invalid', host: url };
  }
  const host = parsed.hostname.toLowerCase();
  const loopback =
    host === 'localhost' || host === '[::1]' || host === '0.0.0.0' || host.startsWith('127.') || host.endsWith('.localhost');
  const privateAddress =
    /^10\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(host) ||
    /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host);
  return { kind: loopback ? 'loopback' : privateAddress ? 'private' : 'public', host };
}

const failures = [];
const warnings = [];

/* ---------------------------------------------------- 1. intended configuration */

const prod = loadEnv('production', process.cwd(), 'VITE_');
const configuredBase = resolveBase(prod);

/**
 * What Vite actually substitutes is the raw value of whichever key is set; the `/api/v1` prefix is
 * appended at runtime by apiUrl.ts, so the resolved base never appears verbatim in a file. Looking
 * for the raw value is what proves the configuration reached the bundle.
 */
const configuredRaw = ((prod.VITE_API_URL ?? '').trim() || (prod.VITE_API_BASE_URL ?? '').trim()).trim();

if (!configuredBase) {
  const message =
    'No endpoint in the production configuration: .env.production leaves VITE_API_URL and ' +
    'VITE_API_BASE_URL empty on purpose. Set one of them in .env.production.local (gitignored) or ' +
    'in the build environment to the HTTPS address of the deployed cloud service.';
  if (RELEASE) failures.push(`[config] ${message}`);
  else warnings.push(`[config] unconfigured release build - ${message}`);
} else {
  const { kind, host } = classify(configuredBase);
  if (kind === 'invalid') failures.push(`[config] "${configuredBase}" is not a full URL with a scheme.`);
  else if (kind === 'loopback') failures.push(`[config] the production endpoint is the loopback address ${host}. A phone cannot resolve it.`);
  else if (kind === 'private') failures.push(`[config] the production endpoint is the private network address ${host}. That is the control room LAN, never a mobile API.`);
  else if (!configuredBase.startsWith('https://')) failures.push(`[config] the production endpoint ${configuredBase} is not HTTPS. Contract §0 requires a valid certificate.`);
  else console.log(`[config] production endpoint ${configuredBase} - HTTPS, public host.`);
}

/* ------------------------------------------------------- 2. what was actually emitted */

if (!existsSync(DIST)) {
  console.error(`verify:api-config — no ${DIST} directory. Run \`npm run build\` first.`);
  process.exit(1);
}

const dev = loadEnv('development', process.cwd(), 'VITE_');
const devBase = resolveBase(dev);

/**
 * Every string that names this machine's development server: the resolved base plus the raw values
 * as written, because a URL assembled from pieces would still contain them. An entry equal to the
 * production base is dropped - if both modes point at the same HTTPS host, nothing leaked.
 */
const forbidden = new Set(
  [devBase, dev.VITE_API_URL, dev.VITE_API_BASE_URL]
    .map((v) => (v ?? '').trim())
    .filter((v) => v && v !== configuredBase && v !== configuredRaw),
);

const files = [...walk(DIST)];
const contents = files.map((file) => [file, readFileSync(file, 'utf8')]);

for (const needle of forbidden) {
  const hit = contents.find(([, text]) => text.includes(needle));
  if (hit) {
    failures.push(
      `[bundle] ${hit[0]} carries ${needle}, which is what this machine's development configuration ` +
        'resolves to. A development endpoint must never be compiled into a release bundle.',
    );
  }
}

// Only worth asking once the configuration itself is sound; otherwise "the bad value is not in the
// bundle" would be reported as a second failure beside the one that matters.
if (failures.length === 0 && configuredBase && !contents.some(([, text]) => text.includes(configuredRaw))) {
  failures.push(
    `[bundle] the configured production endpoint ${configuredRaw} does not appear in any emitted file. ` +
      'Either the value was not substituted at build time or something else supplies the base URL, ' +
      'and a bundle that cannot name its server is not a release.',
  );
}

/* ---------------------------------------------------------------------- report */

for (const w of warnings) console.warn(`verify:api-config — WARNING ${w}`);
if (failures.length > 0) {
  console.error('verify:api-config — FAILED.');
  for (const f of failures) console.error('  ' + f);
  console.error('\n  The app refuses to sign in against an unsafe endpoint by design (src/config/apiUrl.ts).');
  console.error('  Fix the configuration; do not relax this check or the guard to make the screen quiet.');
  process.exit(1);
}

console.log(
  `verify:api-config — OK. ${files.length} emitted files scanned for the development endpoint ` +
    `(${devBase || 'no dev endpoint configured'}); nothing leaked. ${RELEASE ? 'Release' : 'Default'} mode.`,
);
