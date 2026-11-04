#!/usr/bin/env node
/**
 * Verifies that a production bundle cannot reach the fixture layer.
 *
 * `vite build` folds `import.meta.env.DEV` to false, which should make the
 * dynamic `import('./devfixtures/transport')` unreachable and drop the module.
 * This script proves it by scanning the emitted JavaScript for strings that
 * exist only inside `src/devfixtures/`. If any appears, the build is unsafe and
 * this command fails.
 *
 * Run after `npm run build`: `npm run verify:fixtures`.
 */
import { readdirSync, readFileSync, statSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const DIST = process.argv[2] ?? 'dist';

const MARKERS = [
  'FIXTURE_DATA__WATCHTOWER_PERSONNEL__NOT_LIVE',
  'Restricted-zone entry at Main Gate',
  'Fixture transport has no route for',
  'fixture-refresh-token',
  'Ahmad Ahiya',
];

if (!existsSync(DIST)) {
  console.error(`verify:fixtures — no ${DIST} directory. Run \`npm run build\` first.`);
  process.exit(1);
}

function* walk(dir) {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) yield* walk(full);
    else if (/\.(js|mjs|css|html)$/.test(entry)) yield full;
  }
}

const hits = [];
let files = 0;
for (const file of walk(DIST)) {
  files += 1;
  const text = readFileSync(file, 'utf8');
  for (const marker of MARKERS) {
    if (text.includes(marker)) hits.push(`${file}: ${marker}`);
  }
}

if (hits.length > 0) {
  console.error('verify:fixtures — FAILED. Fixture data is present in the production bundle:');
  for (const h of hits) console.error('  ' + h);
  process.exit(1);
}

console.log(`verify:fixtures — OK. Scanned ${files} emitted files; no fixture marker found.`);
