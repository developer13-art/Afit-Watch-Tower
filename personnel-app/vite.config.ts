/// <reference types="vitest/config" />
import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

const pkg = JSON.parse(readFileSync(new URL('./package.json', import.meta.url), 'utf8')) as { version: string };

// AFIT WATCH TOWER personnel app — Vite configuration.
//
// base is './' because the Capacitor Android WebView serves the bundle from
// capacitor://localhost and a relative base avoids path assumptions; the web
// build can be hosted under any prefix.
export default defineConfig({
  base: './',
  // The version the About screen shows is the package version, not a string a screen keeps
  // forgetting to update. The Android native versionCode lives in android/variables.gradle.
  define: { __APP_VERSION__: JSON.stringify(pkg.version) },
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    allowedHosts: true,
  },
  build: {
    target: 'es2022',
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx'],
  },
});
