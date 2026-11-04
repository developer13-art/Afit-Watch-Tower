/// <reference types="vite/client" />

/** Injected from `package.json` by `vite.config.ts` — see `config/env.ts::APP_VERSION`. */
declare const __APP_VERSION__: string;

interface ImportMetaEnv {
  readonly VITE_API_BASE_URL?: string;
  readonly VITE_API_URL?: string;
  readonly VITE_APP_ENV?: string;
  readonly VITE_ANDROID_APP_ID?: string;
  readonly VITE_USE_FIXTURES?: string;
  readonly VITE_API_TIMEOUT_MS?: string;
  readonly VITE_AUTH_TIMEOUT_MS?: string;
  readonly VITE_FIREBASE_API_KEY?: string;
  readonly VITE_FIREBASE_AUTH_DOMAIN?: string;
  readonly VITE_FIREBASE_PROJECT_ID?: string;
  readonly VITE_FIREBASE_STORAGE_BUCKET?: string;
  readonly VITE_FIREBASE_MESSAGING_SENDER_ID?: string;
  readonly VITE_FIREBASE_APP_ID?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
