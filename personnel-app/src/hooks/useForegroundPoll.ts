/**
 * Foreground polling — the shared half of `useAsync` and `useCursorList`.
 *
 * Without a Firebase project this is the only alert delivery the build has: the app re-reads its
 * own queue while a screen is open. It is not a substitute for push, because a closed app runs
 * nothing - see `docs/firebase-setup.md`.
 *
 * Two rules the callers cannot enforce themselves: a hidden webview asks nothing of the API, so a
 * phone in a pocket is not quietly burning its battery, and `stop` lets a screen that has been
 * refused (401) fall silent instead of hammering the endpoint that just said no.
 */
import { useEffect, useRef } from 'react';

export function useForegroundPoll(pollMs: number, run: () => void, stop = false): void {
  const runRef = useRef(run);
  runRef.current = run;

  useEffect(() => {
    if (pollMs <= 0 || stop) return;
    const visible = () => typeof document === 'undefined' || document.visibilityState !== 'hidden';
    const poll = () => {
      if (visible()) runRef.current();
    };
    const id = window.setInterval(poll, pollMs);
    // Coming back to the app shows what arrived while it was away instead of waiting out the cadence.
    document.addEventListener('visibilitychange', poll);
    return () => {
      window.clearInterval(id);
      document.removeEventListener('visibilitychange', poll);
    };
  }, [pollMs, stop]);
}

/**
 * Re-read when the live channel says something changed (contract §10.8).
 *
 * A trigger, not data: the revision is only ever compared with the value seen last render, so a
 * screen that reads nothing from it cannot render it wrong. Mounting with the counter already
 * above zero does not fire, because the initial load already read the rows that bumped it.
 */
export function useLiveReload(revision: number, reload: () => void): void {
  const seen = useRef(revision);
  const reloadRef = useRef(reload);
  reloadRef.current = reload;

  useEffect(() => {
    if (seen.current === revision) return;
    seen.current = revision;
    reloadRef.current();
  }, [revision]);
}
