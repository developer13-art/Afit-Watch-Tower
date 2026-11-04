/**
 * `useAsync` — the loading / empty / error / unauthorized contract in one hook.
 *
 * Every screen in this app renders one of exactly five states, and the state
 * names match the component that renders them. The hook exists so no screen
 * invents its own `isLoading`/`hasError` boolean pair and so a 401 is always
 * distinguishable from "the network is down" — those two need different words
 * to a duty officer.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, asApiError } from '../api/errors';
import { useForegroundPoll, useLiveReload } from './useForegroundPoll';

export type AsyncStatus = 'idle' | 'loading' | 'success' | 'empty' | 'error' | 'unauthorized' | 'forbidden';

export interface AsyncState<T> {
  status: AsyncStatus;
  data: T | null;
  error: ApiError | null;
  /** True while the first load runs; refreshes set `refreshing` instead. */
  loading: boolean;
  refreshing: boolean;
  reload: () => Promise<void>;
  setData: (updater: (current: T | null) => T | null) => void;
}

export interface UseAsyncOptions<T> {
  /** Decide "empty" from "success with zero rows" — only list screens need it. */
  isEmpty?: (data: T) => boolean;
  enabled?: boolean;
  /**
   * Foreground refresh cadence in milliseconds; 0 or omitted means never poll.
   *
   * Screens pass `env.alertPollMs` rather than a number so the cadence has one setting. What
   * polling does and does not deliver is documented in `useForegroundPoll`.
   */
  pollMs?: number;
  /**
   * A live-channel revision (contract §10.8). Changing it re-reads quietly, without the skeleton a
   * normal reload shows. It is a trigger, not data: the numbers mean nothing to a screen.
   */
  liveRevision?: number;
}

export function useAsync<T>(loader: () => Promise<T>, deps: unknown[], options: UseAsyncOptions<T> = {}): AsyncState<T> {
  const [status, setStatus] = useState<AsyncStatus>('loading');
  const [data, setDataState] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const generation = useRef(0);
  const mounted = useRef(true);
  /** Any request in flight, initial or polled — a refresh never stacks behind a slow one. */
  const inFlight = useRef(false);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const isEmpty = options.isEmpty;
  const enabled = options.enabled !== false;

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const run = useCallback(
    async (isRefresh: boolean) => {
      if (!enabled) return;
      if (isRefresh && inFlight.current) return;
      const my = ++generation.current;
      inFlight.current = true;
      if (isRefresh) setRefreshing(true);
      else setLoading(true);
      setError(null);
      try {
        const result = await loaderRef.current();
        if (my !== generation.current || !mounted.current) return;
        setDataState(result);
        const empty = isEmpty ? isEmpty(result) : false;
        setStatus(empty ? 'empty' : 'success');
      } catch (err) {
        if (my !== generation.current || !mounted.current) return;
        const apiError = asApiError(err);
        setError(apiError);
        if (apiError.status === 401) setStatus('unauthorized');
        else if (apiError.status === 403) setStatus('forbidden');
        else setStatus('error');
      } finally {
        inFlight.current = false;
        if (my === generation.current && mounted.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [enabled, isEmpty],
  );

  useEffect(() => {
    void run(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, enabled]);

  const pollMs = options.pollMs ?? 0;
  useForegroundPoll(pollMs, () => void run(true), !enabled || status === 'unauthorized');
  useLiveReload(options.liveRevision ?? 0, () => void run(true));

  const reload = useCallback(async () => {
    await run(data !== null);
  }, [run, data]);

  const setData = useCallback((updater: (current: T | null) => T | null) => {
    setDataState((current) => updater(current));
  }, []);

  return { status, data, error, loading, refreshing, reload, setData };
}
