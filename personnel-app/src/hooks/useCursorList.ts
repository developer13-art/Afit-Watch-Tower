/**
 * Cursor pagination (§5.1, §6.1) — newest first, incremental.
 *
 * A page carries `items` plus `next_cursor`. `loadMore()` appends, `refresh()`
 * resets to page one. Only one append may be in flight, otherwise a slow page
 * two would land after a fast page three and the list would silently reorder.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError, asApiError } from '../api/errors';
import { useForegroundPoll, useLiveReload } from './useForegroundPoll';

export interface CursorPage<T> {
  items: T[];
  next_cursor?: string | null;
}

export type ListStatus = 'loading' | 'success' | 'empty' | 'error' | 'unauthorized' | 'forbidden';

export interface CursorListState<T> {
  items: T[];
  status: ListStatus;
  error: ApiError | null;
  loading: boolean;
  loadingMore: boolean;
  canLoadMore: boolean;
  refresh: () => Promise<void>;
  loadMore: () => Promise<void>;
  /** Local optimistic update after an action (mark read, acknowledge…). */
  patchItem: (id: number, patch: Partial<T>) => void;
  setItems: (items: T[]) => void;
}

export interface UseCursorListOptions {
  pollMs?: number;
  /**
   * A live-channel revision (contract §10.8). Changing it re-reads page one quietly — the rows on
   * screen stay put, unlike a `filterKey` change, which is a different question and does reset.
   */
  liveRevision?: number;
}

export function useCursorList<T extends { id: number }>(
  fetchPage: (cursor: string | null) => Promise<CursorPage<T>>,
  /** Serialised filter key. Changing it resets the list to page one. */
  filterKey: string,
  options: UseCursorListOptions = {},
): CursorListState<T> {
  const [items, setItemsState] = useState<T[]>([]);
  const [status, setStatus] = useState<ListStatus>('loading');
  const [error, setError] = useState<ApiError | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [canLoadMore, setCanLoadMore] = useState(false);

  const cursorRef = useRef<string | null>(null);
  const inFlight = useRef(false);
  const generation = useRef(0);
  const fetchRef = useRef(fetchPage);
  fetchRef.current = fetchPage;

  /**
   * @param quiet true for a poll: the rows already on screen stay on screen, so the list does not
   * flash a skeleton every cadence. `loading` is the first-page flag and would blank the list.
   */
  const loadFirstPage = useCallback(async (quiet: boolean) => {
    if (quiet && inFlight.current) return;
    const my = ++generation.current;
    inFlight.current = true;
    if (!quiet) setLoading(true);
    setError(null);
    cursorRef.current = null;
    try {
      const page = await fetchRef.current(null);
      if (my !== generation.current) return;
      setItemsState(page.items);
      cursorRef.current = page.next_cursor ?? null;
      setCanLoadMore(Boolean(page.next_cursor));
      setStatus(page.items.length === 0 ? 'empty' : 'success');
    } catch (err) {
      if (my !== generation.current) return;
      const apiError = asApiError(err);
      setError(apiError);
      setStatus(apiError.status === 401 ? 'unauthorized' : apiError.status === 403 ? 'forbidden' : 'error');
    } finally {
      if (my === generation.current) {
        setLoading(false);
        inFlight.current = false;
      }
    }
  }, []);

  const refresh = useCallback(async () => {
    await loadFirstPage(false);
  }, [loadFirstPage]);

  const loadMore = useCallback(async () => {
    if (inFlight.current || !cursorRef.current) return;
    inFlight.current = true;
    const my = generation.current;
    setLoadingMore(true);
    try {
      const page = await fetchRef.current(cursorRef.current);
      if (my !== generation.current) return;
      setItemsState((prev) => {
        // Guard against a server that replays a row across the cursor boundary.
        const seen = new Set(prev.map((i) => i.id));
        return [...prev, ...page.items.filter((i) => !seen.has(i.id))];
      });
      cursorRef.current = page.next_cursor ?? null;
      setCanLoadMore(Boolean(page.next_cursor));
    } catch (err) {
      if (my !== generation.current) return;
      setError(asApiError(err));
    } finally {
      if (my === generation.current) {
        setLoadingMore(false);
        inFlight.current = false;
      }
    }
  }, []);

  const patchItem = useCallback((id: number, patch: Partial<T>) => {
    setItemsState((prev) => prev.map((i) => (i.id === id ? { ...i, ...patch } : i)));
  }, []);

  const setItems = useCallback((next: T[]) => {
    setItemsState(next);
    setStatus(next.length === 0 ? 'empty' : 'success');
  }, []);

  useEffect(() => {
    void refresh();
  }, [filterKey, refresh]);

  // A refused session stops asking; a poll never overtakes a page append already in flight.
  useForegroundPoll(options.pollMs ?? 0, () => void loadFirstPage(true), status === 'unauthorized');
  useLiveReload(options.liveRevision ?? 0, () => void loadFirstPage(true));

  return { items, status, error, loading, loadingMore, canLoadMore, refresh, loadMore, patchItem, setItems };
}
