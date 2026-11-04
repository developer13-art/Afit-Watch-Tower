/**
 * Polling a cursor-paginated alert list (`useCursorList` `pollMs`).
 *
 * The three properties that matter on an officer's phone: a poll must not blank the rows already
 * on screen, must not overtake a page append that is in flight, and must fall silent once the
 * session has been refused.
 */
import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useCursorList, type CursorPage } from './useCursorList';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';

interface Item {
  id: number;
}

function setVisibility(state: 'visible' | 'hidden'): void {
  Object.defineProperty(document, 'visibilityState', { value: state, configurable: true });
}

async function drain(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 12; i++) await Promise.resolve();
  });
}

async function tick(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
    for (let i = 0; i < 12; i++) await Promise.resolve();
  });
}

describe('useCursorList foreground polling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    setVisibility('visible');
  });

  afterEach(() => {
    vi.useRealTimers();
    setVisibility('visible');
  });

  it('re-reads page one without clearing the rows on screen', async () => {
    let calls = 0;
    let release: ((page: CursorPage<Item>) => void) | undefined;
    const fetchPage = vi.fn((): Promise<CursorPage<Item>> => {
      calls += 1;
      if (calls === 1) return Promise.resolve({ items: [{ id: 1 }], next_cursor: null });
      return new Promise<CursorPage<Item>>((resolve) => {
        release = () => resolve({ items: [{ id: 1 }, { id: 9 }], next_cursor: null });
      });
    });

    const { result } = renderHook(() => useCursorList<Item>(fetchPage, 'filter', { pollMs: 5_000 }));
    await drain();
    expect(result.current.items).toHaveLength(1);

    // The cadence fires while the poll's own request is still outstanding.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(5_000);
    });
    expect(result.current.loading).toBe(false);
    expect(result.current.items).toHaveLength(1);

    await act(async () => {
      release?.({ items: [{ id: 1 }, { id: 9 }], next_cursor: null });
      for (let i = 0; i < 12; i++) await Promise.resolve();
    });
    expect(result.current.items).toHaveLength(2);
  });

  it('never overtakes a page append that is in flight, and resumes after it', async () => {
    let calls = 0;
    let releaseAppend: ((page: CursorPage<Item>) => void) | undefined;
    const fetchPage = vi.fn((): Promise<CursorPage<Item>> => {
      calls += 1;
      if (calls === 1) return Promise.resolve({ items: [{ id: 1 }], next_cursor: 'c2' });
      if (calls === 2)
        return new Promise<CursorPage<Item>>((resolve) => {
          releaseAppend = () => resolve({ items: [{ id: 2 }], next_cursor: null });
        });
      return Promise.resolve({ items: [{ id: 1 }], next_cursor: 'c2' });
    });

    const { result } = renderHook(() => useCursorList<Item>(fetchPage, 'filter', { pollMs: 5_000 }));
    await drain();

    await act(async () => {
      void result.current.loadMore();
      for (let i = 0; i < 12; i++) await Promise.resolve();
    });
    expect(result.current.loadingMore).toBe(true);

    // Three cadences pass while page two is still being appended.
    await tick(15_000);
    expect(calls).toBe(2);

    await act(async () => {
      releaseAppend?.({ items: [{ id: 2 }], next_cursor: null });
      for (let i = 0; i < 12; i++) await Promise.resolve();
    });
    await tick(5_000);
    expect(calls).toBe(3);
    expect(result.current.items).toEqual([{ id: 1 }]);
  });

  it('falls silent once the session is refused', async () => {
    const fetchPage = vi.fn(async (): Promise<CursorPage<Item>> => {
      throw new ApiError({
        code: ERROR_CODES.AUTHENTICATION_REQUIRED,
        message: 'A bearer access token is required.',
        status: 401,
      });
    });

    const { result } = renderHook(() => useCursorList<Item>(fetchPage, 'filter', { pollMs: 5_000 }));
    await drain();
    expect(result.current.status).toBe('unauthorized');

    await tick(30_000);
    expect(fetchPage).toHaveBeenCalledTimes(1);
  });
});
