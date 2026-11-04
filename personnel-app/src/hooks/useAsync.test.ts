/**
 * Foreground alert polling (`useAsync` `pollMs`).
 *
 * These four cases are the whole reason the option exists: an officer with no Firebase project
 * behind the build still has to see an alert that landed while the app was open — and a phone in
 * a pocket must not keep asking the API, and a slow network must not pile up requests.
 */
import { act, renderHook } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useAsync } from './useAsync';
import { ApiError } from '../api/errors';
import { ERROR_CODES } from '../types/api';

function setVisibility(state: 'visible' | 'hidden'): void {
  Object.defineProperty(document, 'visibilityState', { value: state, configurable: true });
}

describe('useAsync foreground polling', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    setVisibility('visible');
  });

  afterEach(() => {
    vi.useRealTimers();
    setVisibility('visible');
  });

  // `waitFor` is unusable here: it polls with timers this suite has taken over, and it only knows
  // how to auto-advance Jest's. Everything a loader needs to settle is a microtask, so drain those.
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

  it('re-reads on the cadence, and not at all when the cadence is zero', async () => {
    const loader = vi.fn(async () => 'value');
    const first = renderHook(() => useAsync(loader, [], { pollMs: 20_000 }));
    await drain();
    expect(first.result.current.status).toBe('success');
    expect(loader).toHaveBeenCalledTimes(1);

    await tick(20_000);
    await tick(20_000);
    expect(loader).toHaveBeenCalledTimes(3);
    first.unmount();

    const silent = vi.fn(async () => 'value');
    const second = renderHook(() => useAsync(silent, [], { pollMs: 0 }));
    await drain();
    await tick(120_000);
    expect(second.result.current.status).toBe('success');
    expect(second.result.current.refreshing).toBe(false);
    expect(silent).toHaveBeenCalledTimes(1);
    second.unmount();
  });

  it('waits for a slow refresh instead of stacking requests', async () => {
    let release: (() => void) | undefined;
    const loader = vi.fn(
      () =>
        new Promise<string>((resolve) => {
          release = () => resolve('value');
        }),
    );
    const { result } = renderHook(() => useAsync(loader, [], { pollMs: 5_000 }));
    await drain();
    expect(loader).toHaveBeenCalledTimes(1);

    // Three cadences pass while the first request is still outstanding.
    await tick(15_000);
    expect(loader).toHaveBeenCalledTimes(1);

    await act(async () => {
      release?.();
      for (let i = 0; i < 12; i++) await Promise.resolve();
    });
    await tick(5_000);
    expect(loader).toHaveBeenCalledTimes(2);
    expect(result.current.status).toBe('success');
  });

  it('stays quiet in the background and catches up the moment it is seen again', async () => {
    const loader = vi.fn(async () => 'value');
    const { result } = renderHook(() => useAsync(loader, [], { pollMs: 10_000 }));
    await drain();
    expect(result.current.status).toBe('success');
    const baseline = loader.mock.calls.length;

    setVisibility('hidden');
    await tick(40_000);
    expect(loader).toHaveBeenCalledTimes(baseline);

    setVisibility('visible');
    await act(async () => {
      document.dispatchEvent(new Event('visibilitychange'));
      for (let i = 0; i < 12; i++) await Promise.resolve();
    });
    expect(loader).toHaveBeenCalledTimes(baseline + 1);
  });

  it('stops asking once the session is refused, rather than hammering a 401', async () => {
    const loader = vi.fn(async () => {
      throw new ApiError({
        code: ERROR_CODES.AUTHENTICATION_REQUIRED,
        message: 'A bearer access token is required.',
        status: 401,
      });
    });
    const { result } = renderHook(() => useAsync(loader, [], { pollMs: 5_000 }));
    await drain();
    expect(result.current.status).toBe('unauthorized');
    const baseline = loader.mock.calls.length;

    await tick(30_000);
    expect(loader).toHaveBeenCalledTimes(baseline);
  });
});
