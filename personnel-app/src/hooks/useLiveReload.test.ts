/**
 * The live channel's re-read trigger (contract §10.8).
 *
 * Two properties make the difference on a phone: arriving at a screen whose revision counter is
 * already at seven must not fire a second load behind the screen's own initial load, and one burst
 * of frames must not stack one re-read per frame.
 */
import { act, renderHook } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { useLiveReload } from './useForegroundPoll';

async function flush(): Promise<void> {
  await act(async () => {
    for (let i = 0; i < 6; i++) await Promise.resolve();
  });
}

describe('useLiveReload', () => {
  it('stays quiet on mount, fires on a new revision, and ignores the same number twice', async () => {
    const reload = vi.fn();
    const view = renderHook(({ revision }: { revision: number }) => useLiveReload(revision, reload), {
      initialProps: { revision: 7 },
    });
    await flush();
    expect(reload).not.toHaveBeenCalled();

    view.rerender({ revision: 8 });
    await flush();
    expect(reload).toHaveBeenCalledTimes(1);

    view.rerender({ revision: 8 });
    await flush();
    expect(reload).toHaveBeenCalledTimes(1);

    view.rerender({ revision: 12 });
    await flush();
    expect(reload).toHaveBeenCalledTimes(2);
    view.unmount();
  });

  it('runs the callback from this render, not the one that first mounted', async () => {
    const stale = vi.fn();
    const current = vi.fn();
    const view = renderHook(({ revision, reload }: { revision: number; reload: () => void }) => useLiveReload(revision, reload), {
      initialProps: { revision: 1, reload: stale },
    });
    await flush();

    view.rerender({ revision: 1, reload: current });
    await flush();
    expect(stale).not.toHaveBeenCalled();
    expect(current).not.toHaveBeenCalled();

    view.rerender({ revision: 2, reload: current });
    await flush();
    expect(stale).not.toHaveBeenCalled();
    expect(current).toHaveBeenCalledTimes(1);
    view.unmount();
  });
});
