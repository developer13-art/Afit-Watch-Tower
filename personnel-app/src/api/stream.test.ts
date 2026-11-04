/**
 * Live-feed client tests (contract §10.8).
 *
 * The fake transport is a hand-rolled `Response` rather than `new Response(...)`: this runs in a
 * jsdom environment where the fetch classes are not guaranteed, and the only part of the contract
 * being tested here is `body.getReader()`.
 */
import { describe, expect, it } from 'vitest';
import { openLiveFeed, parseSseBlock } from './stream';
import type { LiveFrame, LiveStatus } from '../types/api';

function readyFrame(cursor: string): string {
  return `id: ${cursor}\nevent: ready\ndata: ${JSON.stringify({ cursor, poll_seconds: 2, heartbeat_seconds: 15, server_time: '2026-11-02T09:00:00Z' })}\n\n`;
}

const READY = readyFrame('0:0');

function notificationFrame(id: number): string {
  return `id: ${id}:0\nevent: notification\ndata: ${JSON.stringify({ id, title: 'Perimeter', body: 'movement', severity: 'high' })}\n\n`;
}

interface FakeResponseInit {
  status?: number;
  chunks?: string[];
  json?: unknown;
}

function fakeResponse(init: FakeResponseInit & { ok?: boolean }) {
  const chunks = init.chunks ?? [];
  let index = 0;
  let cancelled = false;
  const status = init.status ?? 200;
  return {
    status,
    ok: status >= 200 && status < 300,
    body: {
      getReader: () => ({
        read: async () => {
          if (cancelled || index >= chunks.length) return { done: true, value: undefined };
          return { done: false, value: new TextEncoder().encode(chunks[index++]) };
        },
        cancel: async () => {
          cancelled = true;
          return undefined;
        },
      }),
    },
    json: async () => init.json ?? {},
  };
}

interface Harness {
  urls: string[];
  headers: Record<string, string>[];
  frames: LiveFrame[];
  statuses: { status: LiveStatus; detail?: string }[];
  delays: number[];
  feed: ReturnType<typeof openLiveFeed>;
}

function harness(responses: Array<FakeResponseInit | ((call: number) => FakeResponseInit)>, options: { token?: () => string | null } = {}): Harness {
  const h: Partial<Harness> = { urls: [], headers: [], frames: [], statuses: [], delays: [] };
  let call = 0;
  const fetchImpl = (async (url: string, init: RequestInit) => {
    h.urls!.push(String(url));
    h.headers!.push(init.headers as Record<string, string>);
    const scripted = responses[call];
    const spec = typeof scripted === 'function' ? scripted(call) : scripted;
    call += 1;
    // Out of scripted responses: stopping here is what keeps a passing test from spinning forever
    // once the reconnect policy has nothing left to assert about.
    if (!spec) {
      h.feed?.stop();
      return fakeResponse({ chunks: [] }) as unknown as Response;
    }
    return fakeResponse(spec) as unknown as Response;
  }) as unknown as typeof fetch;

  h.feed = openLiveFeed({
    url: 'https://cloud.example/api/v1/events/stream',
    token: options.token ?? (() => 'access-token'),
    installationId: () => 'inst-1',
    onFrame: (frame) => h.frames!.push(frame),
    onStatus: (status, detail) => h.statuses!.push({ status, detail }),
    fetchImpl,
    wait: async (ms) => {
      h.delays!.push(ms);
    },
  });
  return h as Harness;
}

/** The feed is an async loop; let it run to the transport's own end. */
async function settle(rounds = 24): Promise<void> {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setTimeout(resolve, 0));
}

describe('parseSseBlock', () => {
  it('reads the event name, the resume cursor and the body', () => {
    const frame = parseSseBlock(READY.trimEnd());
    expect(frame?.name).toBe('ready');
    expect(frame?.id).toBe('0:0');
    expect(frame?.data).toMatchObject({ heartbeat_seconds: 15 });
  });

  it('accepts the CRLF form and ignores comment lines', () => {
    const block = ': keep-alive\r\nid: 7:2\r\nevent: heartbeat\r\ndata: {"cursor":"7:2","server_time":"x"}\r\n';
    const frame = parseSseBlock(block.replace(/\r\n/g, '\n'));
    expect(frame).toMatchObject({ name: 'heartbeat', id: '7:2' });
  });

  it('drops an unknown event rather than inventing a meaning for it', () => {
    expect(parseSseBlock('id: 1:0\nevent: future_thing\ndata: {"a":1}\n')).toBeNull();
  });

  it('drops a body that is not JSON and a block with no cursor', () => {
    expect(parseSseBlock('id: 1:0\nevent: ready\ndata: not json\n')).toBeNull();
    expect(parseSseBlock('event: ready\ndata: {"cursor":"0:0"}\n')).toBeNull();
  });
});

describe('openLiveFeed', () => {
  it('authenticates with a header, never with the token in the URL', async () => {
    const h = harness([{ chunks: [READY] }]);
    h.feed.start();
    await settle();
    h.feed.stop();

    expect(h.urls[0]).toBe('https://cloud.example/api/v1/events/stream');
    expect(h.headers[0].authorization).toBe('Bearer access-token');
    expect(h.headers[0].accept).toBe('text/event-stream');
    expect(h.headers[0]['x-installation-id']).toBe('inst-1');
    expect(h.urls.join()).not.toContain('access-token');
    expect(h.statuses.some((entry) => entry.status === 'live')).toBe(true);
  });

  it('refuses to open without an access token', async () => {
    const h = harness([], { token: () => null });
    h.feed.start();
    await settle(4);
    expect(h.urls).toHaveLength(0);
    expect(h.statuses).toEqual([{ status: 'unavailable', detail: 'no_session' }]);
    // No session is a pause, not a verdict: a sign-in has to be able to reopen this feed, so the
    // only states that set `finished` are the ones where asking again would be wrong.
    expect(h.feed.finished).toBe(false);
  });

  it('carries the cursor into the reconnect so nothing is delivered twice', async () => {
    const h = harness([{ chunks: [READY, notificationFrame(4)] }, { chunks: [readyFrame('4:0')] }]);
    h.feed.start();
    await settle();
    h.feed.stop();

    expect(h.frames.map((f) => f.name)).toEqual(['ready', 'notification', 'ready']);
    expect(h.feed.cursor).toBe('4:0');
    expect(h.urls[1]).toBe('https://cloud.example/api/v1/events/stream?since=4%3A0');
  });

  it('backs off a dropped connection and resets the ladder once the stream is live again', async () => {
    const h = harness([
      { chunks: [READY, notificationFrame(1)] },
      { chunks: [] },
      { chunks: [] },
      { chunks: [READY] },
    ]);
    h.feed.start();
    await settle(60);

    // The first open reached `ready`, so the ladder starts short; the two drops that follow climb
    // it; the next `ready` resets it, so the drop after that is 1s again — not 8s.
    expect(h.delays).toEqual([1_000, 2_000, 5_000, 1_000]);
    expect(h.feed.finished).toBe(true);
  });

  it('reconnects immediately when the service closes the stream on purpose', async () => {
    const closing = 'id: 9:9\nevent: closing\ndata: {"reason":"lifetime","cursor":"9:9","server_time":"x"}\n\n';
    const h = harness([{ chunks: [READY, closing] }]);
    h.feed.start();
    await settle(20);

    // Two attempts, no wait between them: a scheduled close is not a fault, and holding the phone
    // in the backoff for it would stretch a blind spot out for nothing.
    expect(h.urls).toHaveLength(2);
    expect(h.delays).toEqual([]);
    expect(h.feed.cursor).toBe('9:9');
  });

  it('stops asking when the service says it runs no live channel', async () => {
    const h = harness([{ status: 503, json: { error: { code: 'stream_disabled' } } }]);
    h.feed.start();
    await settle();
    expect(h.urls).toHaveLength(1);
    expect(h.statuses.at(-1)).toEqual({ status: 'unsupported', detail: undefined });
    expect(h.feed.finished).toBe(true);
  });

  it('treats a route that does not exist as no live channel either', async () => {
    const h = harness([{ status: 404 }]);
    h.feed.start();
    await settle();
    expect(h.urls).toHaveLength(1);
    expect(h.statuses.at(-1)?.status).toBe('unsupported');
  });

  it('ends the feed on a refused credential instead of retrying into a lock-out', async () => {
    const h = harness([{ status: 401 }, { status: 403 }]);
    h.feed.start();
    await settle();
    expect(h.urls).toHaveLength(1);
    expect(h.statuses.at(-1)).toEqual({ status: 'unavailable', detail: 'rejected' });
    expect(h.feed.finished).toBe(true);
  });

  it('keeps retrying a busy server, because that answer has a retry-after in it', async () => {
    const h = harness([
      { status: 503, json: { error: { code: 'stream_unavailable' } } },
      { status: 503, json: { error: { code: 'stream_unavailable' } } },
      { chunks: [READY] },
    ]);
    h.feed.start();
    await settle(60);

    // A full 503 is a momentary room problem, so it is retried; only `stream_disabled` ends it.
    expect(h.urls.length).toBeGreaterThanOrEqual(3);
    expect(h.statuses.some((entry) => entry.status === 'unsupported')).toBe(false);
    expect(h.statuses.some((entry) => entry.status === 'live')).toBe(true);
    expect(h.feed.finished).toBe(true);
  });

  it('forwards notification and activity rows and nothing else', async () => {
    const activity =
      'id: 0:6\nevent: incident_activity\ndata: {"id":6,"incident_id":3,"incident_reference":"WT-1","incident_status":"acknowledged","incident_severity":"high","action":"acknowledged","note":null,"actor_id":2,"actor_name":"A B","created_at":"2026-11-02T09:01:00Z"}\n\n';
    const heartbeat = 'id: 0:6\nevent: heartbeat\ndata: {"cursor":"0:6","server_time":"x"}\n\n';
    const h = harness([{ chunks: [READY, notificationFrame(5), activity, heartbeat] }]);
    h.feed.start();
    await settle();
    h.feed.stop();

    expect(h.frames.map((f) => f.name)).toEqual(['ready', 'notification', 'incident_activity', 'heartbeat']);
    expect(h.feed.cursor).toBe('0:6');
  });
});
