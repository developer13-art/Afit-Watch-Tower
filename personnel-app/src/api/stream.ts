/**
 * The live feed — a server-sent-events reader that can carry this app's credentials.
 *
 * `EventSource` is the textbook client and is unusable here: it cannot set an `Authorization`
 * header, and the alternative — putting a bearer token in a query string — writes the token into
 * every proxy and hosting access log between the phone and the service. So this is `fetch` with
 * `ReadableStream`, doing the few lines of SSE parsing that `EventSource` would have done.
 *
 * What it will not do is own the session. It reads the current access token when an attempt
 * starts and never calls `/auth/refresh`: the API client is the single place token rotation
 * happens, and a second refresher would rotate the family twice. A 401 therefore ends the feed and
 * reports `unavailable`; the provider restarts it when a fresh token arrives.
 *
 * Reconnect is bounded and quiet: backoff resets on a successful `ready`, a stream the *service*
 * closed (`lifetime`) reconnects at once, and a channel the service says it does not offer
 * (`stream_disabled`) stops asking for good and leaves the foreground poll to do the work.
 */
import type { LiveFrame, LiveStatus } from '../types/api';

const DEFAULT_BACKOFF_MS = [1_000, 2_000, 5_000, 10_000, 30_000];

/** How long to wait for a byte before treating the connection as dead in a way nobody can see. */
const IDLE_MULTIPLIER = 2.5;
const IDLE_FLOOR_MS = 15_000;

export interface LiveFeedOptions {
  /** Absolute URL without the cursor, e.g. `https://host/api/v1/events/stream`. */
  url: string;
  token: () => string | null;
  installationId?: () => string | null;
  onFrame: (frame: LiveFrame) => void;
  onStatus: (status: LiveStatus, detail?: string) => void;
  fetchImpl?: typeof fetch;
  backoffMs?: readonly number[];
  /** Injected for tests; `setTimeout` is the default. */
  wait?: (ms: number, signal: AbortSignal) => Promise<void>;
}

export interface LiveFeed {
  start(): void;
  stop(): void;
  /** True when the feed is switched off for good — a disabled channel or an explicit stop. */
  readonly finished: boolean;
  readonly cursor: string | null;
}

type AttemptOutcome = 'broken' | 'lifetime' | 'unsupported' | 'rejected';

export function openLiveFeed(options: LiveFeedOptions): LiveFeed {
  const fetchImpl = options.fetchImpl ?? ((...args) => fetch(...args));
  const backoff = options.backoffMs ?? DEFAULT_BACKOFF_MS;
  const wait = options.wait ?? defaultWait;

  let controller: AbortController | null = null;
  let running = false;
  let finished = false;
  let cursor: string | null = null;
  let attempt = 0;
  let everLive = false;

  const feed: LiveFeed = {
    get finished() {
      return finished;
    },
    get cursor() {
      return cursor;
    },
    start() {
      if (running || finished) return;
      running = true;
      controller = new AbortController();
      void run(controller.signal);
    },
    stop() {
      finished = true;
      running = false;
      controller?.abort();
      controller = null;
    },
  };

  async function run(signal: AbortSignal): Promise<void> {
    while (running && !signal.aborted) {
      const token = options.token();
      if (!token) {
        // The token is in memory only, so this is what a rotation looks like from here. The
        // provider calls start() again once the client has installed a fresh pair.
        running = false;
        report('unavailable', 'no_session');
        return;
      }
      report(everLive ? 'reconnecting' : 'connecting');

      let outcome: AttemptOutcome;
      try {
        outcome = await readConnection(token, signal);
      } catch (err) {
        if (!running || signal.aborted) break;
        outcome = 'broken';
        report('reconnecting', describe(err));
      }

      if (!running || signal.aborted) break;
      if (outcome === 'unsupported' || outcome === 'rejected') {
        // One is "this service runs no live channel", the other is "the service will not accept
        // these credentials for one". Neither gets better by asking again, and the foreground
        // poll is still running, so nothing is lost by stopping here.
        finished = true;
        running = false;
        if (outcome === 'unsupported') report('unsupported');
        else report('unavailable', 'rejected');
        return;
      }
      if (outcome === 'lifetime') {
        // A scheduled end is not a fault: reconnect straight away so the gap does not stretch to
        // the length of the backoff for no reason.
        attempt = 0;
        continue;
      }
      const delay = backoff[Math.min(attempt, backoff.length - 1)];
      attempt += 1;
      await wait(delay, signal);
    }
    running = false;
  }

  async function readConnection(token: string, feedSignal: AbortSignal): Promise<AttemptOutcome> {
    // A second, per-connection controller: the idle watchdog has to be able to drop *this*
    // connection and let the run loop open another. Aborting the feed's own signal would end the
    // reconnect policy too, and the officer would be left with a dead channel and no error.
    const connection = new AbortController();
    const stopBecauseFeedStopped = () => connection.abort();
    feedSignal.addEventListener('abort', stopBecauseFeedStopped, { once: true });

    let idleTimer: ReturnType<typeof setTimeout> | undefined;
    let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

    try {
      const headers: Record<string, string> = {
        accept: 'text/event-stream',
        authorization: `Bearer ${token}`,
      };
      if (options.installationId) {
        const installation = options.installationId();
        if (installation) headers['x-installation-id'] = installation;
      }
      const target = cursor ? `${options.url}?since=${encodeURIComponent(cursor)}` : options.url;

      const response = await fetchImpl(target, {
        method: 'GET',
        headers,
        signal: connection.signal,
        credentials: 'omit',
      });

      if (response.status === 401 || response.status === 403) return 'rejected';
      if (response.status === 404 || response.status === 405 || response.status === 501) {
        // A cloud build that predates the live channel answers this way. Retrying a route that
        // does not exist is how one handset turns a shared API into a load test.
        return 'unsupported';
      }
      if (response.status === 503) {
        const code = await errorCode(response);
        if (code === 'stream_disabled') return 'unsupported';
        return 'broken';
      }
      if (!response.ok || !response.body) return 'broken';

      const stream = response.body.getReader();
      reader = stream;
      const decoder = new TextDecoder();
      let buffer = '';
      // Until `ready` arrives the server's own cadence is unknown, so start from the floor and
      // tighten to heartbeat × 2.5 as soon as it is stated.
      let idleMs = IDLE_FLOOR_MS;

      const armIdle = () => {
        if (idleTimer !== undefined) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => connection.abort(), idleMs);
      };

      armIdle();
      for (;;) {
        const { done, value } = await stream.read();
        if (done) return 'broken';
        armIdle();
        buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n');
        let boundary = buffer.indexOf('\n\n');
        while (boundary >= 0) {
          const block = buffer.slice(0, boundary);
          buffer = buffer.slice(boundary + 2);
          boundary = buffer.indexOf('\n\n');
          const frame = parseSseBlock(block);
          if (!frame) continue;
          cursor = frame.id;
          if (frame.name === 'ready') {
            attempt = 0;
            everLive = true;
            idleMs = Math.max(IDLE_FLOOR_MS, frame.data.heartbeat_seconds * 1000 * IDLE_MULTIPLIER);
            armIdle();
            report('live');
          }
          if (frame.name === 'closing') {
            return frame.data.reason === 'lifetime' ? 'lifetime' : 'broken';
          }
          options.onFrame(frame);
        }
      }
    } catch (err) {
      // The feed itself was stopped: let the run loop see the abort so it breaks out. Anything
      // else — idle watchdog, a reset connection, a flaky radio — is this attempt's problem only.
      if (feedSignal.aborted || !running) throw err;
      return 'broken';
    } finally {
      if (idleTimer !== undefined) clearTimeout(idleTimer);
      feedSignal.removeEventListener('abort', stopBecauseFeedStopped);
      if (reader) void reader.cancel().catch(() => undefined);
    }
  }

  function report(status: LiveStatus, detail?: string): void {
    options.onStatus(status, detail);
  }

  return feed;
}

/**
 * One `id:`/`event:`/`data:` block into a typed frame, or null when it is a comment or something
 * this build does not know. Unknown names are dropped rather than guessed at: a frame the client
 * invents a meaning for is how a future server revision becomes a wrong badge count today.
 *
 * The cursor comes from the `id:` line, which every frame this service publishes carries — it is
 * the position *after* that row, so a reconnect resumes with nothing delivered twice and nothing
 * skipped.
 */
export function parseSseBlock(block: string): LiveFrame | null {
  let name: string | null = null;
  let id: string | null = null;
  let raw: string | null = null;
  for (const line of block.split('\n')) {
    if (line.startsWith(':')) continue;
    if (line.startsWith('event:')) name = line.slice(6).trim();
    else if (line.startsWith('id:')) id = line.slice(3).trim();
    else if (line.startsWith('data:')) raw = (raw ?? '') + line.slice(5).trim();
  }
  if (!name || !id || raw === null) return null;
  let data: unknown;
  try {
    data = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof data !== 'object' || data === null) return null;
  switch (name) {
    case 'ready':
    case 'notification':
    case 'incident_activity':
    case 'heartbeat':
    case 'closing':
      return { name, id, data } as LiveFrame;
    default:
      return null;
  }
}

async function errorCode(response: Response): Promise<string | null> {
  // The refusal is worth naming only for `stream_disabled`, which is the one answer that means
  // "stop asking". Anything else is retried, and a body we did not read must not be left hanging.
  try {
    const body = (await response.json()) as { error?: { code?: string } };
    return body?.error?.code ?? null;
  } catch {
    return null;
  }
}

function describe(err: unknown): string {
  if (err instanceof DOMException && err.name === 'AbortError') return 'idle_timeout';
  return err instanceof Error ? err.name : 'disconnected';
}

function defaultWait(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      signal.removeEventListener('abort', done);
      resolve();
    }
    signal.addEventListener('abort', done, { once: true });
  });
}
