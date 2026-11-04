/**
 * The React binding for the live channel (contract §10.8).
 *
 * One feed per signed-in session, opened by `SessionProvider` and never by a screen: two
 * connections would mean two copies of the same alert and a badge count that drifts.
 *
 * A rotation revives a feed the service refused. That is the only recovery this hook performs, and
 * it is the reason it subscribes to `onTokensChanged`: the reader deliberately does not refresh
 * tokens, so a 401 ends it, and the fresh pair the API client installed is the signal that it is
 * worth opening again.
 */
import { useEffect, useRef, useState } from 'react';
import type { ApiClient } from '../api/client';
import { openLiveFeed } from '../api/stream';
import { clientEvents } from '../bootstrap';
import { env } from '../config/env';
import type { LiveActivityFrame, LiveStatus, NotificationItem } from '../types/api';

export interface LiveFeedView {
  status: LiveStatus;
  /** Why the channel is not live, in machine terms — shown only where an operator can act on it. */
  detail: string | null;
}

export interface LiveFeedBindings {
  onNotification: (item: NotificationItem) => void;
  onActivity: (frame: LiveActivityFrame) => void;
}

export function useLiveFeed(
  client: ApiClient | null,
  options: { enabled: boolean; installationId: string },
  bindings: LiveFeedBindings,
): LiveFeedView {
  const [status, setStatus] = useState<LiveStatus>('off');
  const [detail, setDetail] = useState<string | null>(null);
  const [tokenEpoch, setTokenEpoch] = useState(0);

  const bindingsRef = useRef(bindings);
  bindingsRef.current = bindings;

  useEffect(() => {
    const previous = clientEvents.onTokensChanged;
    clientEvents.onTokensChanged = (tokens) => {
      setTokenEpoch((n) => n + 1);
      previous?.(tokens);
    };
    return () => {
      clientEvents.onTokensChanged = previous ?? undefined;
    };
  }, []);

  const { enabled, installationId } = options;

  useEffect(() => {
    if (!enabled || !client) {
      setStatus('off');
      setDetail(null);
      return;
    }

    const feed = openLiveFeed({
      url: env.liveFeedUrl,
      token: () => client.accessTokenValue,
      installationId: () => installationId,
      onFrame: (frame) => {
        // `ready` and `closing` are the feed's own business; only rows are for the screens.
        if (frame.name === 'notification') bindingsRef.current.onNotification(frame.data);
        if (frame.name === 'incident_activity') bindingsRef.current.onActivity(frame.data);
      },
      onStatus: (next, why) => {
        setStatus(next);
        setDetail(why ?? null);
      },
    });
    feed.start();

    return () => {
      feed.stop();
      setStatus('off');
      setDetail(null);
    };
  }, [enabled, installationId, client, tokenEpoch]);

  return { status, detail };
}
