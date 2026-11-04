"""Per-identity sliding-window rate limits.

In-memory and per process. A single cloud host is the deployment AFIT is piloting, so this is
honest protection rather than a distributed limiter with a fake claim of one: if the service is
later run behind more than one replica, each replica counts its own traffic and the limit becomes
"approximately N per replica". The deployment guide says so, and the `/health` response reports
the process id so an operator can see how many replicas are actually serving.

Limits are keyed by identity, not by IP alone: a login attempt is counted against both the
username (to stop password guessing across one account) and the source address (to stop one
address trying many accounts).
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

from .errors import CloudError

MAX_TRACKED_KEYS = 50_000


@dataclass(slots=True)
class Bucket:
    limit: int
    window_seconds: float
    hits: deque[float]


class RateLimiter:
    def __init__(self, *, max_tracked_keys: int = MAX_TRACKED_KEYS) -> None:
        self._buckets: dict[tuple[str, str], Bucket] = {}
        self._lock = threading.Lock()
        self._max_keys = max_tracked_keys
        self.rejected_total = 0

    def allow(self, group: str, identity: str, *, limit: int, window_seconds: float) -> float | None:
        """Return None when allowed, or the seconds to wait when the caller is over budget.

        The budget is only consumed by the allowed path: a rejected request must not extend its
        own window, or a client that hammers a locked endpoint would be locked out forever.
        """
        key = (group, identity)
        now = time.monotonic()
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                if len(self._buckets) >= self._max_keys:
                    self._prune(now)
                    if len(self._buckets) >= self._max_keys:
                        # Refusing to track is not a licence to skip the limit: when the table
                        # is full, everything is treated as already at capacity.
                        return window_seconds
                bucket = Bucket(limit=limit, window_seconds=window_seconds, hits=deque())
                self._buckets[key] = bucket
            bucket.limit = limit
            bucket.window_seconds = window_seconds
            cutoff = now - window_seconds
            while bucket.hits and bucket.hits[0] <= cutoff:
                bucket.hits.popleft()
            if len(bucket.hits) >= limit:
                self.rejected_total += 1
                wait = bucket.hits[0] + window_seconds - now
                return max(1.0, round(wait))
            bucket.hits.append(now)
            return None

    def reset(self, group: str, identity: str) -> None:
        with self._lock:
            self._buckets.pop((group, identity), None)

    def _prune(self, now: float) -> None:
        stale = [
            key
            for key, bucket in self._buckets.items()
            if not bucket.hits or bucket.hits[-1] <= now - bucket.window_seconds
        ]
        for key in stale:
            self._buckets.pop(key, None)

    def tracked(self) -> int:
        with self._lock:
            return len(self._buckets)


def enforce(
    limiter: RateLimiter,
    group: str,
    identity: str,
    *,
    limit: int,
    window_seconds: float,
    code: str = "rate_limited",
) -> None:
    wait = limiter.allow(group, identity, limit=limit, window_seconds=window_seconds)
    if wait is not None:
        raise CloudError(
            code,
            "Too many requests for this account. Try again shortly.",
            status_code=429,
            headers={"retry-after": str(int(wait))},
        )
