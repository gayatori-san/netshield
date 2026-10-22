"""Small in-process rate limiter for authentication-sensitive endpoints.

Firebase itself throttles password attempts; this limiter is an additional
guard on the Flask endpoint that mints session cookies. It is intentionally
in-memory: NetShield runs as a single Gunicorn worker because the capture
pipeline is in-process. If the deployment ever adds workers, move this to a
shared store or enforce limits at the proxy.
"""

from __future__ import annotations

import math
import os
import threading
import time
from collections import deque
from typing import Callable, Mapping


class SlidingWindowLimiter:
    def __init__(
        self,
        *,
        limit: int = 30,
        window_seconds: int = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limit = max(1, int(limit))
        self.window_seconds = max(1, int(window_seconds))
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> tuple[bool, int]:
        """Record a hit; return (allowed, retry_after_seconds)."""

        now = self._clock()
        cutoff = now - self.window_seconds
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()

            if len(bucket) >= self.limit:
                retry = max(1, math.ceil(bucket[0] + self.window_seconds - now))
                return False, retry

            bucket.append(now)
            if len(self._hits) > 10_000:
                for stale_key in [
                    entry
                    for entry, values in self._hits.items()
                    if not values or values[-1] <= cutoff
                ]:
                    self._hits.pop(stale_key, None)
            return True, 0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def build_limiter(environ: Mapping[str, str] | None = None) -> SlidingWindowLimiter:
    source = os.environ if environ is None else environ
    raw = (source.get("NETSHIELD_AUTH_RATE_LIMIT") or "30").strip()
    try:
        limit = int(raw)
    except ValueError:
        limit = 30
    limit = min(max(limit, 1), 1000)
    return SlidingWindowLimiter(limit=limit, window_seconds=60)
