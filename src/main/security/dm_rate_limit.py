"""Per-user rate limits for DM send (HTTP 429 only)."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, status

_MINUTE_WINDOW_SECONDS = 60
_MINUTE_LIMIT = 60
_SECOND_WINDOW_SECONDS = 1
_SECOND_LIMIT = 1

_minute_buckets: dict[str, deque[float]] = defaultdict(deque)
_second_buckets: dict[str, deque[float]] = defaultdict(deque)


def _check(
    bucket: dict[str, deque[float]],
    key: str,
    window_seconds: float,
    limit: int,
) -> None:
    now = time.time()
    queue = bucket[key]
    while queue and now - queue[0] > window_seconds:
        queue.popleft()
    if len(queue) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many messages. Please slow down.",
        )
    queue.append(now)


def enforce_dm_send_rate_limit(user_id: int) -> None:
    key = f"dm_send:{user_id}"
    _check(_second_buckets, key, _SECOND_WINDOW_SECONDS, _SECOND_LIMIT)
    _check(_minute_buckets, key, _MINUTE_WINDOW_SECONDS, _MINUTE_LIMIT)
