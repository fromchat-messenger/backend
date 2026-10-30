"""Per-user soft rate limits for scrape-prone endpoints (HTTP 429 only)."""
from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException, status

_WINDOW_SECONDS = 60
_GET_MESSAGES_LIMIT = 60
_DM_HISTORY_LIMIT = 60
_MESSAGES_NEW_LIMIT = 60
_DM_FETCH_LIMIT = 60
_CHECK_AUTH_LIMIT = 120
_USERS_SEARCH_LIMIT = 60

_windows: dict[str, deque[float]] = defaultdict(deque)


def _check(key: str, limit: int) -> None:
    now = time.time()
    bucket = _windows[key]
    while bucket and now - bucket[0] > _WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= limit:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please slow down.",
        )
    bucket.append(now)


def enforce_get_messages_soft_limit(user_id: int) -> None:
    _check(f"get_messages:{user_id}", _GET_MESSAGES_LIMIT)


def enforce_dm_history_soft_limit(user_id: int) -> None:
    _check(f"dm_history:{user_id}", _DM_HISTORY_LIMIT)


def enforce_messages_new_soft_limit(user_id: int) -> None:
    _check(f"messages_new:{user_id}", _MESSAGES_NEW_LIMIT)


def enforce_dm_fetch_soft_limit(user_id: int) -> None:
    _check(f"dm_fetch:{user_id}", _DM_FETCH_LIMIT)


def enforce_check_auth_soft_limit(user_id: int) -> None:
    _check(f"check_auth:{user_id}", _CHECK_AUTH_LIMIT)


def enforce_users_search_soft_limit(user_id: int) -> None:
    _check(f"users_search:{user_id}", _USERS_SEARCH_LIMIT)
