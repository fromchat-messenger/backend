"""Sample gauges/counters every minute and maintain rollups."""

from __future__ import annotations

import logging
import time
from typing import Callable

from sqlalchemy.orm import Session

from .analytics_store import (
    add_to_sample,
    bucket_start,
    prune,
    query_all_metrics,
    rollup_from_lower,
    take_pending,
    upsert_sample,
)
from .stats_store import get_stats

logger = logging.getLogger("uvicorn.error")

# Subscribers receive (granularity, series_dict) after each tick.
_listeners: list[Callable[[str, dict], None]] = []


def add_analytics_listener(cb: Callable[[str, dict], None]) -> None:
    _listeners.append(cb)


def remove_analytics_listener(cb: Callable[[str, dict], None]) -> None:
    try:
        _listeners.remove(cb)
    except ValueError:
        pass


def _notify(granularity: str) -> None:
    series = query_all_metrics(granularity)  # type: ignore[arg-type]
    for cb in list(_listeners):
        try:
            cb(granularity, series)
        except Exception as e:
            logger.debug("analytics listener error: %s", e)


def collect_minute_sample(db: Session) -> None:
    """Flush pending counters + sample gauges into the current minute bucket."""
    from ..models import User
    from ..routes.messaging import messagingManager

    now = time.time()
    minute = bucket_start(now, "minute")
    pending = take_pending()

    for metric in ("messages", "blocked", "requests"):
        add_to_sample(metric, "minute", minute, int(pending.get(metric) or 0))

    registered = db.query(User).filter(User.deleted.is_(False)).count()
    banned = (
        db.query(User)
        .filter(User.suspended.is_(True), User.deleted.is_(False))
        .count()
    )
    online = len(set(messagingManager.user_by_ws.values()))

    # Keep blocked total also as gauge-friendly absolute via stats_store if no events.
    # Counters already track deltas; gauges:
    upsert_sample("registered", "minute", minute, int(registered))
    upsert_sample("banned", "minute", minute, int(banned))
    upsert_sample("online", "minute", minute, int(online))

    # Also bump blocked from durable counter delta is handled via note_event;
    # ensure stats_store increments call note_event.

    rollup_from_lower("minute", "hour", now=now)
    rollup_from_lower("hour", "day", now=now)
    rollup_from_lower("day", "month", now=now)
    prune()

    for gran in ("minute", "hour", "day", "month"):
        _notify(gran)


def bootstrap_from_db(db: Session) -> None:
    """One-shot backfill of day-level counters from existing tables (best-effort)."""
    from datetime import datetime, timedelta

    from sqlalchemy import func

    from ..models import DMEnvelope, Message, User
    from .analytics_store import query_series

    # Skip if we already have day samples for messages.
    existing = query_series("messages", "day", window=7)
    if any(p["v"] > 0 for p in existing):
        return

    logger.info("Bootstrapping analytics day series from database…")
    now = datetime.now()
    start = now - timedelta(days=365)
    trunc = func.date_trunc("day", Message.timestamp)
    trunc_dm = func.date_trunc("day", DMEnvelope.timestamp)

    public = {
        (b.date() if hasattr(b, "date") else b): int(c)
        for b, c in db.query(trunc, func.count())
        .filter(Message.timestamp >= start)
        .group_by(trunc)
        .all()
    }
    dms = {
        (b.date() if hasattr(b, "date") else b): int(c)
        for b, c in db.query(trunc_dm, func.count())
        .filter(DMEnvelope.timestamp >= start)
        .group_by(trunc_dm)
        .all()
    }

    days = set(public) | set(dms)
    for day in days:
        try:
            if hasattr(day, "year"):
                ts = int(datetime(day.year, day.month, day.day).timestamp())
            else:
                continue
        except Exception:
            continue
        total = int(public.get(day, 0)) + int(dms.get(day, 0))
        upsert_sample("messages", "day", ts, total)

    # Current gauges into today.
    today = bucket_start(time.time(), "day")
    registered = db.query(User).filter(User.deleted.is_(False)).count()
    banned = (
        db.query(User)
        .filter(User.suspended.is_(True), User.deleted.is_(False))
        .count()
    )
    upsert_sample("registered", "day", today, int(registered))
    upsert_sample("banned", "day", today, int(banned))
    durable = get_stats()
    # Store blocked as absolute on day bootstrap once.
    upsert_sample("blocked", "day", today, int(durable.get("messages_blocked") or 0))
    logger.info("Analytics bootstrap complete (%s days with messages)", len(days))
