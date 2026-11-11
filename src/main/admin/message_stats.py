"""Daily message aggregates for the admin dashboard.

Closed days are persisted under DATA_DIR/admin/stats.json so DM retention
purges cannot erase chart history. Today's bucket is always queried live.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import DMEnvelope, Message
from .stats_store import (
    get_daily_messages,
    get_last_finalized_day,
    replace_daily_messages,
    upsert_daily_messages,
)

logger = logging.getLogger("uvicorn.error")

# Keep about a year of rollups on disk.
_RETENTION_DAYS = 400


def _day_key(value: date | datetime | str) -> str:
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    return str(value)[:10]


def query_daily_counts(
    db: Session,
    start: datetime,
    end: datetime,
) -> dict[str, dict[str, int]]:
    """Count public + DM messages per calendar day in [start, end)."""
    trunc = func.date_trunc("day", Message.timestamp)
    trunc_dm = func.date_trunc("day", DMEnvelope.timestamp)

    public_rows = (
        db.query(trunc.label("bucket"), func.count().label("count"))
        .filter(Message.timestamp >= start, Message.timestamp < end)
        .group_by("bucket")
        .all()
    )
    dm_rows = (
        db.query(trunc_dm.label("bucket"), func.count().label("count"))
        .filter(DMEnvelope.timestamp >= start, DMEnvelope.timestamp < end)
        .group_by("bucket")
        .all()
    )

    buckets: dict[str, dict[str, int]] = {}
    for bucket, count in public_rows:
        key = _day_key(bucket)
        entry = buckets.setdefault(key, {"public": 0, "dm": 0, "total": 0})
        entry["public"] = int(count)
        entry["total"] += int(count)
    for bucket, count in dm_rows:
        key = _day_key(bucket)
        entry = buckets.setdefault(key, {"public": 0, "dm": 0, "total": 0})
        entry["dm"] = int(count)
        entry["total"] += int(count)
    return buckets


def sync_daily_message_stats(db: Session, *, now: datetime | None = None) -> None:
    """
    Persist closed days and refresh today.

    - Backfill any missing days before today from the DB (once).
    - Finalize yesterday (and any earlier gaps) when the calendar rolls.
    - Always overwrite today's bucket with a live query.
    """
    now = now or datetime.now()
    today = now.date()
    today_key = today.isoformat()
    yesterday = today - timedelta(days=1)
    yesterday_key = yesterday.isoformat()

    stored = get_daily_messages()
    last_finalized = get_last_finalized_day()

    # Bootstrap / gap fill for closed days in the retention window.
    window_start = today - timedelta(days=_RETENTION_DAYS)
    fill_from = window_start
    if last_finalized:
        try:
            fill_from = max(window_start, date.fromisoformat(last_finalized) + timedelta(days=1))
        except ValueError:
            fill_from = window_start

    # Include every closed day up through yesterday.
    if fill_from <= yesterday:
        start_dt = datetime.combine(fill_from, datetime.min.time())
        end_dt = datetime.combine(today, datetime.min.time())
        closed = query_daily_counts(db, start_dt, end_dt)
        # Zero-fill so finalized days without traffic still exist.
        cursor = fill_from
        while cursor <= yesterday:
            key = cursor.isoformat()
            if key not in closed:
                closed[key] = {"public": 0, "dm": 0, "total": 0}
            cursor += timedelta(days=1)
        upsert_daily_messages(closed, last_finalized_day=yesterday_key)
        logger.info(
            "Admin daily message stats finalized through %s (%s days)",
            yesterday_key,
            len(closed),
        )
    elif last_finalized != yesterday_key and yesterday_key not in stored:
        # Edge case: store exists but yesterday missing after a clock skew.
        start_dt = datetime.combine(yesterday, datetime.min.time())
        end_dt = datetime.combine(today, datetime.min.time())
        closed = query_daily_counts(db, start_dt, end_dt)
        if yesterday_key not in closed:
            closed[yesterday_key] = {"public": 0, "dm": 0, "total": 0}
        upsert_daily_messages(closed, last_finalized_day=yesterday_key)

    # Live today.
    start_today = datetime.combine(today, datetime.min.time())
    end_tomorrow = datetime.combine(today + timedelta(days=1), datetime.min.time())
    today_buckets = query_daily_counts(db, start_today, end_tomorrow)
    today_bucket = today_buckets.get(today_key, {"public": 0, "dm": 0, "total": 0})
    upsert_daily_messages({today_key: today_bucket})

    # Prune old days.
    stored = get_daily_messages()
    cutoff = (today - timedelta(days=_RETENTION_DAYS)).isoformat()
    pruned = {k: v for k, v in stored.items() if k >= cutoff}
    if len(pruned) != len(stored):
        replace_daily_messages(pruned, last_finalized_day=get_last_finalized_day())


def build_daily_series(
    db: Session,
    range_days: int,
    *,
    now: datetime | None = None,
) -> list[dict[str, Any]]:
    """Return a continuous daily series; today is always live from DB."""
    now = now or datetime.now()
    today = now.date()
    today_key = today.isoformat()
    start_day = today - timedelta(days=max(range_days - 1, 0))

    # Refresh today (and finalize gaps) before serving.
    try:
        sync_daily_message_stats(db, now=now)
    except Exception as e:
        logger.error("Failed to sync daily message stats: %s", e)

    stored = get_daily_messages()

    # Live override for today even if sync failed partway.
    start_today = datetime.combine(today, datetime.min.time())
    end_tomorrow = datetime.combine(today + timedelta(days=1), datetime.min.time())
    try:
        live_today = query_daily_counts(db, start_today, end_tomorrow).get(
            today_key,
            {"public": 0, "dm": 0, "total": 0},
        )
        stored[today_key] = live_today
    except Exception as e:
        logger.error("Failed to query today's message stats: %s", e)

    series: list[dict[str, Any]] = []
    cursor = start_day
    while cursor <= today:
        key = cursor.isoformat()
        bucket = stored.get(key) or {"public": 0, "dm": 0, "total": 0}
        series.append(
            {
                "bucket": key,
                "public": int(bucket.get("public") or 0),
                "dm": int(bucket.get("dm") or 0),
                "total": int(bucket.get("total") or 0),
            }
        )
        cursor += timedelta(days=1)
    return series
