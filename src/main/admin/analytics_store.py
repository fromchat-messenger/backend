"""Compact SQLite analytics for admin live charts.

Retention (space-efficient):
  minute → 2 days
  hour   → 90 days
  day    → 365 days (1 year)
  month  → 24 months

Counter metrics store per-bucket event counts.
Gauge metrics store the last sampled value in the bucket.
"""

from __future__ import annotations

import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Literal

from ..constants import DATA_DIR

Metric = Literal["messages", "blocked", "banned", "online", "registered", "requests"]
Granularity = Literal["minute", "hour", "day", "month"]

METRICS: tuple[Metric, ...] = (
    "messages",
    "blocked",
    "banned",
    "online",
    "registered",
    "requests",
)
GRANULARITIES: tuple[Granularity, ...] = ("minute", "hour", "day", "month")

# Which metrics are event counters (sum when rolling up) vs gauges (last/avg).
COUNTERS: frozenset[str] = frozenset({"messages", "blocked", "requests"})

RETENTION_SECONDS: dict[Granularity, int] = {
    "minute": 2 * 24 * 3600,
    "hour": 90 * 24 * 3600,
    "day": 365 * 24 * 3600,
    "month": 24 * 30 * 24 * 3600,
}

DEFAULT_WINDOW: dict[Granularity, int] = {
    "minute": 60,
    "hour": 48,
    "day": 30,
    "month": 12,
}

_BUCKET_SECONDS: dict[Granularity, int] = {
    "minute": 60,
    "hour": 3600,
    "day": 86400,
    "month": 30 * 86400,  # approximate; real month keys use calendar months
}

_LOCK = threading.RLock()
_DB_PATH = DATA_DIR / "admin" / "analytics.sqlite3"

# In-process counters for the current minute (flushed by the collector).
_pending: dict[str, int] = {"messages": 0, "blocked": 0, "requests": 0}


def _connect() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH), timeout=30, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS samples (
            metric TEXT NOT NULL,
            granularity TEXT NOT NULL,
            bucket INTEGER NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY (metric, granularity, bucket)
        ) WITHOUT ROWID
        """
    )
    return conn


_conn: sqlite3.Connection | None = None


def _db() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = _connect()
    return _conn


def note_event(metric: Literal["messages", "blocked", "requests"], by: int = 1) -> None:
    if by == 0:
        return
    with _LOCK:
        _pending[metric] = int(_pending.get(metric) or 0) + by


def take_pending() -> dict[str, int]:
    with _LOCK:
        out = dict(_pending)
        _pending["messages"] = 0
        _pending["blocked"] = 0
        _pending["requests"] = 0
        return out


def bucket_start(ts: float | int, granularity: Granularity) -> int:
    """Local-timezone aligned bucket starts (avoids UTC day flips at ~03:00 / 23:00 local)."""
    dt = datetime.fromtimestamp(int(ts))
    if granularity == "month":
        return int(dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0).timestamp())
    if granularity == "day":
        return int(dt.replace(hour=0, minute=0, second=0, microsecond=0).timestamp())
    if granularity == "hour":
        return int(dt.replace(minute=0, second=0, microsecond=0).timestamp())
    # minute
    return int(dt.replace(second=0, microsecond=0).timestamp())


def _prev_bucket(bucket: int, granularity: Granularity) -> int:
    dt = datetime.fromtimestamp(bucket)
    if granularity == "month":
        y, m = dt.year, dt.month - 1
        if m <= 0:
            y, m = y - 1, 12
        return int(datetime(y, m, 1).timestamp())
    if granularity == "day":
        return int((dt.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)).timestamp())
    if granularity == "hour":
        return int((dt - timedelta(hours=1)).timestamp())
    return int((dt - timedelta(minutes=1)).timestamp())


def _next_bucket(bucket: int, granularity: Granularity) -> int:
    dt = datetime.fromtimestamp(bucket)
    if granularity == "month":
        y, m = dt.year, dt.month + 1
        if m > 12:
            y, m = y + 1, 1
        return int(datetime(y, m, 1).timestamp())
    if granularity == "day":
        return int((dt + timedelta(days=1)).timestamp())
    if granularity == "hour":
        return int((dt + timedelta(hours=1)).timestamp())
    return int((dt + timedelta(minutes=1)).timestamp())


def upsert_sample(metric: Metric, granularity: Granularity, bucket: int, value: int) -> None:
    with _LOCK:
        db = _db()
        db.execute(
            """
            INSERT INTO samples(metric, granularity, bucket, value)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(metric, granularity, bucket) DO UPDATE SET value = excluded.value
            """,
            (metric, granularity, int(bucket), int(value)),
        )
        db.commit()


def add_to_sample(metric: Metric, granularity: Granularity, bucket: int, delta: int) -> None:
    if delta == 0:
        return
    with _LOCK:
        db = _db()
        db.execute(
            """
            INSERT INTO samples(metric, granularity, bucket, value)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(metric, granularity, bucket) DO UPDATE SET value = value + excluded.value
            """,
            (metric, granularity, int(bucket), int(delta)),
        )
        db.commit()


def query_series(
    metric: Metric,
    granularity: Granularity,
    *,
    window: int | None = None,
    now: float | None = None,
) -> list[dict[str, int]]:
    """Return continuous series of {t, v} for the last `window` buckets."""
    now = now if now is not None else time.time()
    window = window if window is not None else DEFAULT_WINDOW[granularity]
    end = bucket_start(now, granularity)
    buckets: list[int] = []
    cursor = end
    for _ in range(window):
        buckets.append(cursor)
        cursor = _prev_bucket(cursor, granularity)
    buckets.reverse()

    with _LOCK:
        db = _db()
        if not buckets:
            return []
        placeholders = ",".join("?" * len(buckets))
        rows = db.execute(
            f"""
            SELECT bucket, value FROM samples
            WHERE metric = ? AND granularity = ? AND bucket IN ({placeholders})
            """,
            (metric, granularity, *buckets),
        ).fetchall()
    by_bucket = {int(b): int(v) for b, v in rows}

    # Gauges: forward-fill so an empty new local day/hour doesn't drop the line to 0.
    out: list[dict[str, int]] = []
    last = 0
    is_gauge = metric not in COUNTERS
    for b in buckets:
        if b in by_bucket:
            last = by_bucket[b]
            out.append({"t": b, "v": last})
        elif is_gauge:
            out.append({"t": b, "v": last})
        else:
            out.append({"t": b, "v": by_bucket.get(b, 0)})
    return out


def query_all_metrics(
    granularity: Granularity,
    *,
    window: int | None = None,
) -> dict[str, list[dict[str, int]]]:
    return {m: query_series(m, granularity, window=window) for m in METRICS}


def prune() -> None:
    now = int(time.time())
    with _LOCK:
        db = _db()
        for gran, retain in RETENTION_SECONDS.items():
            cutoff = now - retain
            db.execute(
                "DELETE FROM samples WHERE granularity = ? AND bucket < ?",
                (gran, cutoff),
            )
        db.commit()
        db.execute("PRAGMA wal_checkpoint(TRUNCATE)")


def rollup_from_lower(
    source: Granularity,
    target: Granularity,
    *,
    now: float | None = None,
) -> None:
    """Aggregate source buckets into the current target bucket."""
    now = now if now is not None else time.time()
    target_bucket = bucket_start(now, target)
    start = target_bucket
    end = _next_bucket(target_bucket, target)

    with _LOCK:
        db = _db()
        for metric in METRICS:
            rows = db.execute(
                """
                SELECT value FROM samples
                WHERE metric = ? AND granularity = ? AND bucket >= ? AND bucket < ?
                ORDER BY bucket
                """,
                (metric, source, start, end),
            ).fetchall()
            values = [int(r[0]) for r in rows]
            if not values:
                continue
            if metric in COUNTERS:
                value = sum(values)
            else:
                value = values[-1]
            db.execute(
                """
                INSERT INTO samples(metric, granularity, bucket, value)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(metric, granularity, bucket) DO UPDATE SET value = excluded.value
                """,
                (metric, target, target_bucket, value),
            )
        db.commit()


def db_path() -> Path:
    return _DB_PATH


def approx_size_bytes() -> int:
    try:
        return _DB_PATH.stat().st_size if _DB_PATH.exists() else 0
    except OSError:
        return 0
