from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

from ..constants import DATA_DIR

_LOCK = threading.RLock()
_STATS_PATH = DATA_DIR / "admin" / "stats.json"

_DEFAULT: dict[str, Any] = {
    "messages_blocked": 0,
    "daily_messages": {},
    "last_finalized_day": None,
}


def _ensure_dir() -> None:
    _STATS_PATH.parent.mkdir(parents=True, exist_ok=True)


def _read() -> dict[str, Any]:
    _ensure_dir()
    if not _STATS_PATH.exists():
        return dict(_DEFAULT)
    try:
        data = json.loads(_STATS_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return dict(_DEFAULT)
        out = dict(_DEFAULT)
        out.update(data)
        daily = out.get("daily_messages")
        if not isinstance(daily, dict):
            out["daily_messages"] = {}
        else:
            cleaned: dict[str, dict[str, int]] = {}
            for day, bucket in daily.items():
                if not isinstance(bucket, dict):
                    continue
                public = int(bucket.get("public") or 0)
                dm = int(bucket.get("dm") or 0)
                cleaned[str(day)[:10]] = {
                    "public": public,
                    "dm": dm,
                    "total": int(bucket.get("total") or (public + dm)),
                }
            out["daily_messages"] = cleaned
        return out
    except Exception:
        return dict(_DEFAULT)


def _write(data: dict[str, Any]) -> None:
    _ensure_dir()
    tmp = _STATS_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_STATS_PATH)


def get_stats() -> dict[str, Any]:
    with _LOCK:
        return _read()


def increment_messages_blocked(by: int = 1) -> int:
    with _LOCK:
        data = _read()
        data["messages_blocked"] = int(data.get("messages_blocked") or 0) + by
        _write(data)
        try:
            from .analytics_store import note_event

            note_event("blocked", by)
        except Exception:
            pass
        return int(data["messages_blocked"])


def get_daily_messages() -> dict[str, dict[str, int]]:
    with _LOCK:
        data = _read()
        daily = data.get("daily_messages") or {}
        return dict(daily) if isinstance(daily, dict) else {}


def upsert_daily_messages(
    buckets: dict[str, dict[str, int]],
    *,
    last_finalized_day: str | None = None,
) -> None:
    """Merge day buckets into the durable store. Does not clear missing days."""
    with _LOCK:
        data = _read()
        daily = dict(data.get("daily_messages") or {})
        for day, bucket in buckets.items():
            key = str(day)[:10]
            public = int(bucket.get("public") or 0)
            dm = int(bucket.get("dm") or 0)
            daily[key] = {
                "public": public,
                "dm": dm,
                "total": int(bucket.get("total") or (public + dm)),
            }
        data["daily_messages"] = daily
        if last_finalized_day is not None:
            data["last_finalized_day"] = last_finalized_day[:10]
        _write(data)


def get_last_finalized_day() -> str | None:
    with _LOCK:
        data = _read()
        value = data.get("last_finalized_day")
        return str(value)[:10] if value else None


def replace_daily_messages(
    buckets: dict[str, dict[str, int]],
    *,
    last_finalized_day: str | None = None,
) -> None:
    """Replace the entire daily_messages map (used for retention pruning)."""
    with _LOCK:
        data = _read()
        cleaned: dict[str, dict[str, int]] = {}
        for day, bucket in buckets.items():
            key = str(day)[:10]
            public = int(bucket.get("public") or 0)
            dm = int(bucket.get("dm") or 0)
            cleaned[key] = {
                "public": public,
                "dm": dm,
                "total": int(bucket.get("total") or (public + dm)),
            }
        data["daily_messages"] = cleaned
        if last_finalized_day is not None:
            data["last_finalized_day"] = last_finalized_day[:10]
        _write(data)
