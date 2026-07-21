from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

from ..constants import DATA_DIR

_LOCK = threading.RLock()
_PATH = DATA_DIR / "admin" / "ip_history.json"
_TTL_SECONDS = 48 * 60 * 60


def _ensure_dir() -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)


def _read() -> dict[str, list[dict[str, Any]]]:
    _ensure_dir()
    if not _PATH.exists():
        return {}
    try:
        data = json.loads(_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            return {}
        out: dict[str, list[dict[str, Any]]] = {}
        for k, v in data.items():
            if isinstance(v, list):
                out[str(k)] = [e for e in v if isinstance(e, dict)]
        return out
    except Exception:
        return {}


def _write(data: dict[str, list[dict[str, Any]]]) -> None:
    _ensure_dir()
    tmp = _PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_PATH)


def _prune(entries: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    cutoff = now - _TTL_SECONDS
    kept: list[dict[str, Any]] = []
    seen_ips: set[str] = set()
    for entry in sorted(entries, key=lambda e: float(e.get("seen_at") or 0), reverse=True):
        ip = str(entry.get("ip") or "").strip()
        seen_at = float(entry.get("seen_at") or 0)
        if not ip or seen_at < cutoff:
            continue
        if ip in seen_ips:
            # Keep latest only per IP in the window
            continue
        seen_ips.add(ip)
        kept.append({"ip": ip, "seen_at": seen_at})
    return kept


def record_ip(user_id: int, ip: str | None) -> None:
    if not ip or user_id <= 0:
        return
    ip = ip.strip()
    if not ip or ip in {"127.0.0.1", "::1", "localhost"}:
        # Still record localhost for local debugging
        pass
    now = time.time()
    key = str(user_id)
    with _LOCK:
        data = _read()
        entries = list(data.get(key) or [])
        entries.append({"ip": ip, "seen_at": now})
        data[key] = _prune(entries, now)
        # Prune other users opportunistically
        for other in list(data.keys()):
            if other == key:
                continue
            pruned = _prune(data[other], now)
            if pruned:
                data[other] = pruned
            else:
                del data[other]
        _write(data)


def get_ips_for_user(user_id: int) -> list[dict[str, Any]]:
    now = time.time()
    key = str(user_id)
    with _LOCK:
        data = _read()
        entries = _prune(list(data.get(key) or []), now)
        data[key] = entries
        _write(data)
        return [
            {"ip": e["ip"], "seen_at": e["seen_at"]}
            for e in entries
        ]
