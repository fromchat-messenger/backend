"""Persistent custom blocklist (JSON on disk)."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from threading import RLock
from typing import Iterable, List, Set, Tuple

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
BLOCKLIST_PATH = DATA_DIR / "blocklist.json"

_lock = RLock()
logger = logging.getLogger("uvicorn.error")


def _normalize_words(words: Iterable[str]) -> Set[str]:
    normalized: Set[str] = set()
    for raw in words:
        if not raw:
            continue
        cleaned = re.sub(r"\s+", " ", str(raw)).strip().lower()
        if cleaned:
            normalized.add(cleaned)
    return normalized


def _load() -> Set[str]:
    if not BLOCKLIST_PATH.exists():
        return set()
    try:
        data = json.loads(BLOCKLIST_PATH.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return _normalize_words(data)
    except Exception:
        pass
    return set()


def _write(words: Iterable[str]) -> None:
    BLOCKLIST_PATH.parent.mkdir(parents=True, exist_ok=True)
    BLOCKLIST_PATH.write_text(
        json.dumps(sorted(words), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def get_blocklist() -> List[str]:
    with _lock:
        return sorted(_load())


def add_words(words: Iterable[str]) -> Tuple[List[str], List[str]]:
    normalized = _normalize_words(words)
    if not normalized:
        return [], get_blocklist()
    with _lock:
        current = _load()
        added = sorted(normalized - current)
        if not added:
            return [], sorted(current)
        updated = sorted(current | normalized)
        _write(updated)
        return added, updated


def remove_words(words: Iterable[str]) -> Tuple[List[str], List[str]]:
    normalized = _normalize_words(words)
    if not normalized:
        return [], get_blocklist()
    with _lock:
        current = _load()
        removed = sorted(word for word in normalized if word in current)
        if not removed:
            return [], sorted(current)
        updated = sorted(current - normalized)
        _write(updated)
        return removed, updated


def clear_blocklist() -> None:
    with _lock:
        _write([])
