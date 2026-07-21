from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from ..constants import LOGS_DIR

_ACCESS_LOG = LOGS_DIR / "access.log"
_ENTRY_START = re.compile(r"^(\d{2}:\d{2}:\d{2})\s+(.*)$")
_HTTP_REQ = re.compile(
    r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(\S+)\s+from\s+(\S+)\s+->\s+(\S+)$"
)
_AUTH_USER = re.compile(r"Authenticated user:\s+(.+)$")


@dataclass
class AccessEntry:
    id: str
    time: str
    date: str | None
    action: str
    method: str | None
    path: str | None
    ip: str | None
    status: str | None
    user: str | None
    raw: str


def _iter_log_files() -> list[Path]:
    files: list[Path] = []
    if _ACCESS_LOG.exists():
        files.append(_ACCESS_LOG)
    # Rotated backups: access.log.1 .. access.log.5
    for i in range(1, 6):
        p = Path(f"{_ACCESS_LOG}.{i}")
        if p.exists():
            files.append(p)
    return files


def _parse_entries(text: str) -> list[AccessEntry]:
    current_date: str | None = None
    entries: list[AccessEntry] = []
    current: dict[str, Any] | None = None
    lines_buf: list[str] = []
    idx = 0

    def flush() -> None:
        nonlocal current, lines_buf, idx
        if not current:
            return
        raw = "\n".join(lines_buf)
        method = path = ip = status = user = None
        action = "other"
        first = current.get("first") or ""
        m = _HTTP_REQ.match(first)
        if m:
            action = "http_request"
            method, path, ip, status = m.group(1), m.group(2), m.group(3), m.group(4)
        elif first.startswith("HTTP error"):
            action = "http_error"
        elif first.startswith("WebSocket connected"):
            action = "ws_connect"
        elif first.startswith("WebSocket disconnected"):
            action = "ws_disconnect"
        for line in lines_buf[1:]:
            um = _AUTH_USER.search(line)
            if um:
                user = um.group(1).strip()
        entry_id = f"{current_date or ''}:{current.get('time')}:{idx}"
        idx += 1
        entries.append(
            AccessEntry(
                id=entry_id,
                time=str(current.get("time") or ""),
                date=current_date,
                action=action,
                method=method,
                path=path,
                ip=ip,
                status=status,
                user=user,
                raw=raw,
            )
        )
        current = None
        lines_buf = []

    for line in text.splitlines():
        stripped = line.strip()
        if re.fullmatch(r"-{5,}", stripped):
            continue
        if re.fullmatch(r"\d{2}\.\d{2}\.\d{4}", stripped):
            flush()
            current_date = stripped
            continue
        m = _ENTRY_START.match(line)
        if m:
            flush()
            current = {"time": m.group(1), "first": m.group(2)}
            lines_buf = [line.rstrip()]
            continue
        if current is not None:
            lines_buf.append(line.rstrip())
    flush()
    return entries


def list_requests(*, before: str | None = None, limit: int = 100) -> dict[str, Any]:
    limit = max(1, min(limit, 500))
    all_entries: list[AccessEntry] = []
    for path in reversed(_iter_log_files()):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        all_entries.extend(_parse_entries(text))

    # Newest last in file; return newest-first for UI pagination with before cursor
    all_entries.reverse()
    start = 0
    if before:
        for i, e in enumerate(all_entries):
            if e.id == before:
                start = i + 1
                break
    page = all_entries[start : start + limit]
    next_before = page[-1].id if len(page) == limit else None
    return {
        "items": [
            {
                "id": e.id,
                "time": e.time,
                "date": e.date,
                "action": e.action,
                "method": e.method,
                "path": e.path,
                "ip": e.ip,
                "status": e.status,
                "user": e.user,
                "raw": e.raw,
            }
            for e in page
        ],
        "next_before": next_before,
    }


def access_log_path() -> Path:
    return _ACCESS_LOG


def follow_new_bytes(path: Path, offset: int) -> tuple[str, int]:
    if not path.exists():
        return "", offset
    size = path.stat().st_size
    if offset > size:
        offset = 0
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read()
    return data.decode("utf-8", errors="replace"), offset + len(data)
