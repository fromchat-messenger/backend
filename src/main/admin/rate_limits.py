from __future__ import annotations

import re
from typing import Any

from ..security.rate_limit import limiter, _get_storage_dict

_IP_RE = re.compile(
    r"(?:(?:\d{1,3}\.){3}\d{1,3})|(?:\[[0-9a-fA-F:]+\]|[0-9a-fA-F:]{3,})"
)


def list_rate_limited() -> list[dict[str, Any]]:
    """Best-effort list of currently rate-limited keys / IPs from slowapi memory store."""
    try:
        storage = limiter._storage
        storage_dict = _get_storage_dict(storage)
        if storage_dict is None:
            return []
        items: list[dict[str, Any]] = []
        for key, value in list(storage_dict.items()):
            key_s = str(key)
            ip_match = _IP_RE.search(key_s)
            ip = ip_match.group(0).strip("[]") if ip_match else None
            count = None
            reset_time = None
            if isinstance(value, (tuple, list)) and len(value) >= 2:
                count = value[0]
                reset_time = value[1]
            elif isinstance(value, dict):
                count = value.get("count") or value.get("hits")
                reset_time = value.get("expiry") or value.get("reset") or value.get("reset_time")
            items.append(
                {
                    "key": key_s,
                    "ip": ip,
                    "count": count,
                    "reset_time": reset_time,
                }
            )
        return items
    except Exception:
        return []
