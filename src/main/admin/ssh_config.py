from __future__ import annotations

import os
from typing import Any


def ssh_enabled() -> bool:
    return os.getenv("ADMIN_SSH_ENABLED", "").strip().lower() in {"1", "true", "yes", "on"}


def ssh_host() -> str:
    return os.getenv("ADMIN_SSH_HOST", "").strip() or _default_host()


def ssh_port() -> int:
    raw = os.getenv("ADMIN_SSH_PORT", "22").strip() or "22"
    try:
        return int(raw)
    except ValueError:
        return 22


def _default_host() -> str:
    # Prefer Docker Desktop host alias; Linux compose often uses host-gateway.
    return os.getenv("ADMIN_SSH_DEFAULT_HOST", "host.docker.internal").strip() or "host.docker.internal"


def ssh_status() -> dict[str, Any]:
    enabled = ssh_enabled()
    return {
        "enabled": enabled,
        "host": ssh_host() if enabled else None,
        "port": ssh_port() if enabled else None,
    }
