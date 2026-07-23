"""Shared OAuth env flag helpers for identity verification providers."""
from __future__ import annotations

import os


def env_flag(name: str, default: bool = False) -> bool:
    raw = (os.getenv(name) or "").strip().lower()
    if not raw:
        return default
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    raise SystemExit(f"Invalid {name}={os.getenv(name)!r}. Use 1/true or 0/false.")


OAUTH_REQUIRED = env_flag("OAUTH_REQUIRED", default=False)


def oauth_required() -> bool:
    """True when registration must verify via an enabled identity provider."""
    return OAUTH_REQUIRED


def assert_oauth_startup() -> None:
    """Fail fast when OAUTH_REQUIRED is set but no provider is enabled."""
    from .vk_oauth import vk_is_configured
    from .yandex_oauth import yandex_is_configured

    if OAUTH_REQUIRED and not yandex_is_configured() and not vk_is_configured():
        raise SystemExit(
            "OAUTH_REQUIRED=1 but neither YANDEX_OAUTH_ENABLED nor VK_OAUTH_ENABLED is set."
        )
