"""
Instance-wide DM encryption mode policy (e2ee | compliance).

Persisted under DATA_DIR as instance_encryption.json; ENCRYPTION_MODE seeds on first boot.
Reads reload from disk on each call (no process-lifetime cache).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from .constants import DATA_DIR

logger = logging.getLogger(__name__)

EncryptionMode = Literal["e2ee", "compliance"]
VALID_ENCRYPTION_MODES: frozenset[str] = frozenset({"e2ee", "compliance"})

_INSTANCE_ENCRYPTION_FILE = DATA_DIR / "instance_encryption.json"
ENV_ENCRYPTION_MODE = "ENCRYPTION_MODE"
INSTANCE_API_PROTOCOL = "1"


@dataclass(frozen=True)
class InstanceEncryptionPolicy:
    mode: EncryptionMode
    changed_at: str
    version: int


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _default_mode_from_env() -> EncryptionMode:
    raw = (os.getenv(ENV_ENCRYPTION_MODE) or "compliance").strip().lower()
    if raw not in VALID_ENCRYPTION_MODES:
        raise ValueError(
            f"{ENV_ENCRYPTION_MODE} must be 'e2ee' or 'compliance', got {raw!r}"
        )
    return raw  # type: ignore[return-value]


def _parse_policy_payload(data: dict) -> InstanceEncryptionPolicy:
    mode = str(data.get("mode", "")).strip().lower()
    if mode not in VALID_ENCRYPTION_MODES:
        raise ValueError(f"Invalid encryption mode in policy file: {mode!r}")
    changed_at = str(data.get("changed_at") or _utc_now_iso())
    version = int(data.get("version", 1))
    if version < 1:
        raise ValueError("encryption policy version must be >= 1")
    return InstanceEncryptionPolicy(mode=mode, changed_at=changed_at, version=version)


def _write_policy_file(policy: InstanceEncryptionPolicy) -> None:
    _INSTANCE_ENCRYPTION_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "mode": policy.mode,
        "changed_at": policy.changed_at,
        "version": policy.version,
    }
    _INSTANCE_ENCRYPTION_FILE.write_text(
        json.dumps(payload, indent=2) + "\n",
        encoding="utf-8",
    )


def ensure_instance_encryption_file() -> InstanceEncryptionPolicy:
    """Create policy file from env when missing; return current policy."""
    if _INSTANCE_ENCRYPTION_FILE.is_file():
        try:
            return read_instance_encryption_policy()
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            logger.warning(
                "Could not read %s (%s); re-seeding from env",
                _INSTANCE_ENCRYPTION_FILE,
                exc,
            )
    mode = _default_mode_from_env()
    policy = InstanceEncryptionPolicy(
        mode=mode,
        changed_at=_utc_now_iso(),
        version=1,
    )
    try:
        _write_policy_file(policy)
    except OSError as exc:
        logger.warning("Could not persist instance encryption policy: %s", exc)
    return policy


def read_instance_encryption_policy() -> InstanceEncryptionPolicy:
    """Reload policy from disk (or seed file if absent)."""
    if not _INSTANCE_ENCRYPTION_FILE.is_file():
        return ensure_instance_encryption_file()
    text = _INSTANCE_ENCRYPTION_FILE.read_text(encoding="utf-8")
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("instance_encryption.json must be a JSON object")
    return _parse_policy_payload(data)


def build_instance_info_payload(instance_id: str) -> dict:
    policy = read_instance_encryption_policy()
    return {
        "instance_id": instance_id,
        "protocol": INSTANCE_API_PROTOCOL,
        "encryption_mode": policy.mode,
        "encryption_mode_changed_at": policy.changed_at,
        "encryption_mode_version": policy.version,
    }


def set_instance_encryption_mode(
    mode: EncryptionMode,
    *,
    bump_version: bool = True,
) -> InstanceEncryptionPolicy:
    current = read_instance_encryption_policy()
    if current.mode == mode:
        new_version = current.version
    else:
        new_version = current.version + 1 if bump_version else current.version
    policy = InstanceEncryptionPolicy(
        mode=mode,
        changed_at=_utc_now_iso(),
        version=new_version,
    )
    _write_policy_file(policy)
    return policy


def reset_instance_encryption_for_tests(path: Path | None = None) -> None:
    """Remove policy file (tests only)."""
    target = path or _INSTANCE_ENCRYPTION_FILE
    try:
        target.unlink(missing_ok=True)
    except OSError:
        pass
