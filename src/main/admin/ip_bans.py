"""IP bans via UFW on the Docker host (over SSH).

Ban:
  ufw deny from <ip> to any port 443 proto tcp comment "FromChat | Attacker block"

List (as UFW docs suggest):
  ufw status numbered

Unban:
  ufw delete deny from <ip> to any port 443 proto tcp
"""
from __future__ import annotations

import asyncio
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from .ssh_config import ssh_host, ssh_port

logger = logging.getLogger("uvicorn.error")

UFW_COMMENT = "FromChat | Attacker block"

# [ 1] 443/tcp                   DENY IN     1.2.3.4                   # FromChat | Attacker block
_NUMBERED_LINE = re.compile(
    r"^\[\s*(\d+)\]\s+(\S+)\s+(ALLOW|DENY|REJECT|LIMIT)\s+(IN|OUT)\s+(\S+)(?:\s+#\s*(.*))?$",
    re.IGNORECASE,
)
_IP_RE = re.compile(r"^[0-9a-fA-F.:]+$")


def _ufw_user() -> str:
    return (
        os.getenv("ADMIN_UFW_SSH_USER", "").strip()
        or os.getenv("ADMIN_SSH_USER", "").strip()
        or "root"
    )


def _ufw_password() -> str | None:
    raw = (
        os.getenv("ADMIN_UFW_SSH_PASSWORD", "").strip()
        or os.getenv("ADMIN_SSH_PASSWORD", "").strip()
    )
    return raw or None


def _ufw_key_path() -> str | None:
    raw = (
        os.getenv("ADMIN_UFW_SSH_KEY_PATH", "").strip()
        or os.getenv("ADMIN_SSH_KEY_PATH", "").strip()
    )
    return raw or None


def _ufw_bin() -> str:
    use_sudo = os.getenv("ADMIN_UFW_USE_SUDO", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return "sudo -n ufw" if use_sudo else "ufw"


async def _run_ufw_async(remote_args: str) -> str:
    try:
        import asyncssh
    except ImportError as exc:
        raise RuntimeError("asyncssh is required for UFW IP bans") from exc

    password = _ufw_password()
    key_path = _ufw_key_path()
    if not key_path and not password:
        raise RuntimeError(
            "UFW SSH credentials missing: set ADMIN_UFW_SSH_KEY_PATH or "
            "ADMIN_UFW_SSH_PASSWORD (host via ADMIN_SSH_HOST)"
        )

    connect_kwargs: dict[str, Any] = {
        "host": ssh_host(),
        "port": ssh_port(),
        "username": _ufw_user(),
        "known_hosts": None,
    }
    if key_path:
        connect_kwargs["client_keys"] = [key_path]
    if password:
        connect_kwargs["password"] = password

    full = f"{_ufw_bin()} {remote_args}"
    async with asyncssh.connect(**connect_kwargs) as conn:
        result = await conn.run(full, check=False)

    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()
    if result.exit_status not in (0, None):
        raise RuntimeError(f"ufw failed: {stderr or stdout or result.exit_status}")
    return stdout


def run_ufw(remote_args: str) -> str:
    """Run `ufw <remote_args>` on the host over SSH (sync wrapper for FastAPI routes)."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(_run_ufw_async(remote_args))
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(_run_ufw_async(remote_args))).result(
            timeout=60
        )


def _parse_numbered_status(text: str) -> list[dict[str, Any]]:
    """Parse `ufw status numbered` into rule dicts (UFW-style fields)."""
    items: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line.startswith("["):
            continue
        m = _NUMBERED_LINE.match(line)
        if not m:
            continue
        number, to, action, direction, frm, comment = m.groups()
        comment = (comment or "").strip()
        items.append(
            {
                "number": int(number),
                "to": to,
                "action": action.upper(),
                "direction": direction.upper(),
                "from": frm,
                "ip": frm,
                "comment": comment,
                "reason": comment,
                "raw": line,
            }
        )
    return items


def list_bans() -> list[dict[str, Any]]:
    """Banned IPs from `ufw status numbered` (FromChat attacker blocks / DENY 443)."""
    out = run_ufw("status numbered")
    items = _parse_numbered_status(out)
    return [
        i
        for i in items
        if i.get("comment") == UFW_COMMENT
        or (
            i.get("action") == "DENY"
            and i.get("direction") == "IN"
            and "443" in str(i.get("to") or "")
        )
    ]


def ban_ip(ip: str, reason: str | None = None, actor_id: int | None = None) -> dict[str, Any]:
    _ = reason, actor_id
    ip = ip.strip()
    if not ip or not _IP_RE.fullmatch(ip):
        raise ValueError("Invalid IP address")
    run_ufw(
        f'deny from {ip} to any port 443 proto tcp comment "{UFW_COMMENT}"'
    )
    return {
        "ip": ip,
        "from": ip,
        "to": "443/tcp",
        "action": "DENY",
        "direction": "IN",
        "comment": UFW_COMMENT,
        "reason": UFW_COMMENT,
    }


def unban_ip(ip: str) -> bool:
    ip = ip.strip()
    if not ip or not _IP_RE.fullmatch(ip):
        raise ValueError("Invalid IP address")
    try:
        run_ufw(f"--force delete deny from {ip} to any port 443 proto tcp")
        return True
    except RuntimeError as first_err:
        logger.info("UFW delete by spec failed (%s); trying numbered delete", first_err)
        rules = list_bans()
        for rule in reversed(rules):
            if str(rule.get("from") or rule.get("ip")) == ip:
                run_ufw(f"--force delete {int(rule['number'])}")
                return True
        return False
