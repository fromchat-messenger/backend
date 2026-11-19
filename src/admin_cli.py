from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import os
import re
import shlex
import sys
import time
from getpass import getpass
from typing import Iterable, List, Optional
import readline
import httpx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from admin_server_probe import (
    DEFAULT_PUBLIC_API_BASE,
    ServerProbeError,
    ServerProbeOk,
    probe_server_target,
)


class CLIError(Exception):
    """Generic CLI error with a human-readable message."""


VALID_ENCRYPTION_MODES = frozenset({"compliance", "e2ee"})

# readline: bytes between \001 and \002 are excluded from the visible prompt width.
_RL_NOPRINT_START = "\001"
_RL_NOPRINT_END = "\002"

# Max positional args per command (None = unlimited). Checked in dispatch after aliases resolve.
COMMAND_MAX_ARGS: dict[str, Optional[int]] = {
    "login": 1,
    "suspend": 1,
    "ban": 1,
    "unsuspend": 1,
    "unban": 1,
    "delete": 1,
    "remove": 1,
    "verify": 1,
    "unverify": 1,
    "user": 1,
    "unblock-ip": 1,
    "set-encryption-mode": 1,
    "encryption-mode-set": 1,
    "compliance-mode": 1,
    "encryption-mode": 0,
    "encryption": 0,
    "instance-info": 0,
    "toggle-encryption-mode": 0,
    "toggle-compliance": 0,
    "help": 0,
    "whoami": 0,
    "list": 0,
    "blocklist": 0,
    "clear-blocklist": 0,
    "clear-all-rate-limits": 0,
    "server": 1,
    "sleep": 1,
}


_YES_FLAG_TOKENS = frozenset({"-y", "--yes"})


def _strip_inline_yes_flags(parts: List[str]) -> tuple[List[str], bool]:
    """Remove -y / --yes anywhere after the command name."""
    if not parts:
        return parts, False
    assume = False
    kept = [parts[0]]
    for token in parts[1:]:
        if token in _YES_FLAG_TOKENS:
            assume = True
        else:
            kept.append(token)
    return kept, assume


def _split_command_chain(raw: str) -> List[str]:
    """Split on `&&` (shell-style); does not split inside quotes."""
    stripped = raw.strip()
    if not stripped:
        return []
    return [segment.strip() for segment in re.split(r"\s+&&\s+", stripped) if segment.strip()]


def _colored_input_prompt(identity: str) -> str:
    """Prompt string safe for GNU readline (history / cursor position)."""
    s, e = _RL_NOPRINT_START, _RL_NOPRINT_END
    return (
        f"{s}\033[36m{e}{identity}"
        f"{s}\033[0m{e} "
        f"{s}\033[1m{e}>"
        f"{s}\033[0m{e} "
    )


def _read_interactive_line(prompt: str) -> str:
    """One REPL line; works with GNU readline and macOS libedit (no set_prompt)."""
    try:
        if hasattr(readline, "set_prompt"):
            readline.set_prompt(prompt)
            return readline.readline()
        return readline.readline(prompt)
    except Exception:
        return input(prompt)


def _reject_extra_args(command: str, args: List[str]) -> None:
    limit = COMMAND_MAX_ARGS.get(command)
    if limit is None:
        return
    if len(args) > limit:
        if limit == 0:
            raise CLIError(f"Too many arguments for {command} (expected none).")
        raise CLIError(
            f"Too many arguments for {command} (expected at most {limit}, got {len(args)}).",
        )


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    blocks: list[bytes] = []
    previous = b""
    counter = 1
    while len(b"".join(blocks)) < length:
        previous = hmac.new(prk, previous + info + bytes([counter]), hashlib.sha256).digest()
        blocks.append(previous)
        counter += 1
    return b"".join(blocks)[:length]


def derive_auth_secret(username: str, password: str) -> str:
    salt = f"fromchat.user:{username}".encode("utf-8")
    prk = _hkdf_extract(salt, password.encode("utf-8"))
    okm = _hkdf_expand(prk, b"auth-secret", 32)
    return base64.b64encode(okm).decode("utf-8")


def _read_single_key() -> str:
    try:  # Windows
        import msvcrt  # type: ignore

        ch = msvcrt.getch()
        return ch.decode("utf-8", errors="ignore").lower()
    except ImportError:
        import termios
        import tty

        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch.lower()


class AdminCLI:
    def __init__(self, api_url: str, *, assume_yes: bool = False, probe: Optional[ServerProbeOk] = None) -> None:
        self.console = Console()
        self.api_url = api_url.rstrip("/")
        self.client = httpx.Client(base_url=self.api_url, timeout=30.0)
        self.username: Optional[str] = None
        self.token: Optional[str] = None
        self.assume_yes = assume_yes
        self.last_probe: Optional[ServerProbeOk] = probe

    def close(self) -> None:
        self.client.close()

    def _replace_client(self, api_base: str) -> None:
        next_base = api_base.rstrip("/")
        if self.api_url == next_base:
            return
        self.close()
        self.api_url = next_base
        self.client = httpx.Client(base_url=self.api_url, timeout=30.0)
        self.token = None
        self.username = None

    def _render_server_probe(self, probe: ServerProbeOk, *, unchanged: bool = False) -> None:
        title = "Server" if unchanged else "Server configured"
        table = Table(title=title, show_header=False)
        table.add_row("API", probe.api_base_url)
        table.add_row("Instance ID", probe.instance_id)
        table.add_row("HTTPS", "yes" if probe.https_enabled else "no")
        table.add_row("Calls (LiveKit)", "✅" if probe.calls_ok else "❌")
        table.add_row("Ping", f"{probe.ping_ms} ms")
        table.add_row("Encryption", f"{probe.encryption_mode} (v{probe.encryption_mode_version})")
        self.console.print(table)

    def _apply_server(self, raw: str) -> None:
        try:
            probe = probe_server_target(raw)
        except ServerProbeError as exc:
            raise CLIError(str(exc)) from exc
        same = probe.api_base_url.rstrip("/") == self.api_url.rstrip("/")
        self._replace_client(probe.api_base_url)
        self.last_probe = probe
        self._render_server_probe(probe, unchanged=same)
        if not same:
            self.console.print("[yellow]Session cleared — login again for this server.[/]")

    # --------------------------- HTTP helpers --------------------------- #
    def _auth_headers(self) -> dict:
        headers: dict = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _request(self, method: str, path: str, *, auth: bool = True, **kwargs) -> httpx.Response:
        rel_path = path.lstrip("/")
        headers = kwargs.pop("headers", {})
        if auth:
            headers.update(self._auth_headers())
        response = self.client.request(method, rel_path, headers=headers, **kwargs)
        if response.status_code >= 400:
            detail = ""
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    detail = payload.get("detail") or payload.get("message") or ""
            except Exception:
                detail = response.text
            message = f"{response.status_code} {response.reason_phrase}"
            if detail:
                message = f"{message}: {detail}"
            raise CLIError(message.strip())
        return response

    # --------------------------- CLI primitives ------------------------- #
    def _require_auth(self) -> None:
        if not self.token:
            raise CLIError("You must login before running this command.")

    def _resolve_user(self, identifier: str) -> dict:
        self._require_auth()
        if identifier.isdigit():
            response = self._request("GET", f"user/id/{identifier}")
        else:
            response = self._request("GET", f"user/{identifier.replace('@', '')}")
        return response.json()

    def _confirm(self, prompt: str) -> bool:
        if self.assume_yes:
            self.console.print(f"[dim]{prompt} (auto-confirmed)[/]")
            return True
        self.console.print(f"[bold yellow]{prompt}[/] [green](y)[/] / [red](n)[/]: ", end="")
        choice = _read_single_key()
        self.console.print("")  # move to next line
        return choice == "y"

    def _render_user(self, user: dict) -> None:
        table = Table(show_header=False)
        table.add_row("ID", str(user.get("id")))
        table.add_row("Username", user.get("username", ""))
        table.add_row("Display name", user.get("display_name", ""))
        table.add_row("Verified", "✅" if user.get("verified") else "❌")
        if user.get("suspended"):
            table.add_row("Suspended", f"🚫 ({user.get('suspension_reason') or 'no reason'})")
        else:
            table.add_row("Suspended", "✅ Active")
        self.console.print(table)

    # --------------------------- Commands ------------------------------- #
    def cmd_login(self, args: List[str]) -> None:
        if args:
            username = args[0]
        else:
            username = self.console.input("[bold cyan]Username[/]: ").strip()
        if not username:
            raise CLIError("Username is required.")

        password = getpass("Password: ")
        derived_password = derive_auth_secret(username, password)
        payload = {"username": username, "password": derived_password}
        response = self._request("POST", "auth/steps/password", json=payload, auth=False)
        body = response.json()
        status = body.get("status")
        if status == "needs_register":
            raise CLIError("User does not exist; register via a client first.")
        token = body.get("token")
        if not token:
            hint = f" (status={status})" if status else ""
            raise CLIError(f"Login did not return a token{hint}.")
        self.token = token
        self.username = username
        self.console.print("[bold green]Login successful.[/]")

    def cmd_suspend(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: suspend <user_id|username>")
        identifier = args[0]
        user = self._resolve_user(identifier)
        self.console.print(Panel.fit("[bold red]Suspend user[/]", style="red"))
        self._render_user(user)
        reason = self.console.input("[bold yellow]Reason (press Enter to leave empty)[/]: ").strip()
        if not self._confirm(f"Confirm suspension of {user.get('username')}?"):
            self.console.print("[yellow]Suspension cancelled.[/]")
            return
        payload = {"reason": reason}
        self._request("POST", f"user/{user['id']}/suspend", json=payload)
        log_reason = reason or "no reason provided"
        self.console.print(f"[bold red]User {user['username']} suspended ({log_reason}).[/]")

    def cmd_unsuspend(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: unsuspend <user_id|username>")
        identifier = args[0]
        user = self._resolve_user(identifier)
        self.console.print(Panel.fit("[bold green]Unsuspend user[/]", style="green"))
        self._render_user(user)
        if not self._confirm(f"Unsuspend {user.get('username')}?"):
            self.console.print("[yellow]Unsuspension cancelled.[/]")
            return
        self._request("POST", f"user/{user['id']}/unsuspend")
        self.console.print(f"[bold green]User {user['username']} unsuspended.[/]")

    def cmd_block_word(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: block-word <word or phrase> [additional words...]")
        self._require_auth()
        words = args
        response = self._request("POST", "moderation/blocklist", json={"words": words})
        data = response.json()
        added = data.get("added", [])
        current = data.get("words", [])
        if added:
            self.console.print(f"[bold green]Added {len(added)} entr{'y' if len(added)==1 else 'ies'} to blocklist.[/]")
        else:
            self.console.print("[yellow]No new words added.[/]")
        self.console.print(f"Blocklist size: {len(current)}")

    def cmd_list_users(self) -> None:
        self._require_auth()
        payload = self._request("GET", "user/list").json()
        users = payload.get("users", [])
        table = Table(title="Users", show_lines=False)
        table.add_column("ID")
        table.add_column("Username")
        table.add_column("Display name")
        table.add_column("Suspended")
        for user in users:
            table.add_row(
                str(user.get("id")),
                user.get("username", ""),
                user.get("display_name", ""),
                "🚫" if user.get("suspended") else "✅",
            )
        self.console.print(table)

    def cmd_user(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: user <user_id|username>")
        user = self._resolve_user(args[0])
        self._render_user(user)

    def cmd_delete(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: delete <user_id|username>")
        user = self._resolve_user(args[0])
        self.console.print(Panel.fit("[bold red]Delete user[/]", style="red"))
        self._render_user(user)
        if not self._confirm(f"Permanently delete {user.get('username')}?"):
            self.console.print("[yellow]Deletion cancelled.[/]")
            return
        self._request("POST", f"user/{user['id']}/delete")
        self.console.print(f"[bold red]User {user['username']} deleted.[/]")

    def cmd_unblock_word(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: unblock-word <word or phrase> [additional words...]")
        self._require_auth()
        response = self._request("DELETE", "moderation/blocklist", json={"words": args})
        data = response.json()
        removed = data.get("removed", [])
        current = data.get("words", [])
        if removed:
            self.console.print(f"[bold green]Removed {len(removed)} entr{'y' if len(removed)==1 else 'ies'} from blocklist.[/]")
        else:
            self.console.print("[yellow]No matching words removed.[/]")
        self.console.print(f"Blocklist size: {len(current)}")

    def cmd_verify(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: verify <user_id|username>")
        user = self._resolve_user(args[0])
        if user.get("verified"):
            self.console.print(f"[yellow]{user['username']} is already verified.[/]")
            return
        self._request("POST", f"user/{user['id']}/verify")
        self.console.print(f"[bold green]{user['username']} marked as verified.[/]")

    def cmd_unverify(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: unverify <user_id|username>")
        user = self._resolve_user(args[0])
        if not user.get("verified"):
            self.console.print(f"[yellow]{user['username']} is already unverified.[/]")
            return
        self._request("POST", f"user/{user['id']}/verify")
        self.console.print(f"[bold green]{user['username']} is now unverified.[/]")

    def cmd_list_blocklist(self) -> None:
        self._require_auth()
        try:
            response = self._request("GET", "moderation/blocklist")
        except CLIError as err:
            self.console.print(f"[yellow]{err}[/]")
            return
        words = response.json().get("words", [])
        if not words:
            self.console.print("[cyan]Blocklist is empty.[/]")
            return
        table = Table(title="Blocked Words", show_lines=True)
        table.add_column("Word / Phrase")
        for entry in words:
            table.add_row(entry)
        self.console.print(table)

    def cmd_clear_blocklist(self) -> None:
        self._require_auth()
        if not self._confirm("Clear the entire chat-filter blocklist?"):
            self.console.print("[yellow]Cancelled.[/]")
            return
        self._request("POST", "moderation/blocklist/clear")
        self.console.print("[bold green]Blocklist cleared.[/]")

    def cmd_unblock_ip(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: unblock-ip <ip_address>")
        self._require_auth()
        ip = args[0].strip()
        if not ip:
            raise CLIError("IP address cannot be empty")
        response = self._request("POST", "moderation/unblock-ip", json={"ip": ip})
        data = response.json()
        message = data.get("message", "IP unblocked")
        self.console.print(f"[bold green]{message}[/]")

    def cmd_clear_all_rate_limits(self) -> None:
        """Clear all rate limit entries. Use with caution."""
        self._require_auth()
        if not self._confirm("Clear ALL rate limit entries? This affects all IPs."):
            self.console.print("[yellow]Operation cancelled.[/]")
            return
        response = self._request("POST", "moderation/clear-all-rate-limits")
        data = response.json()
        message = data.get("message", "Rate limits cleared")
        self.console.print(f"[bold green]{message}[/]")

    def cmd_help(self) -> None:
        self.console.print(
            "[dim]Chain with && (stops on error). Skip confirmations: "
            "[cyan]-y[/] anywhere after the command name, e.g. "
            "[cyan]set-encryption-mode -y e2ee[/] or "
            "[cyan]sleep 5 && set-encryption-mode e2ee -y[/][/]",
        )
        cmds = {
            "login [username]": "Authenticate as owner/admin.",
            "suspend <user>": "Suspend account (alias: ban).",
            "unsuspend <user>": "Unsuspend account (alias: unban).",
            "delete <user>": "Permanently delete the user account.",
            "verify <user>": "Mark user as verified.",
            "unverify <user>": "Remove verification flag.",
            "block-word <words>": "Add words/phrases to chat filter.",
            "unblock-word <words>": "Remove words/phrases from filter.",
            "blocklist": "Show current blocklist (if supported).",
            "clear-blocklist": "Clear the entire chat-filter blocklist.",
            "unblock-ip <ip>": "Unblock an IP address from rate limiting.",
            "clear-all-rate-limits": "Clear all rate limit entries (use with caution).",
            "list": "List all users.",
            "user <user>": "Show detailed user information.",
            "whoami": "Display current session context.",
            "server [url]": "Show or switch API server (probed like the app).",
            "encryption-mode": "Show instance encryption mode (public /instance/info).",
            "set-encryption-mode <mode>": "Set mode to compliance or e2ee (admin user id 1).",
            "toggle-encryption-mode": "Switch compliance ↔ e2ee (admin user id 1).",
            "compliance-mode <on|off>": "Enable or disable compliance encryption mode.",
            "sleep <seconds>": "Pause before the next command (use with &&).",
            "help": "Show this help panel.",
            "exit": "Quit the CLI.",
        }
        table = Table(title="Available Commands")
        table.add_column("Command", style="cyan")
        table.add_column("Description", style="white")
        for cmd, desc in cmds.items():
            table.add_row(cmd, desc)
        self.console.print(table)

    def cmd_whoami(self) -> None:
        self.console.print(f"[cyan]Server[/] [bold]{self.api_url}[/]")
        if not self.token:
            self.console.print("[yellow]Not authenticated.[/]")
            return
        self.console.print(f"[green]Logged in as[/] [bold]{self.username}[/]")

    def cmd_server(self, args: List[str]) -> None:
        if not args:
            if self.last_probe is not None:
                self._render_server_probe(self.last_probe, unchanged=True)
            else:
                self.console.print(f"[cyan]Server[/] [bold]{self.api_url}[/]")
            return
        self._apply_server(args[0])

    def _fetch_instance_info(self) -> dict:
        return self._request("GET", "instance/info", auth=False).json()

    def _render_instance_encryption(self, info: dict) -> None:
        mode = info.get("encryption_mode", "?")
        style = "green" if mode == "compliance" else "cyan"
        table = Table(title="Instance encryption", show_header=False)
        table.add_row("Instance ID", str(info.get("instance_id", "")))
        table.add_row("Mode", f"[{style}]{mode}[/]")
        table.add_row("Version", str(info.get("encryption_mode_version", "")))
        table.add_row("Changed at", str(info.get("encryption_mode_changed_at", "")))
        self.console.print(table)

    def cmd_encryption_mode(self, _args: List[str]) -> None:
        self._render_instance_encryption(self._fetch_instance_info())

    def cmd_set_encryption_mode(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: set-encryption-mode <compliance|e2ee>")
        mode = args[0].strip().lower()
        if mode not in VALID_ENCRYPTION_MODES:
            raise CLIError("Mode must be compliance or e2ee.")
        self._require_auth()
        current = self._fetch_instance_info()
        previous = current.get("encryption_mode")
        if previous == mode:
            self.console.print(f"[yellow]Encryption mode is already [bold]{mode}[/].[/]")
            self._render_instance_encryption(current)
            return
        self.console.print(Panel.fit(f"[bold]Set encryption mode → {mode}[/]", style="yellow"))
        self._render_instance_encryption(current)
        if not self._confirm(f"Change encryption mode from {previous} to {mode}?"):
            self.console.print("[yellow]Cancelled.[/]")
            return
        info = self._request(
            "PATCH",
            "admin/encryption-mode",
            params={"broadcast": "true"},
            json={"mode": mode},
        ).json()
        self.console.print("[bold green]Encryption mode updated.[/]")
        self._render_instance_encryption(info)

    def cmd_toggle_encryption_mode(self, _args: List[str]) -> None:
        current = self._fetch_instance_info().get("encryption_mode")
        if current not in VALID_ENCRYPTION_MODES:
            raise CLIError(f"Unknown current encryption mode: {current!r}")
        target = "e2ee" if current == "compliance" else "compliance"
        self.cmd_set_encryption_mode([target])

    def cmd_sleep(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: sleep <seconds>")
        try:
            seconds = float(args[0])
        except ValueError as exc:
            raise CLIError("sleep: seconds must be a number") from exc
        if seconds < 0:
            raise CLIError("sleep: seconds must be non-negative")
        if seconds > 86_400:
            raise CLIError("sleep: seconds too large (max 86400)")
        time.sleep(seconds)

    def cmd_compliance_mode(self, args: List[str]) -> None:
        if not args:
            raise CLIError("Usage: compliance-mode <on|off>")
        switch = args[0].strip().lower()
        if switch in {"on", "1", "true", "enable", "compliance"}:
            self.cmd_set_encryption_mode(["compliance"])
        elif switch in {"off", "0", "false", "disable", "e2ee"}:
            self.cmd_set_encryption_mode(["e2ee"])
        else:
            raise CLIError("Use compliance-mode on or compliance-mode off.")

    def _dispatch_command(self, command: str, args: List[str]) -> Optional[bool]:
        """Run one command. Return False to exit the REPL, None/True to continue."""
        if command in {"exit", "quit"}:
            self.console.print("[red]Goodbye.[/]")
            return False

        _reject_extra_args(command, args)

        if command == "login":
            self.cmd_login(args)
        elif command in {"suspend", "ban"}:
            self.cmd_suspend(args)
        elif command in {"unsuspend", "unban"}:
            self.cmd_unsuspend(args)
        elif command == "block-word":
            self.cmd_block_word(args)
        elif command == "unblock-word":
            self.cmd_unblock_word(args)
        elif command == "blocklist":
            self.cmd_list_blocklist()
        elif command == "clear-blocklist":
            self.cmd_clear_blocklist()
        elif command == "unblock-ip":
            self.cmd_unblock_ip(args)
        elif command == "clear-all-rate-limits":
            self.cmd_clear_all_rate_limits()
        elif command == "verify":
            self.cmd_verify(args)
        elif command == "unverify":
            self.cmd_unverify(args)
        elif command in {"delete", "remove"}:
            self.cmd_delete(args)
        elif command == "list":
            self.cmd_list_users()
        elif command == "user":
            self.cmd_user(args)
        elif command == "help":
            self.cmd_help()
        elif command == "whoami":
            self.cmd_whoami()
        elif command == "server":
            self.cmd_server(args)
        elif command in {"encryption-mode", "encryption", "instance-info"}:
            self.cmd_encryption_mode(args)
        elif command in {"set-encryption-mode", "encryption-mode-set"}:
            self.cmd_set_encryption_mode(args)
        elif command in {"toggle-encryption-mode", "toggle-compliance"}:
            self.cmd_toggle_encryption_mode(args)
        elif command == "compliance-mode":
            self.cmd_compliance_mode(args)
        elif command == "sleep":
            self.cmd_sleep(args)
        else:
            self.console.print("[yellow]Unknown command. Type help for a list of commands.[/]")
        return True

    def _run_one_command(self, raw: str) -> Optional[bool]:
        try:
            parts = shlex.split(raw)
        except ValueError as exc:
            raise CLIError(f"Parse error: {exc}") from exc
        if not parts:
            return True
        parts, local_yes = _strip_inline_yes_flags(parts)
        command = parts[0].lstrip("/").lower()
        args = parts[1:]
        previous_yes = self.assume_yes
        if local_yes:
            self.assume_yes = True
        try:
            return self._dispatch_command(command, args)
        finally:
            self.assume_yes = previous_yes

    def _parse_and_run(self, raw: str) -> Optional[bool]:
        segments = _split_command_chain(raw)
        if not segments:
            return True
        for segment in segments:
            try:
                outcome = self._run_one_command(segment)
            except CLIError as err:
                self.console.print(f"[red]Error:[/] {err}")
                return True
            except httpx.RequestError as err:
                self.console.print(f"[red]Network error:[/] {err}")
                return True
            if outcome is False:
                return False
        return True

    def _readline_prompt(self) -> str:
        return _colored_input_prompt(self.username or "guest")

    # --------------------------- Main loop ------------------------------ #
    def run(self) -> None:
        self.console.print(Panel.fit("[bold magenta]FromChat Admin CLI[/]", style="magenta"))
        if self.last_probe is not None:
            self._render_server_probe(self.last_probe, unchanged=True)
        histfile = os.path.expanduser("~/.fromchat_admin_cli_history")
        if hasattr(readline, "read_history_file"):
            try:
                readline.read_history_file(histfile)
            except FileNotFoundError:
                pass
        if hasattr(readline, "set_history_length"):
            readline.set_history_length(500)

        while True:
            try:
                raw = _read_interactive_line(self._readline_prompt()).strip()
            except (KeyboardInterrupt, EOFError):
                self.console.print("\n[red]Exiting...[/]")
                break

            if not raw:
                continue

            try:
                if self._parse_and_run(raw) is False:
                    break
            except CLIError as err:
                self.console.print(f"[red]Error:[/] {err}")
            except httpx.RequestError as err:
                self.console.print(f"[red]Network error:[/] {err}")

        if hasattr(readline, "write_history_file"):
            try:
                readline.write_history_file(histfile)
            except OSError:
                pass
        self.close()


def _initial_server_url(cli_args: argparse.Namespace) -> str:
    if cli_args.server:
        return cli_args.server
    return os.getenv("FC_ADMIN_API_URL", DEFAULT_PUBLIC_API_BASE)


def _bootstrap_cli(cli_args: argparse.Namespace) -> AdminCLI:
    target = _initial_server_url(cli_args)
    try:
        probe = probe_server_target(target)
    except ServerProbeError as exc:
        raise CLIError(f"Cannot reach server {target!r}: {exc}") from exc
    cli = AdminCLI(probe.api_base_url, assume_yes=cli_args.yes, probe=probe)
    return cli


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="FromChat Emergency Admin CLI")
    parser.add_argument(
        "--server",
        metavar="URL",
        default=None,
        help=f"API server host or URL (default: {DEFAULT_PUBLIC_API_BASE}; override with FC_ADMIN_API_URL).",
    )
    parser.add_argument(
        "--api-url",
        dest="server",
        metavar="URL",
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "-c",
        "--command",
        action="append",
        metavar="CMD",
        help="Run a command non-interactively (repeat for multiple). Implies login prompts when needed.",
    )
    parser.add_argument(
        "-y",
        "--yes",
        action="store_true",
        help="Skip all confirmation prompts for the session (per-command: -y after the command name).",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)
    try:
        cli = _bootstrap_cli(args)
    except CLIError as exc:
        Console().print(f"[red]Error:[/] {exc}")
        raise SystemExit(1) from exc

    if args.command:
        exit_code = 0
        for line in args.command:
            try:
                if cli._parse_and_run(line) is False:
                    break
            except CLIError as err:
                cli.console.print(f"[red]Error:[/] {err}")
                exit_code = 1
            except httpx.RequestError as err:
                cli.console.print(f"[red]Network error:[/] {err}")
                exit_code = 1
        cli.close()
        raise SystemExit(exit_code)
    cli.run()


if __name__ == "__main__":
    main()

