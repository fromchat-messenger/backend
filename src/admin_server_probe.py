"""Server endpoint parse + probe (aligned with app ServerConfigProbe / InstanceIdResolve)."""

from __future__ import annotations

import ipaddress
import re
import ssl
from dataclasses import dataclass
from typing import Optional, Tuple

import httpx

INSTANCE_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
INSTANCE_FETCH_TIMEOUT_S = 10.0
CALLS_PROBE_TIMEOUT_S = 1.5

DEFAULT_PUBLIC_API_BASE = "https://api.fromchat.ru"


@dataclass(frozen=True)
class ParsedServerEndpoint:
    host: str
    port: int
    https_preferred: bool
    scheme_explicit: bool


@dataclass(frozen=True)
class ServerProbeOk:
    api_base_url: str
    instance_id: str
    ping_ms: int
    calls_ok: bool
    encryption_mode: str
    encryption_mode_version: int
    https_enabled: bool
    host: str
    port: int


class ServerProbeError(Exception):
    pass


def is_loopback_server_host(host: str) -> bool:
    trimmed = host.strip().removeprefix("[").removesuffix("]").lower()
    return trimmed in {"localhost", "127.0.0.1", "::1"}


def is_private_or_local_server_host(host: str) -> bool:
    trimmed = host.strip().removeprefix("[").removesuffix("]")
    if trimmed.lower() == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(trimmed)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local)


def parse_server_endpoint(raw: str) -> Optional[ParsedServerEndpoint]:
    """Parse `https://host:port`, `host:port`, or bare host (port 443)."""
    text = raw.strip()
    if not text:
        return None

    scheme_explicit = False
    https_preferred = True
    lower = text.lower()
    if lower.startswith("https://"):
        scheme_explicit = True
        https_preferred = True
        text = text[len("https://") :]
    elif lower.startswith("http://"):
        scheme_explicit = True
        https_preferred = False
        text = text[len("http://") :]

    text = text.strip().strip("/")
    if not text:
        return None

    host, port = _parse_host_and_port(text)
    if host is None:
        return None

    if not _is_valid_hostname(host):
        return None

    if not scheme_explicit and is_loopback_server_host(host):
        https_preferred = False

    return ParsedServerEndpoint(
        host=host,
        port=port,
        https_preferred=https_preferred,
        scheme_explicit=scheme_explicit,
    )


def parse_server_target(raw: str) -> ParsedServerEndpoint:
    parsed = parse_server_endpoint(raw)
    if parsed is None:
        raise ServerProbeError("Invalid server URL or host. Use e.g. api.fromchat.ru or http://127.0.0.1:8300")
    return parsed


def format_api_base_url(host: str, port: int, *, https: bool) -> str:
    scheme = "https" if https else "http"
    authority = _host_for_authority(host)
    if (https and port == 443) or (not https and port == 80):
        return f"{scheme}://{authority}"
    return f"{scheme}://{authority}:{port}"


def probe_server_target(raw: str) -> ServerProbeOk:
    endpoint = parse_server_target(raw)
    return probe_server_endpoint(
        host=endpoint.host,
        port=endpoint.port,
        https_preferred=endpoint.https_preferred,
        scheme_explicit=endpoint.scheme_explicit,
    )


def probe_server_endpoint(
    *,
    host: str,
    port: int,
    https_preferred: bool,
    scheme_explicit: bool,
) -> ServerProbeOk:
    local_dev = is_private_or_local_server_host(host)
    if scheme_explicit:
        schemes = [https_preferred]
    elif local_dev:
        schemes = [False]
    elif https_preferred:
        schemes = [True, False]
    else:
        schemes = [False]

    last_error: Optional[str] = None
    for index, https in enumerate(schemes):
        api_base = format_api_base_url(host, port, https=https)
        record_tls = scheme_explicit or index == len(schemes) - 1
        try:
            return _probe_once(api_base, host=host, port=port, https=https)
        except ServerProbeError as exc:
            last_error = str(exc)
            if not scheme_explicit and https and index < len(schemes) - 1 and _is_ssl_failure_message(str(exc)):
                continue
            if record_tls:
                raise
    raise ServerProbeError(last_error or "Server unreachable")


def _probe_once(api_base: str, *, host: str, port: int, https: bool) -> ServerProbeOk:
    import time

    start = time.perf_counter()
    try:
        with httpx.Client(base_url=api_base, timeout=INSTANCE_FETCH_TIMEOUT_S, follow_redirects=True) as client:
            instance_resp = client.get("/instance_id")
            instance_resp.raise_for_status()
            instance_id = ""
            try:
                payload = instance_resp.json()
                if isinstance(payload, dict):
                    instance_id = str(payload.get("instance_id", "")).strip()
            except Exception as exc:
                raise ServerProbeError(f"Invalid /instance_id response: {exc}") from exc

            if not INSTANCE_ID_RE.fullmatch(instance_id):
                raise ServerProbeError("Server is not a supported FromChat instance (bad instance_id).")

            encryption_mode = "compliance"
            encryption_mode_version = 1
            try:
                info_resp = client.get("/instance/info")
                if info_resp.is_success:
                    info = info_resp.json()
                    if isinstance(info, dict):
                        encryption_mode = str(info.get("encryption_mode", encryption_mode))
                        encryption_mode_version = int(info.get("encryption_mode_version", 1))
            except Exception:
                pass

            calls_ok = False
            try:
                calls_resp = client.get("/livekit-health", timeout=CALLS_PROBE_TIMEOUT_S)
                calls_ok = calls_resp.is_success
            except Exception:
                calls_ok = False

            ping_ms = max(0, int((time.perf_counter() - start) * 1000))
            return ServerProbeOk(
                api_base_url=api_base.rstrip("/"),
                instance_id=instance_id,
                ping_ms=ping_ms,
                calls_ok=calls_ok,
                encryption_mode=encryption_mode,
                encryption_mode_version=encryption_mode_version,
                https_enabled=https,
                host=host,
                port=port,
            )
    except httpx.TimeoutException as exc:
        raise ServerProbeError("Server timed out") from exc
    except httpx.HTTPStatusError as exc:
        if 400 <= exc.response.status_code < 500:
            raise ServerProbeError("Server is not a supported FromChat instance") from exc
        raise ServerProbeError(f"HTTP {exc.response.status_code}") from exc
    except ssl.SSLError as exc:
        raise ServerProbeError(f"TLS error: {exc}") from exc
    except httpx.ConnectError as exc:
        raise ServerProbeError(f"Unreachable: {exc}") from exc
    except httpx.RequestError as exc:
        raise ServerProbeError(str(exc)) from exc


def _is_ssl_failure_message(message: str) -> bool:
    lowered = message.lower()
    return any(
        token in lowered
        for token in ("ssl", "tls", "certificate", "handshake", "cert")
    )


def _parse_host_and_port(authority: str) -> Tuple[Optional[str], int]:
    if authority.startswith("["):
        end = authority.find("]")
        if end <= 1:
            return None, 443
        host = authority[1:end]
        rest = authority[end + 1 :]
        if not rest:
            return host, 443
        if not rest.startswith(":"):
            return None, 443
        port_s = rest[1:]
        port = int(port_s) if port_s.isdigit() and 1 <= int(port_s) <= 65535 else None
        if port is None:
            return None, 443
        return host, port

    colon = authority.rfind(":")
    if colon > 0:
        port_part = authority[colon + 1 :]
        if port_part.isdigit():
            port = int(port_part)
            if 1 <= port <= 65535:
                host = authority[:colon]
                if host:
                    return host, port

    return authority, 443


def _host_for_authority(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _is_valid_hostname(host: str) -> bool:
    h = host.strip().removeprefix("[").removesuffix("]")
    if not h or len(h) > 253:
        return False
    if h.replace(".", "").replace("-", "").isalnum() or "." in h or "-" in h:
        try:
            ipaddress.ip_address(h)
            return True
        except ValueError:
            pass
        if h.endswith("."):
            return False
        labels = h.split(".")
        if not labels:
            return False
        return all(0 < len(label) <= 63 and label[0] != "-" and label[-1] != "-" for label in labels)
    return False
