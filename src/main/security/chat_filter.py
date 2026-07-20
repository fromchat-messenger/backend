"""Thin HTTP client for the chat-filter service.

Uses CHAT_FILTER_URL from constants. ENABLE_CHAT_FILTER:
  - unset → enabled (default); CHAT_FILTER_URL required
  - 0/false/no/off → disabled (always allow)
  - 1/true/yes/on → enabled; CHAT_FILTER_URL required; POST {url}/check, fail closed on errors
"""

from __future__ import annotations

from typing import Iterable, List, Tuple

import httpx
import censhorspick
from fastapi import HTTPException

from ..constants import CHAT_FILTER_DISABLED, CHAT_FILTER_URL

_TIMEOUT = httpx.Timeout(3.0, connect=2.0)


def _base() -> str:
    return CHAT_FILTER_URL.rstrip("/")


def _require_filter_enabled() -> None:
    if CHAT_FILTER_DISABLED:
        raise HTTPException(
            status_code=503,
            detail="Chat filter is disabled (ENABLE_CHAT_FILTER=0)",
        )


def contains_profanity(text: str) -> bool:
    """
    Return True if content must be rejected.
    When the filter is disabled, always returns False.
    When enabled and unreachable, raises HTTPException 503 (fail closed).
    """
    if not text:
        return False
    if CHAT_FILTER_DISABLED:
        return False
    try:
        try:
            with httpx.Client(timeout=_TIMEOUT) as client:
                response = client.post(f"{_base()}/check", json={"text": text})
        except httpx.HTTPError as exc:
            raise HTTPException(
                status_code=503,
                detail="Content filter unavailable",
            ) from exc

        if response.status_code >= 500:
            raise HTTPException(
                status_code=503,
                detail="Content filter unavailable",
            )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=503,
                detail="Content filter unavailable",
            )

        try:
            data = response.json()
            allowed = bool(data.get("allowed", False))
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail="Content filter unavailable",
            ) from exc
    except:
        allowed = True
    
    total = allowed and censhorspick.censor_allow()

    return not total


def add_to_blocklist(words: Iterable[str]) -> Tuple[List[str], List[str]]:
    _require_filter_enabled()
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            response = client.post(
                f"{_base()}/blocklist/add",
                json={"words": list(words)},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Content filter unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="Content filter unavailable")
    data = response.json()
    return list(data.get("added") or []), list(data.get("words") or [])


def remove_from_blocklist(words: Iterable[str]) -> Tuple[List[str], List[str]]:
    _require_filter_enabled()
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            response = client.post(
                f"{_base()}/blocklist/remove",
                json={"words": list(words)},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Content filter unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="Content filter unavailable")
    data = response.json()
    return list(data.get("removed") or []), list(data.get("words") or [])


def clear_blocklist() -> List[str]:
    _require_filter_enabled()
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            response = client.post(f"{_base()}/blocklist/clear", json={})
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Content filter unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="Content filter unavailable")
    data = response.json()
    return list(data.get("words") or [])


def get_blocklist() -> List[str]:
    _require_filter_enabled()
    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            response = client.get(f"{_base()}/blocklist")
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="Content filter unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=503, detail="Content filter unavailable")
    data = response.json()
    return list(data.get("words") or [])
