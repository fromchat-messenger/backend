"""Yandex SmartCaptcha verification for registration when Yandex OAuth is not required."""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import HTTPException, status

from .yandex_oauth import yandex_required_for_register

logger = logging.getLogger("uvicorn.error")

SMARTCAPTCHA_VALIDATE_URL = "https://smartcaptcha.cloud.yandex.ru/validate"
SMARTCAPTCHA_SERVER_KEY = (os.getenv("SMARTCAPTCHA_SERVER_KEY") or "").strip()
SMARTCAPTCHA_CLIENT_KEY = (os.getenv("SMARTCAPTCHA_CLIENT_KEY") or "").strip()


def _redact_token(token: str) -> str:
    cleaned = (token or "").strip()
    if not cleaned:
        return "(empty)"
    return f"len={len(cleaned)} prefix={cleaned[:6]}…"


def smartcaptcha_is_configured() -> bool:
    return bool(SMARTCAPTCHA_SERVER_KEY and SMARTCAPTCHA_CLIENT_KEY)


def smartcaptcha_required_for_register() -> bool:
    required = smartcaptcha_is_configured() and not yandex_required_for_register()
    logger.debug(
        "SmartCaptcha required_for_register=%s configured=%s yandex_required=%s",
        required,
        smartcaptcha_is_configured(),
        yandex_required_for_register(),
    )
    return required


def public_smartcaptcha_params() -> dict[str, str]:
    """Params safe to send to clients (never includes server key)."""
    return {"client_key": SMARTCAPTCHA_CLIENT_KEY}


def verify_smartcaptcha_token(token: str, ip: str | None = None) -> None:
    """Validate a one-time SmartCaptcha token. Raises HTTPException on failure."""
    cleaned = (token or "").strip()
    logger.info(
        "SmartCaptcha verify start token=%s ip=%s configured=%s",
        _redact_token(cleaned),
        ip or "(none)",
        smartcaptcha_is_configured(),
    )
    if not cleaned:
        logger.warning("SmartCaptcha verify rejected: empty token ip=%s", ip or "(none)")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Captcha verification is required to create an account.",
        )
    if not smartcaptcha_is_configured():
        logger.error("SmartCaptcha verify failed: not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Captcha verification is temporarily unavailable.",
        )

    data: dict[str, str] = {
        "secret": SMARTCAPTCHA_SERVER_KEY,
        "token": cleaned,
    }
    if ip:
        data["ip"] = ip

    try:
        with httpx.Client(timeout=10.0) as client:
            response = client.post(SMARTCAPTCHA_VALIDATE_URL, data=data)
    except httpx.HTTPError as exc:
        logger.warning(
            "SmartCaptcha validate request failed token=%s ip=%s err=%s",
            _redact_token(cleaned),
            ip or "(none)",
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Captcha verification is temporarily unavailable.",
        ) from exc

    # Non-200 must not be treated as success (Yandex docs).
    if response.status_code != 200:
        logger.warning(
            "SmartCaptcha validate HTTP %s token=%s ip=%s body=%s",
            response.status_code,
            _redact_token(cleaned),
            ip or "(none)",
            response.text[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Captcha verification failed. Please try again.",
        )

    try:
        payload = response.json()
    except ValueError:
        logger.warning(
            "SmartCaptcha validate non-JSON HTTP 200 token=%s body=%s",
            _redact_token(cleaned),
            response.text[:200],
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Captcha verification failed. Please try again.",
        )

    status_value = payload.get("status")
    message = (payload.get("message") or "").strip()
    host = payload.get("host")
    logger.info(
        "SmartCaptcha validate response status=%s host=%s message=%s token=%s ip=%s",
        status_value,
        host,
        message or "(none)",
        _redact_token(cleaned),
        ip or "(none)",
    )
    if status_value != "ok":
        logger.info(
            "SmartCaptcha rejected token=%s message=%s",
            _redact_token(cleaned),
            message or "(no message)",
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Captcha verification failed. Please try again.",
        )
    logger.info(
        "SmartCaptcha verify ok token=%s host=%s ip=%s",
        _redact_token(cleaned),
        host,
        ip or "(none)",
    )
