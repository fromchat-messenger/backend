"""Yandex OAuth for registration proof (identity-only; no profile PII stored)."""
from __future__ import annotations

import logging
import os
import time
from typing import Any

import httpx
import jwt
from fastapi import HTTPException, status

from ..constants import JWT_ALGORITHM, JWT_SECRET_KEY
from .oauth_flags import env_flag

logger = logging.getLogger("uvicorn.error")

YANDEX_AUTHORIZE_URL = "https://oauth.yandex.com/authorize"
YANDEX_TOKEN_URL = "https://oauth.yandex.com/token"
YANDEX_INFO_URL = "https://login.yandex.ru/info"
# Must match permissions enabled on the Yandex OAuth app (oauth.yandex.com → app → permissions).
# Default login:email; override with YANDEX_OAUTH_SCOPE (space-separated) if needed.
# We still only persist id/psuid from /info — never email or other PII.
YANDEX_SCOPE = (os.getenv("YANDEX_OAUTH_SCOPE") or "login:email").strip()
REGISTRATION_PROOF_TTL_SECONDS = 15 * 60
_PROOF_PURPOSE = "yandex_registration"

YANDEX_OAUTH_CLIENT_ID = (os.getenv("YANDEX_OAUTH_CLIENT_ID") or "").strip()
YANDEX_OAUTH_CLIENT_SECRET = (os.getenv("YANDEX_OAUTH_CLIENT_SECRET") or "").strip()
YANDEX_OAUTH_REDIRECT_URI = (os.getenv("YANDEX_OAUTH_REDIRECT_URI") or "fromchat://oauth/yandex").strip()
YANDEX_OAUTH_ENABLED = env_flag("YANDEX_OAUTH_ENABLED", default=False)

if YANDEX_OAUTH_ENABLED and (not YANDEX_OAUTH_CLIENT_ID or not YANDEX_OAUTH_CLIENT_SECRET):
    raise SystemExit(
        "YANDEX_OAUTH_ENABLED=1 but YANDEX_OAUTH_CLIENT_ID / YANDEX_OAUTH_CLIENT_SECRET are missing."
    )


def yandex_is_configured() -> bool:
    return YANDEX_OAUTH_ENABLED


def public_yandex_oauth_params() -> dict[str, str]:
    """Params safe to send to clients (never includes client_secret)."""
    return {
        "client_id": YANDEX_OAUTH_CLIENT_ID,
        "redirect_uri": YANDEX_OAUTH_REDIRECT_URI,
        "authorize_url": YANDEX_AUTHORIZE_URL,
        "scope": YANDEX_SCOPE,
    }


def create_registration_proof(yandex_id: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "purpose": _PROOF_PURPOSE,
            "yandex_id": yandex_id,
            "iat": now,
            "exp": now + REGISTRATION_PROOF_TTL_SECONDS,
        },
        JWT_SECRET_KEY,
        algorithm=JWT_ALGORITHM,
    )


def verify_registration_proof(proof: str) -> str:
    try:
        payload = jwt.decode(proof, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired Yandex verification. Sign in with Yandex again.",
        ) from exc
    if payload.get("purpose") != _PROOF_PURPOSE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Yandex verification.",
        )
    yandex_id = payload.get("yandex_id")
    if not isinstance(yandex_id, str) or not yandex_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid Yandex verification.",
        )
    return yandex_id.strip()


def exchange_code_for_registration_proof(code: str, code_verifier: str) -> str:
    if not yandex_is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Yandex sign-in is not configured on this server.",
        )
    code = (code or "").strip()
    code_verifier = (code_verifier or "").strip()
    if not code or not code_verifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="code and code_verifier are required",
        )

    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            token_resp = client.post(
                YANDEX_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": YANDEX_OAUTH_CLIENT_ID,
                    "client_secret": YANDEX_OAUTH_CLIENT_SECRET,
                    "redirect_uri": YANDEX_OAUTH_REDIRECT_URI,
                    "code_verifier": code_verifier,
                },
            )
            if token_resp.status_code != 200:
                logger.warning(
                    "Yandex token exchange failed: status=%s body=%s",
                    token_resp.status_code,
                    token_resp.text[:300],
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not complete Yandex sign-in. Try again.",
                )
            token_data: dict[str, Any] = token_resp.json()
            access_token = token_data.get("access_token")
            if not isinstance(access_token, str) or not access_token:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not complete Yandex sign-in. Try again.",
                )

            info_resp = client.get(
                YANDEX_INFO_URL,
                params={"format": "json"},
                headers={"Authorization": f"OAuth {access_token}"},
            )
            if info_resp.status_code != 200:
                logger.warning(
                    "Yandex info failed: status=%s body=%s",
                    info_resp.status_code,
                    info_resp.text[:300],
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not verify Yandex account. Try again.",
                )
            info: dict[str, Any] = info_resp.json()
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning("Yandex HTTP error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Yandex sign-in temporarily unavailable.",
        ) from exc

    # Opaque subject only — never store name/gender/phone even if Yandex returns extras.
    subject = info.get("id") or info.get("psuid")
    if subject is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not verify Yandex account. Try again.",
        )
    yandex_id = str(subject).strip()
    if not yandex_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not verify Yandex account. Try again.",
        )
    return create_registration_proof(yandex_id)
