"""VK ID OAuth for registration proof (identity-only; no profile PII stored)."""
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

VK_AUTHORIZE_URL = "https://id.vk.ru/authorize"
VK_TOKEN_URL = "https://id.vk.ru/oauth2/auth"
VK_SCOPE = (os.getenv("VK_OAUTH_SCOPE") or "").strip()
REGISTRATION_PROOF_TTL_SECONDS = 15 * 60
_PROOF_PURPOSE = "vk_registration"

VK_OAUTH_CLIENT_ID = (os.getenv("VK_OAUTH_CLIENT_ID") or "").strip()
VK_OAUTH_SERVICE_TOKEN = (os.getenv("VK_OAUTH_SERVICE_TOKEN") or "").strip()
VK_OAUTH_REDIRECT_URI = (os.getenv("VK_OAUTH_REDIRECT_URI") or "https://api.fromchat.ru/oauth/vk").strip()
VK_OAUTH_ENABLED = env_flag("VK_OAUTH_ENABLED", default=False)

if VK_OAUTH_ENABLED and (not VK_OAUTH_CLIENT_ID or not VK_OAUTH_SERVICE_TOKEN):
    raise SystemExit(
        "VK_OAUTH_ENABLED=1 but VK_OAUTH_CLIENT_ID / VK_OAUTH_SERVICE_TOKEN are missing."
    )


def vk_is_configured() -> bool:
    return VK_OAUTH_ENABLED


def public_vk_oauth_params() -> dict[str, str]:
    """Params safe to send to clients (never includes service_token)."""
    return {
        "client_id": VK_OAUTH_CLIENT_ID,
        "redirect_uri": VK_OAUTH_REDIRECT_URI,
        "authorize_url": VK_AUTHORIZE_URL,
        "scope": VK_SCOPE,
    }


def create_registration_proof(vk_id: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {
            "purpose": _PROOF_PURPOSE,
            "vk_id": vk_id,
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
            detail="Invalid or expired VK verification. Sign in with VK ID again.",
        ) from exc
    if payload.get("purpose") != _PROOF_PURPOSE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid VK verification.",
        )
    vk_id = payload.get("vk_id")
    if not isinstance(vk_id, str) or not vk_id.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid VK verification.",
        )
    return vk_id.strip()


def exchange_code_for_registration_proof(
    code: str,
    code_verifier: str,
    device_id: str,
    state: str,
) -> str:
    if not vk_is_configured():
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="VK sign-in is not configured on this server.",
        )
    code = (code or "").strip()
    code_verifier = (code_verifier or "").strip()
    device_id = (device_id or "").strip()
    state = (state or "").strip()
    if not code or not code_verifier or not device_id or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="code, code_verifier, device_id, and state are required",
        )

    try:
        with httpx.Client(timeout=httpx.Timeout(10.0, connect=5.0)) as client:
            token_resp = client.post(
                VK_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": VK_OAUTH_CLIENT_ID,
                    "service_token": VK_OAUTH_SERVICE_TOKEN,
                    "redirect_uri": VK_OAUTH_REDIRECT_URI,
                    "code_verifier": code_verifier,
                    "device_id": device_id,
                    "state": state,
                },
            )
            if token_resp.status_code != 200:
                logger.warning(
                    "VK token exchange failed: status=%s body=%s",
                    token_resp.status_code,
                    token_resp.text[:300],
                )
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Could not complete VK sign-in. Try again.",
                )
            token_data: dict[str, Any] = token_resp.json()
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        logger.warning("VK HTTP error: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="VK sign-in temporarily unavailable.",
        ) from exc

    # Opaque subject only — use user_id from the token response; never store profile PII.
    subject = token_data.get("user_id")
    if subject is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not verify VK account. Try again.",
        )
    vk_id = str(subject).strip()
    if not vk_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Could not verify VK account. Try again.",
        )
    return create_registration_proof(vk_id)
