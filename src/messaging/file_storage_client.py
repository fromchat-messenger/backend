"""HTTP client for file-storage (streaming; no base64 on the wire)."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx

logger = logging.getLogger("uvicorn.error")

_STREAM_CHUNK = 1024 * 1024


def file_storage_base_url() -> str:
    url = (os.getenv("FILE_STORAGE_SERVICE_URL") or "").strip()
    if not url:
        raise RuntimeError("FILE_STORAGE_SERVICE_URL is not set")
    return url.rstrip("/")


async def download_resumable_upload_to_path(
    upload_id: str,
    user_id: int,
    dest: Path,
    timeout: float = 120.0,
) -> None:
    url = f"{file_storage_base_url()}/uploads/resumable/{upload_id}/data"
    dest.parent.mkdir(parents=True, exist_ok=True)
    async with httpx.AsyncClient(timeout=timeout) as client:
        async with client.stream(
            "GET",
            url,
            headers={"X-User-ID": str(user_id)},
        ) as response:
            response.raise_for_status()
            with open(dest, "wb") as handle:
                async for chunk in response.aiter_bytes(_STREAM_CHUNK):
                    handle.write(chunk)


async def upload_encrypted_file_from_path(
    source_path: Path,
    filename: str,
    allowed_user_ids: list[int],
    timeout: float = 120.0,
) -> dict:
    url = f"{file_storage_base_url()}/uploads/files/encrypted/store"
    async with httpx.AsyncClient(timeout=timeout) as client:
        with open(source_path, "rb") as file_handle:
            response = await client.post(
                url,
                data={
                    "filename": filename,
                    "content_type": "application/octet-stream",
                    "allowed_user_ids": json.dumps(allowed_user_ids),
                },
                files={"file": (filename, file_handle, "application/octet-stream")},
            )
        response.raise_for_status()
        return response.json()
