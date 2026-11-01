"""
Helper functions for inter-service communication used by the main service.

HTTP calls to messaging and file_storage (URLs from constants).
"""
from typing import Dict, Any
import base64
import logging
import json
import os
from pathlib import Path

import httpx
from fastapi import HTTPException, status

from .constants import FILE_STORAGE_SERVICE_URL, MESSAGING_SERVICE_URL

logger = logging.getLogger("uvicorn.error")


def _messaging_base_url() -> str:
    return MESSAGING_SERVICE_URL


def _file_storage_base_url() -> str:
    return FILE_STORAGE_SERVICE_URL


async def get_messaging_transport_public_key(timeout: float = 5.0) -> Dict[str, Any]:
    """
    Return messaging service ephemeral transport public key.
    """
    messaging_url = _messaging_base_url()
    url = f"{messaging_url.rstrip('/')}/key/transport/public"
    try:
        try:
            r = httpx.get(url, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception:
            from urllib import request
            with request.urlopen(url, timeout=timeout) as r:
                return json.loads(r.read())
    except Exception as e:
        logger.error("Failed to fetch messaging transport public key: %s", e)
        raise


async def get_compliance_public_key(timeout: float = 5.0) -> Dict[str, Any]:
    """
    Return compliance system public key (for MEK wrapping).
    """
    try:
        from src.shared.message_retention import get_message_retention
    except ImportError:
        from src.shared.message_retention import get_message_retention  # type: ignore
    if get_message_retention().never_store_compliance_mek():
        return {"public_key_b64": ""}

    # Compliance key should be configured via environment variable
    # The compliance public key is not exposed via HTTP for security reasons
    compliance_key = os.getenv("COMPLIANCE_PUBLIC_KEY", "").strip()
    if compliance_key:
        return {"public_key_b64": compliance_key}

    logger.error("COMPLIANCE_PUBLIC_KEY environment variable not set")
    raise RuntimeError("Compliance public key not available - set COMPLIANCE_PUBLIC_KEY environment variable")


async def invalidate_messaging_key(timeout: float = 5.0) -> Dict[str, Any]:
    """
    Request messaging service to invalidate its current ephemeral transport key (rotate).
    """
    messaging_url = _messaging_base_url()
    url = f"{messaging_url.rstrip('/')}/key/transport/invalidate"
    try:
        try:
            r = httpx.post(url, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception:
            from urllib import request
            req = request.Request(url, method="POST")
            with request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
    except Exception as e:
        logger.error("Failed to invalidate messaging key: %s", e)
        raise


async def upload_file_to_storage(file_obj: Any, timeout: float = 30.0) -> Dict[str, Any]:
    """
    Upload a file to file storage service. Returns JSON response.
    """
    storage_url = _file_storage_base_url()
    url = f"{storage_url.rstrip('/')}/upload"
    try:
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(url, files={"file": file_obj})
                r.raise_for_status()
                return r.json()
        except Exception:
            from urllib import request
            # Synchronous fallback using urllib
            req = request.Request(url, method="POST")
            if hasattr(file_obj, "read"):
                data = file_obj.read()
            else:
                data = file_obj
            req.data = data
            req.add_header("Content-Type", "application/octet-stream")
            with request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
    except Exception as e:
        logger.error("Failed to upload file to storage: %s", e)
        raise


async def store_encrypted_file(
    encrypted_file_data_b64: str,
    filename: str,
    content_type: str = "application/octet-stream",
    sender_id: int = None,
    recipient_id: int = None,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """
    Store an encrypted file (base64 encoded) in the file storage service.

    Returns:
        {
            "file_id": stored filename,
            "filename": original filename,
            "size": file size in bytes,
            "path": access path
        }
    """
    allowed_user_ids: list[int] = []
    if sender_id is not None:
        allowed_user_ids.append(sender_id)
    if recipient_id is not None:
        allowed_user_ids.append(recipient_id)

    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/upload-base64"
    try:
        try:
            payload = {
                "filename": filename,
                "data_b64": encrypted_file_data_b64,
                "content_type": content_type,
                "allowed_user_ids": allowed_user_ids,
            }
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(url, json=payload)
                r.raise_for_status()
                return r.json()
        except Exception:
            from urllib import request

            payload = {
                "filename": filename,
                "data_b64": encrypted_file_data_b64,
                "content_type": content_type,
                "allowed_user_ids": allowed_user_ids,
            }
            req = request.Request(url, method="POST")
            req.data = json.dumps(payload).encode("utf-8")
            req.add_header("Content-Type", "application/json")
            with request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
    except Exception as e:
        logger.error("Failed to store encrypted file: %s", e)
        raise


async def process_message_in_messaging_service(
    client_public_key_b64: str,
    transport_nonce_b64: str,
    transport_ciphertext_b64: str,
    compliance_public_key_b64: str,
    sender_public_key_b64: str,
    recipient_public_key_b64: str,
    timeout: float = 5.0,
) -> Dict[str, Any]:
    """
    Process an encrypted message through the messaging service envelope encryption pipeline.

    Args:
        client_public_key_b64: Client's ephemeral public key
        transport_nonce_b64: Nonce for transport encryption
        transport_ciphertext_b64: Encrypted message
        compliance_public_key_b64: Compliance system public key
        sender_public_key_b64: Sender's public key
        recipient_public_key_b64: Recipient's public key
        timeout: Request timeout in seconds

    Returns:
        Dict with encrypted message and wrapped MEKs:
        {
            "nonce": base64-encoded nonce,
            "ciphertext": base64-encoded ciphertext,
            "compliance_wrapped_mek": wrapped MEK,
            "sender_wrapped_mek": wrapped MEK,
            "recipient_wrapped_mek": wrapped MEK,
        }
    """
    messaging_url = _messaging_base_url()
    url = f"{messaging_url.rstrip('/')}/process"
    try:
        try:
            payload = {
                "client_public_key_b64": client_public_key_b64,
                "transport_nonce_b64": transport_nonce_b64,
                "transport_ciphertext_b64": transport_ciphertext_b64,
                "compliance_public_key_b64": compliance_public_key_b64,
                "sender_public_key_b64": sender_public_key_b64,
                "recipient_public_key_b64": recipient_public_key_b64,
            }
            async with httpx.AsyncClient(timeout=timeout) as client:
                r = await client.post(url, json=payload)
                r.raise_for_status()
                return r.json()
        except Exception:
            from urllib import request
            payload = {
                "client_public_key_b64": client_public_key_b64,
                "transport_nonce_b64": transport_nonce_b64,
                "transport_ciphertext_b64": transport_ciphertext_b64,
                "compliance_public_key_b64": compliance_public_key_b64,
                "sender_public_key_b64": sender_public_key_b64,
                "recipient_public_key_b64": recipient_public_key_b64,
            }
            req = request.Request(url, method="POST")
            req.data = json.dumps(payload).encode("utf-8")
            req.add_header("Content-Type", "application/json")
            with request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
    except Exception as e:
        logger.error("Failed to process message in messaging service: %s", e)
        raise


async def process_message_with_files_in_messaging_service(
    client_public_key_b64: str,
    transport_nonce_b64: str,
    transport_ciphertext_b64: str,
    compliance_public_key_b64: str,
    sender_public_key_b64: str,
    recipient_public_key_b64: str,
    transport_files: list[dict[str, str]],
    file_access_user_id: int,
    recipient_id: int,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    """
    Process an encrypted message and transport-encrypted files using a single MEK.

    Returns:
        {
            "message": {"nonce": str, "ciphertext": str},
            "files": [{"nonce": str, "ciphertext": str}, ...],
            "compliance_wrapped_mek": str,
            "sender_wrapped_mek": str,
            "recipient_wrapped_mek": str,
        }
    """
    messaging_url = _messaging_base_url()
    url = f"{messaging_url.rstrip('/')}/process-with-files"
    payload = {
        "client_public_key_b64": client_public_key_b64,
        "transport_nonce_b64": transport_nonce_b64,
        "transport_ciphertext_b64": transport_ciphertext_b64,
        "compliance_public_key_b64": compliance_public_key_b64,
        "sender_public_key_b64": sender_public_key_b64,
        "recipient_public_key_b64": recipient_public_key_b64,
        "files": transport_files,
        "file_access_user_id": file_access_user_id,
        "recipient_id": recipient_id,
    }
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.post(url, json=payload)
            r.raise_for_status()
            return r.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == status.HTTP_400_BAD_REQUEST:
            try:
                body = e.response.json()
                detail = body.get("detail", str(body)) if isinstance(body, dict) else str(body)
            except Exception:
                detail = (e.response.text or "").strip() or str(e)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=detail,
            ) from e
        logger.error("Failed to process message+files in messaging service: %s", e)
        raise
    except Exception as e:
        logger.error("Failed to process message+files in messaging service: %s", e)
        raise


async def init_resumable_upload_in_storage(
    filename: str,
    total_size: int,
    allowed_user_ids: list[int],
    chunk_size: int | None = None,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/init"
    payload = {
        "filename": filename,
        "total_size": total_size,
        "allowed_user_ids": allowed_user_ids,
    }
    if chunk_size is not None:
        payload["chunk_size"] = chunk_size

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(url, json=payload)
        r.raise_for_status()
        return r.json()


async def get_resumable_upload_status_in_storage(
    upload_id: str,
    user_id: int,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, headers={"X-User-ID": str(user_id)})
        r.raise_for_status()
        return r.json()


async def upload_resumable_chunk_bytes_in_storage(
    upload_id: str,
    user_id: int,
    offset: int,
    data: bytes,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.patch(
            url,
            content=data,
            headers={
                "X-User-ID": str(user_id),
                "Content-Type": "application/octet-stream",
                "X-Upload-Offset": str(offset),
            },
        )
        r.raise_for_status()
        return r.json()


async def stage_transport_ciphertext_resumable_upload(
    *,
    transport_ciphertext: bytes,
    filename: str,
    allowed_user_ids: list[int],
    user_id: int,
    timeout: float = 120.0,
) -> str:
    """Store transport-layer ciphertext in file-storage; return upload_id for messaging."""
    total_size = len(transport_ciphertext)
    init = await init_resumable_upload_in_storage(
        filename=filename,
        total_size=total_size,
        allowed_user_ids=allowed_user_ids,
        timeout=timeout,
    )
    upload_id = str(init["upload_id"])
    await upload_resumable_chunk_bytes_in_storage(
        upload_id,
        user_id,
        0,
        transport_ciphertext,
        timeout=timeout,
    )
    await complete_resumable_upload_in_storage(upload_id, user_id, timeout=timeout)
    return upload_id


async def upload_resumable_chunk_in_storage(
    upload_id: str,
    user_id: int,
    offset: int,
    data_b64: str,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}"
    payload = {
        "offset": offset,
        "data_b64": data_b64,
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.patch(url, json=payload, headers={"X-User-ID": str(user_id)})
        r.raise_for_status()
        return r.json()


async def complete_resumable_upload_in_storage(
    upload_id: str,
    user_id: int,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}/complete"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(url, json={"upload_id": upload_id}, headers={"X-User-ID": str(user_id)})
        r.raise_for_status()
        return r.json()


async def get_resumable_upload_blob_path_in_storage(
    upload_id: str,
    user_id: int,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}/blob-path"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, headers={"X-User-ID": str(user_id)})
        r.raise_for_status()
        return r.json()


async def promote_resumable_upload_to_normal_in_storage(
    upload_id: str,
    user_id: int,
    stored_name: str,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    """Copy a completed resumable upload into normal public attachment storage."""
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}/promote-normal"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            url,
            json={"stored_name": stored_name},
            headers={"X-User-ID": str(user_id)},
        )
        r.raise_for_status()
        return r.json()


async def store_encrypted_file_from_path(
    source_path: str,
    filename: str,
    content_type: str = "application/octet-stream",
    sender_id: int = None,
    recipient_id: int = None,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    allowed_user_ids: list[int] = []
    if sender_id is not None:
        allowed_user_ids.append(sender_id)
    if recipient_id is not None:
        allowed_user_ids.append(recipient_id)

    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/files/encrypted/store"
    src = Path(source_path)

    async with httpx.AsyncClient(timeout=timeout) as client:
        with open(src, "rb") as file_handle:
            r = await client.post(
                url,
                data={
                    "filename": filename,
                    "content_type": content_type,
                    "allowed_user_ids": json.dumps(allowed_user_ids),
                },
                files={"file": (filename, file_handle, content_type)},
            )
        r.raise_for_status()
        return r.json()


async def get_resumable_upload_data_in_storage(
    upload_id: str,
    user_id: int,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}/data-b64"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.get(url, headers={"X-User-ID": str(user_id)})
        r.raise_for_status()
        return r.json()


async def store_normal_file_from_path_in_storage(
    stored_name: str,
    source_path: str | Path,
    timeout: float = 120.0,
) -> Dict[str, Any]:
    """Persist a plain public-chat attachment where file downloads are served from."""
    src = Path(source_path)
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/files/normal/store"

    async with httpx.AsyncClient(timeout=timeout) as client:
        with open(src, "rb") as file_handle:
            r = await client.post(
                url,
                data={"stored_name": stored_name},
                files={"file": (Path(stored_name).name, file_handle, "application/octet-stream")},
            )
        r.raise_for_status()
        return r.json()


async def store_public_thumb_in_storage(
    stored_name: str,
    jpeg_bytes: bytes,
    *,
    width: int,
    height: int,
    file_size: int,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Persist a public-chat thumbnail under file_storage THUMBS_DIR."""
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/files/thumbs/store"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            url,
            data={
                "stored_name": stored_name,
                "width": str(width),
                "height": str(height),
                "file_size": str(file_size),
            },
            files={"file": (f"{Path(stored_name).stem}.jpg", jpeg_bytes, "image/jpeg")},
        )
        r.raise_for_status()
        return r.json()


async def store_public_image_dimensions_in_storage(
    stored_name: str,
    *,
    width: int,
    height: int,
    file_size: int,
    timeout: float = 30.0,
) -> Dict[str, Any]:
    """Persist image dimensions for large public attachments (no JPEG thumbnail)."""
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/files/thumbs/dimensions"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.post(
            url,
            data={
                "stored_name": stored_name,
                "width": str(width),
                "height": str(height),
                "file_size": str(file_size),
            },
        )
        r.raise_for_status()
        return r.json()


def get_public_thumb_meta_in_storage_sync(
    stored_name: str,
    timeout: float = 10.0,
) -> Dict[str, Any] | None:
    """Load thumbnail metadata (+ base64 JPEG when present) for a public attachment basename."""
    file_storage_url = _file_storage_base_url()
    safe_name = Path(stored_name).name
    url = f"{file_storage_url.rstrip('/')}/uploads/files/thumbs/meta/{safe_name}"

    try:
        r = httpx.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        logger.error("Remote file_storage.get_public_thumb_meta failed: %s", e)
        return None


def get_normal_file_dimensions_in_storage_sync(
    stored_name: str,
    timeout: float = 10.0,
) -> Dict[str, Any] | None:
    """Read image dimensions (+ byte size) from the stored normal/public file via file_storage."""
    file_storage_url = _file_storage_base_url()
    safe_name = Path(stored_name).name
    url = f"{file_storage_url.rstrip('/')}/uploads/files/normal/{safe_name}/dimensions"

    try:
        r = httpx.get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        return r.json()
    except Exception as e:
        logger.error("Remote file_storage.get_normal_file_dimensions failed: %s", e)
        return None


async def get_public_thumb_meta_in_storage(
    stored_name: str,
    timeout: float = 10.0,
) -> Dict[str, Any] | None:
    """Load thumbnail metadata (+ base64 JPEG when present) for a public attachment basename."""
    file_storage_url = _file_storage_base_url()
    safe_name = Path(stored_name).name
    url = f"{file_storage_url.rstrip('/')}/uploads/files/thumbs/meta/{safe_name}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if r.status_code != 200:
                return None
            return r.json()
    except Exception as e:
        logger.error("Remote file_storage.get_public_thumb_meta failed: %s", e)
        return None


async def delete_resumable_upload_in_storage(
    upload_id: str,
    user_id: int,
    timeout: float = 10.0,
) -> Dict[str, Any]:
    file_storage_url = _file_storage_base_url()
    url = f"{file_storage_url.rstrip('/')}/uploads/resumable/{upload_id}"

    async with httpx.AsyncClient(timeout=timeout) as client:
        r = await client.delete(url, headers={"X-User-ID": str(user_id)})
        r.raise_for_status()
        return r.json()
