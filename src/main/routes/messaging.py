from datetime import datetime
import html
import logging
from pathlib import Path
import os
import re
import uuid
import asyncio
import time
import unicodedata
from collections import defaultdict, deque
from difflib import SequenceMatcher
from typing import Any
import json
import httpx
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, UploadFile, File, Form, Request, status
from sqlalchemy.orm import Session
from ..dependencies import get_current_user, get_current_user_allow_suspended, get_db
from .account import convert_user_for_dm_conversation
from ..deleted_user import deleted_username_for, is_deleted_or_suspended, is_deleted_user, is_suspended_user, public_display_username
from ..constants import OWNER_USERNAME, DATA_DIR, FILE_STORAGE_SERVICE_URL
from ..models import Message, SendMessageRequest, EditMessageRequest, User, DMEnvelope, DmConversationPreference, MessageFile, DMFile, Reaction, ReactionRequest, ReactionResponse, DMReaction, DMReactionRequest, DMReactionResponse, UpdateLog, MessageEditHistory, MessageEditHistoryResponse, DeviceSession
from ..presence_service import presence_service
from ..push_service import push_service
from src.shared.public_image_dimensions import (
    is_placeholder_dimensions,
    read_image_dimensions_from_bytes,
    read_image_dimensions_from_path,
)
from PIL import Image, ImageOps
import io
import json
from pydantic import BaseModel
from ..security.audit import log_access, log_dm, log_public_chat, log_security
from ..security.chat_filter import contains_profanity
from ..security.rate_limit import rate_limit_per_ip
from ..verification_service import (
    VerificationStatus,
    compute_verification_status,
    get_verified_users_data,
)
from ..websocket.utils import authenticate_user

from ..models import FcmToken
from .. import service_calls

router = APIRouter()
logger = logging.getLogger("uvicorn.error")

MAX_TOTAL_SIZE = 4 * 1024 * 1024 * 1024  # 4 GB

# Legacy local fallback only — canonical public attachments live in file_storage:
# files/data/uploads/files/normal/{name} (served via /uploads/files/normal/...).
FILES_BASE_DIR = DATA_DIR / "uploads" / "files"
FILES_NORMAL_DIR = FILES_BASE_DIR / "normal"
FILES_ENCRYPTED_DIR = FILES_BASE_DIR / "encrypted"

os.makedirs(FILES_NORMAL_DIR, exist_ok=True)
os.makedirs(FILES_ENCRYPTED_DIR, exist_ok=True)

_IMAGE_EXTENSIONS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp"})
_THUMB_SIZE = 80
_LARGE_FILE_THUMB_BYTES = 32 * 1024 * 1024


def _generate_public_thumbnail(image_bytes: bytes) -> tuple[bytes | None, list[int]]:
    """Tiny JPEG thumbnail for public chat. Returns (jpeg_bytes, [w, h]) or (None, [1, 1])."""
    try:
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(image_bytes)))
        img = img.convert("RGB")
        if hasattr(img, "info") and img.info:
            img.info.pop("icc_profile", None)
        w, h = img.size
        aspect_wh = [w, h]
        if w > _THUMB_SIZE or h > _THUMB_SIZE:
            scale = min(_THUMB_SIZE / w, _THUMB_SIZE / h)
            new_w = max(1, int(w * scale))
            new_h = max(1, int(h * scale))
            img = img.resize((new_w, new_h), Image.Resampling.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=85, optimize=True)
        return buf.getvalue(), aspect_wh
    except Exception as e:
        logger.warning("PUBLIC THUMB: Generation failed: %s", e)
        return None, [1, 1]


def _resolve_public_file_media(stored_name: str, original_name: str) -> tuple[str, list[int], int]:
    """Return (thumbnail_b64, [width, height], file_size). Never emits placeholder [1, 1]."""
    thumb_b64 = ""
    size = 0
    dimensions: list[int] | None = None

    try:
        meta = service_calls.get_public_thumb_meta_in_storage_sync(stored_name)
    except Exception as error:
        logger.warning("PUBLIC THUMB: meta load failed for %s: %s", stored_name, error)
        meta = None
    if meta:
        thumb_b64 = str(meta.get("thumbnail_b64") or "")
        size = int(meta.get("file_size") or 0)
        width = int(meta.get("width") or 1)
        height = int(meta.get("height") or 1)
        if not is_placeholder_dimensions(width, height):
            dimensions = [width, height]

    # Fallback: read dimensions from the stored normal file (via file_storage HTTP).
    if dimensions is None or size <= 0:
        try:
            file_dims = service_calls.get_normal_file_dimensions_in_storage_sync(stored_name)
        except Exception as error:
            logger.warning("PUBLIC THUMB: file dimensions load failed for %s: %s", stored_name, error)
            file_dims = None
        if file_dims:
            if dimensions is None:
                width = int(file_dims.get("width") or 1)
                height = int(file_dims.get("height") or 1)
                if not is_placeholder_dimensions(width, height):
                    dimensions = [width, height]
            if size <= 0:
                size = int(file_dims.get("file_size") or 0)

    if dimensions is None and Path(original_name).suffix.lower() in _IMAGE_EXTENSIONS:
        logger.error("PUBLIC THUMB: could not resolve dimensions for %s", stored_name)

    if dimensions is None:
        dimensions = [1, 1]

    return thumb_b64, dimensions, size


def _public_attachment_media_fields_sync(msg: Message) -> dict:
    """Build fileThumbnails / fileAspectRatios / fileSizes for public messages."""
    files = list(msg.files or [])
    if not files:
        return {}
    thumbnails: list[str] = []
    aspect_ratios: list[list[int]] = []
    sizes: list[int] = []
    for f in files:
        stored_name = Path(f.path).name
        thumb_b64, dimensions, size = _resolve_public_file_media(stored_name, f.name)
        thumbnails.append(thumb_b64)
        aspect_ratios.append(dimensions)
        sizes.append(size)
    return {
        "fileThumbnails": thumbnails,
        "fileAspectRatios": aspect_ratios,
        "fileSizes": sizes,
    }


def _get_file_storage_url() -> str:
    return FILE_STORAGE_SERVICE_URL

_SPAM_WINDOW_SECONDS = 45
_SPAM_SIMILARITY_THRESHOLD = 0.88
_SPAM_MESSAGE_LIMIT = 5
_BURST_WINDOW_SECONDS = 30
_BURST_COUNT_THRESHOLD = 20
_SHORT_MESSAGE_LENGTH = 8
_SHORT_MESSAGE_REPEAT_LIMIT = 4

_recent_message_cache: dict[int, deque[tuple[str, str, float, int]]] = defaultdict(deque)  # (normalized, content, timestamp, message_id)
_message_rate_cache: dict[int, deque[tuple[float, int]]] = defaultdict(deque)  # (timestamp, message_id)
_burst_last_logged: dict[int, float] = {}

_PUBLIC_SEND_IDEMPOTENCY_TTL_SEC = 3600
_public_send_by_client_id: dict[tuple[int, str], tuple[int, float]] = {}


def _prune_public_send_idempotency(now: float | None = None) -> None:
    now = now if now is not None else time.time()
    stale = [
        key
        for key, (_, ts) in _public_send_by_client_id.items()
        if now - ts > _PUBLIC_SEND_IDEMPOTENCY_TTL_SEC
    ]
    for key in stale:
        _public_send_by_client_id.pop(key, None)


def _find_idempotent_public_message(
    user_id: int,
    client_message_id: str | None,
    db: Session,
) -> Message | None:
    if not client_message_id:
        return None
    _prune_public_send_idempotency()
    entry = _public_send_by_client_id.get((user_id, client_message_id))
    if not entry:
        return None
    message_id, _ = entry
    return (
        db.query(Message)
        .filter(Message.id == message_id, Message.user_id == user_id)
        .first()
    )


def _remember_idempotent_public_send(
    user_id: int,
    client_message_id: str | None,
    message_id: int,
) -> None:
    if not client_message_id:
        return
    _public_send_by_client_id[(user_id, client_message_id)] = (message_id, time.time())


def _normalize_for_spam(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    # Remove whitespace and punctuation while keeping alphanumerics
    cleaned = re.sub(r"[^0-9a-zа-яё]+", "", normalized, flags=re.IGNORECASE)
    return cleaned


def _monitor_public_message_activity(user: User, content: str, message_id: int, db: Session) -> None:
    now = time.time()

    def suspend(reason: str, event: str, message_ids_to_delete: list[int] = None, **extra: Any) -> None:
        if user.suspended or user.id == 1:
            return
        
        # Delete spam messages that triggered the ban
        if message_ids_to_delete:
            try:
                db.query(Message).filter(Message.reply_to_id.in_(message_ids_to_delete)).update(
                    {Message.reply_to_id: None},
                    synchronize_session=False,
                )
                db.query(MessageEditHistory).filter(
                    MessageEditHistory.message_id.in_(message_ids_to_delete)
                ).delete(synchronize_session=False)
                deleted_count = db.query(Message).filter(Message.id.in_(message_ids_to_delete)).delete(synchronize_session=False)
                db.commit()
                logger.info(f"Deleted {deleted_count} spam messages for user {user.id}")
            except Exception as e:
                logger.error(f"Failed to delete spam messages: {e}")
                db.rollback()
        
        user.suspended = True
        user.suspension_reason = reason
        try:
            from .account import revoke_all_user_sessions
            revoke_all_user_sessions(db, user.id)
        except Exception:
            pass
        db.commit()
        log_security(
            event,
            severity="warning",
            user_id=user.id,
            username=user.username,
            reason=reason,
            deleted_messages=len(message_ids_to_delete) if message_ids_to_delete else 0,
            **extra,
        )
        try:
            asyncio.create_task(messagingManager.send_suspension_to_user(user.id, reason, db))
            asyncio.create_task(
                messagingManager.disconnect_user(user.id, code=4003, reason="Account suspended")
            )
        except Exception:
            pass
        try:
            from .profile import broadcast_profile_update
            asyncio.create_task(broadcast_profile_update(user, db))
        except Exception:
            pass

    # Rate tracking for burst detection
    rate_bucket = _message_rate_cache[user.id]
    rate_bucket.append((now, message_id))
    while rate_bucket and now - rate_bucket[0][0] > _BURST_WINDOW_SECONDS:
        rate_bucket.popleft()

    burst_count = len(rate_bucket)
    if burst_count >= _BURST_COUNT_THRESHOLD:
        last_logged = _burst_last_logged.get(user.id)
        if not last_logged or now - last_logged > _BURST_WINDOW_SECONDS:
            log_security(
                "public_message_burst",
                severity="warning",
                user_id=user.id,
                username=user.username,
                count=burst_count,
                window_seconds=_BURST_WINDOW_SECONDS,
            )
            _burst_last_logged[user.id] = now
        
        # Get all message IDs from the burst window
        burst_message_ids = [msg_id for _, msg_id in rate_bucket]
        suspend(
            "Automatic suspension: excessive message rate",
            "auto_suspension_public_burst",
            message_ids_to_delete=burst_message_ids,
            count=burst_count,
            window_seconds=_BURST_WINDOW_SECONDS,
        )
        return

    # Similarity-based spam detection
    normalized = _normalize_for_spam(content)
    history = _recent_message_cache[user.id]
    while history and now - history[0][2] > _SPAM_WINDOW_SECONDS:
        history.popleft()

    prior_same = sum(1 for prev_norm, _, _, _ in history if prev_norm == normalized)
    prior_similar = sum(
        1
        for prev_norm, _, _, _ in history
        if prev_norm and normalized and prev_norm != normalized and SequenceMatcher(None, normalized, prev_norm).ratio() >= _SPAM_SIMILARITY_THRESHOLD
    )

    history.append((normalized, content, now, message_id))

    total_matches = prior_same + prior_similar + 1

    if len(normalized) <= _SHORT_MESSAGE_LENGTH and prior_same + 1 >= _SHORT_MESSAGE_REPEAT_LIMIT:
        # Get message IDs of all matching short messages
        spam_message_ids = [msg_id for prev_norm, _, _, msg_id in history if prev_norm == normalized]
        spam_message_ids.append(message_id)  # Include current message
        suspend(
            "Automatic suspension: repeated short messages",
            "auto_suspension_public_spam",
            message_ids_to_delete=spam_message_ids,
            occurrences=prior_same + 1,
            window_seconds=_SPAM_WINDOW_SECONDS,
            match_type="short",
        )
        return

    if total_matches >= _SPAM_MESSAGE_LIMIT:
        # Get message IDs of all matching similar messages
        spam_message_ids = []
        for prev_norm, _, _, msg_id in history:
            if prev_norm == normalized:
                spam_message_ids.append(msg_id)
            elif prev_norm and normalized and prev_norm != normalized:
                similarity = SequenceMatcher(None, normalized, prev_norm).ratio()
                if similarity >= _SPAM_SIMILARITY_THRESHOLD:
                    spam_message_ids.append(msg_id)
        spam_message_ids.append(message_id)  # Include current message
        suspend(
            "Automatic suspension: repeated similar public messages",
            "auto_suspension_public_spam",
            message_ids_to_delete=spam_message_ids,
            similar_messages=total_matches,
            window_seconds=_SPAM_WINDOW_SECONDS,
            match_type="similar",
        )


def convert_message(
    msg: Message,
    verified_users_data: list[dict[str, str]] | None = None,
) -> dict:
    vdata = verified_users_data or []
    # Group reactions by emoji
    reactions_dict = {}
    if msg.reactions:
        for reaction in msg.reactions:
            emoji = reaction.emoji
            if emoji not in reactions_dict:
                reactions_dict[emoji] = {
                    "emoji": emoji,
                    "count": 0,
                    "users": []
                }
            reactions_dict[emoji]["count"] += 1
            reactions_dict[emoji]["users"].append({
                "id": reaction.user_id,
                "username": (
                    deleted_username_for(reaction.user_id)
                    if is_deleted_or_suspended(reaction.user)
                    else reaction.user.display_name
                ),
            })

    # Handle deleted or suspended authors (peers see them as deleted accounts)
    if is_deleted_or_suspended(msg.author):
        username = deleted_username_for(msg.author.id)
        profile_picture = None
        verified = False
        verification_status = VerificationStatus.NONE.value
    else:
        username = msg.author.display_name
        profile_picture = msg.author.profile_picture
        verified = msg.author.verified
        verification_status = compute_verification_status(msg.author, vdata).value

    return {
        "id": msg.id,
        "user_id": msg.author.id,
        "content": msg.content,
        "timestamp": msg.timestamp.isoformat(),
        "is_read": msg.is_read,
        "is_edited": msg.is_edited,
        "username": username,
        "profile_picture": profile_picture,
        "verified": verified,
        "verification_status": verification_status,
        "reply_to": convert_message(msg.reply_to, verified_users_data) if msg.reply_to else None,
        "reactions": list(reactions_dict.values()),
        "files": [
            {
                "path": f"/uploads/files/normal/{Path(f.path).name}",
                "id": f.id,
                "name": f.name,
                "message_id": f.message_id
            }
            for f in (msg.files or [])
        ],
        **_public_attachment_media_fields_sync(msg),
    }


def convert_message_for_user(
    msg: Message,
    viewer_user_id: int | None,
    *,
    sender_client_message_id: str | None = None,
    verified_users_data: list[dict[str, str]] | None = None,
) -> dict:
    """
    Per-user public chat payload. [sender_client_message_id] is included only for the sender
    so clients can match optimistic rows to the server ack; never exposed to other viewers.
    """
    payload = convert_message(msg, verified_users_data)
    if (
        sender_client_message_id
        and viewer_user_id is not None
        and viewer_user_id == msg.user_id
    ):
        payload["client_message_id"] = sender_client_message_id
    return payload


def convert_dm_envelope(db: Session, envelope: DMEnvelope, user_id: int | None = None) -> dict:
    # Group reactions by emoji
    reactions_dict = {}
    if envelope.reactions:
        for reaction in envelope.reactions:
            emoji = reaction.emoji
            if emoji not in reactions_dict:
                reactions_dict[emoji] = {
                    "emoji": emoji,
                    "count": 0,
                    "users": []
                }
            reactions_dict[emoji]["count"] += 1
            reactions_dict[emoji]["users"].append({
                "id": reaction.user_id,
                "username": (
                    deleted_username_for(reaction.user_id)
                    if is_deleted_or_suspended(reaction.user)
                    else reaction.user.display_name
                ),
            })

    # Get sender info for verified status
    sender = db.query(User).filter(User.id == envelope.sender_id).first()
    verified_users_data = get_verified_users_data(db)

    # Handle deleted or suspended senders (peers see them as deleted accounts)
    if sender and is_deleted_or_suspended(sender):
        sender_verified = False
        verification_status = VerificationStatus.NONE.value
        sender_username = deleted_username_for(sender.id)
    else:
        sender_verified = sender.verified if sender else False
        verification_status = (
            compute_verification_status(sender, verified_users_data).value
            if sender
            else VerificationStatus.NONE.value
        )
        sender_username = sender.username if sender else f"user_{envelope.sender_id}"

    # Return only the MEK wrapped with the requesting user's key
    if user_id == envelope.sender_id:
        wrapped_mek_b64 = envelope.sender_wrapped_mek_b64
    elif user_id == envelope.recipient_id:
        wrapped_mek_b64 = envelope.recipient_wrapped_mek_b64
    elif user_id == 1:
        # Compliance user (ID 1) gets compliance MEK
        wrapped_mek_b64 = envelope.compliance_wrapped_mek_b64
    else:
        # User is not authorized to view this message
        wrapped_mek_b64 = None

    result = {
        "id": envelope.id,
        "senderId": envelope.sender_id,
        "recipientId": envelope.recipient_id,
        "sender_username": sender_username,
        "iv_b64": envelope.iv_b64,
        "ciphertext_b64": envelope.ciphertext_b64,
        "wrapped_mek_b64": wrapped_mek_b64,
        "timestamp": envelope.timestamp.isoformat(),
        "verified": sender_verified,
        "verification_status": verification_status,
        "reactions": list(reactions_dict.values()),
        "files": []
    }

    for f in (envelope.files or []):
        safe_path = f"/uploads/files/encrypted/{Path(f.path).name}"
        # Files use the same MEK as the message envelope
        selected_file_wrapped = wrapped_mek_b64
        result["files"].append(
            {
                "path": safe_path,
                "id": f.id,
                "name": f.name,
                "dm_envelope_id": f.message_id,
                "wrapped_mek_b64": selected_file_wrapped,
                "nonce_b64": getattr(f, "nonce_b64", None),
            }
        )

    return result


def convert_dm_envelope_for_conversation_preview(
    db: Session,
    envelope: DMEnvelope,
    user_id: int | None = None,
) -> dict:
    """Minimal last-message payload for DM conversation list previews."""
    if user_id == envelope.sender_id:
        wrapped_mek_b64 = envelope.sender_wrapped_mek_b64
    elif user_id == envelope.recipient_id:
        wrapped_mek_b64 = envelope.recipient_wrapped_mek_b64
    elif user_id == 1:
        wrapped_mek_b64 = envelope.compliance_wrapped_mek_b64
    else:
        wrapped_mek_b64 = None

    return {
        "id": envelope.id,
        "senderId": envelope.sender_id,
        "recipientId": envelope.recipient_id,
        "iv_b64": envelope.iv_b64,
        "ciphertext_b64": envelope.ciphertext_b64,
        "wrapped_mek_b64": wrapped_mek_b64,
        "timestamp": envelope.timestamp.isoformat(),
    }


def convert_dm_envelope_for_user(
    db: Session,
    envelope: DMEnvelope,
    user_id: int | None,
    *,
    sender_client_message_id: str | None = None,
) -> dict:
    """
    Per-user DM payload. [sender_client_message_id] is included only for the sender so clients
    can match optimistic rows to the server ack; never exposed to the recipient.
    """
    payload = convert_dm_envelope(db, envelope, user_id)
    if (
        sender_client_message_id
        and user_id is not None
        and user_id == envelope.sender_id
    ):
        payload["client_message_id"] = sender_client_message_id
    return payload


class PublicInitResumableUploadRequest(BaseModel):
    filename: str
    total_size: int
    chunk_size: int | None = None


class PublicUploadChunkRequest(BaseModel):
    offset: int
    data_b64: str


@router.post("/public/upload/init")
async def init_public_resumable_upload(
    request: PublicInitResumableUploadRequest,
    current_user: User = Depends(get_current_user),
):
    if request.total_size <= 0:
        raise HTTPException(status_code=400, detail="total_size must be > 0")

    return await service_calls.init_resumable_upload_in_storage(
        filename=request.filename,
        total_size=request.total_size,
        allowed_user_ids=[current_user.id],
        chunk_size=request.chunk_size,
    )


@router.get("/public/upload/{upload_id}")
async def get_public_resumable_upload_status(
    upload_id: str,
    current_user: User = Depends(get_current_user),
):
    return await service_calls.get_resumable_upload_status_in_storage(upload_id, current_user.id)


@router.patch("/public/upload/{upload_id}")
async def upload_public_resumable_chunk(
    upload_id: str,
    request: PublicUploadChunkRequest,
    current_user: User = Depends(get_current_user),
):
    return await service_calls.upload_resumable_chunk_in_storage(
        upload_id=upload_id,
        user_id=current_user.id,
        offset=request.offset,
        data_b64=request.data_b64,
    )


@router.post("/public/upload/{upload_id}/complete")
async def complete_public_resumable_upload(
    upload_id: str,
    current_user: User = Depends(get_current_user),
):
    return await service_calls.complete_resumable_upload_in_storage(upload_id, current_user.id)


@router.delete("/public/upload/{upload_id}")
async def delete_public_resumable_upload(
    upload_id: str,
    current_user: User = Depends(get_current_user),
):
    return await service_calls.delete_resumable_upload_in_storage(upload_id, current_user.id)


def _optimize_image_bytes_if_possible(content: bytes, original_name: str) -> bytes:
    ext = Path(original_name).suffix.lower()
    try:
        image = ImageOps.exif_transpose(Image.open(io.BytesIO(content)))
        img_format = image.format or ("PNG" if ext == ".png" else "JPEG")
        buf = io.BytesIO()
        save_kwargs = {"optimize": True}
        if img_format.upper() == "JPEG":
            save_kwargs["quality"] = 95
        image.save(buf, format=img_format, **save_kwargs)
        buf.seek(0)
        return buf.read()
    except Exception:
        return content


def _read_image_dimensions(
    *,
    content: bytes | None = None,
    source_path: Path | None = None,
    original_name: str = "",
) -> list[int]:
    """Read pixel size without decoding full multi-hundred-MP payloads when possible."""
    try:
        if source_path is not None:
            dimensions = read_image_dimensions_from_path(source_path)
            if dimensions is not None:
                return dimensions
        if content is not None:
            dimensions = read_image_dimensions_from_bytes(content, Path(original_name).suffix)
            if dimensions is not None:
                return dimensions
    except Exception as error:
        logger.warning("PUBLIC THUMB: dimension read failed: %s", error)
    return [1, 1]


async def _maybe_store_public_thumbnail(
    stored_name: str,
    original_name: str,
    *,
    content: bytes | None = None,
    source_path: Path | None = None,
    file_size: int,
) -> None:
    """Generate and store a thumbnail under file_storage THUMBS_DIR when possible."""
    if Path(original_name).suffix.lower() not in _IMAGE_EXTENSIONS:
        return
    if file_size <= 0:
        return
    try:
        wh = _read_image_dimensions(
            content=content,
            source_path=source_path,
            original_name=original_name,
        )
        if is_placeholder_dimensions(wh[0], wh[1]):
            logger.warning("PUBLIC THUMB: skipping meta for %s — dimensions unknown", stored_name)
            return
        if file_size > _LARGE_FILE_THUMB_BYTES:
            await service_calls.store_public_image_dimensions_in_storage(
                stored_name,
                width=wh[0],
                height=wh[1],
                file_size=file_size,
            )
            return
        if content is not None:
            image_bytes = content
        elif source_path is not None:
            image_bytes = Path(source_path).read_bytes()
        else:
            return
        jpeg, thumb_wh = _generate_public_thumbnail(image_bytes)
        if not jpeg:
            await service_calls.store_public_image_dimensions_in_storage(
                stored_name,
                width=wh[0],
                height=wh[1],
                file_size=file_size,
            )
            return
        await service_calls.store_public_thumb_in_storage(
            stored_name,
            jpeg,
            width=thumb_wh[0],
            height=thumb_wh[1],
            file_size=file_size,
        )
    except Exception as error:
        logger.warning("PUBLIC THUMB: store failed for %s: %s", stored_name, error)


async def _store_public_normal_attachment(
    message_id: int,
    original_name: str,
    *,
    content: bytes | None = None,
    source_path: Path | None = None,
) -> MessageFile:
    """Write a public attachment to file_storage so download proxy can serve it."""
    import tempfile

    ext = Path(original_name).suffix.lower()
    uid = uuid.uuid4().hex
    safe_name = f"{message_id}_{uid}{ext or ''}"

    if content is not None:
        payload = _optimize_image_bytes_if_possible(content, original_name)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        try:
            stored = await service_calls.store_normal_file_from_path_in_storage(safe_name, tmp_path)
        finally:
            tmp_path.unlink(missing_ok=True)
        file_size = int(stored.get("size") or len(payload))
        await _maybe_store_public_thumbnail(
            safe_name,
            original_name,
            content=payload,
            file_size=file_size,
        )
    elif source_path is not None:
        src = Path(source_path)
        if not src.is_file():
            raise HTTPException(status_code=404, detail="Upload payload not found")
        src_size = int(src.stat().st_size)
        # Avoid loading huge non-image blobs into memory just to recompress.
        if (
            Path(original_name).suffix.lower() in _IMAGE_EXTENSIONS
            and src_size <= _LARGE_FILE_THUMB_BYTES
        ):
            payload = _optimize_image_bytes_if_possible(src.read_bytes(), original_name)
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp.write(payload)
                tmp_path = Path(tmp.name)
            try:
                stored = await service_calls.store_normal_file_from_path_in_storage(safe_name, tmp_path)
            finally:
                tmp_path.unlink(missing_ok=True)
            file_size = int(stored.get("size") or len(payload))
            await _maybe_store_public_thumbnail(
                safe_name,
                original_name,
                content=payload,
                file_size=file_size,
            )
        else:
            stored = await service_calls.store_normal_file_from_path_in_storage(safe_name, src)
            file_size = int(stored.get("size") or src_size)
            await _maybe_store_public_thumbnail(
                safe_name,
                original_name,
                source_path=src,
                file_size=file_size,
            )
    else:
        raise HTTPException(status_code=500, detail="Attachment payload missing")

    # Canonical path matches file_storage layout so clients/proxies resolve by basename.
    stored_path = str(stored.get("path") or f"/uploads/files/normal/{safe_name}")
    return MessageFile(
        message_id=message_id,
        name=original_name,
        path=stored_path,
    )


async def _attach_resumable_uploads_to_message(
    message: Message,
    upload_ids: list[str],
    current_user: User,
    db: Session,
) -> None:
    if not upload_ids:
        return

    total_size = 0
    statuses: list[dict] = []
    for upload_id in upload_ids:
        upload_status = await service_calls.get_resumable_upload_status_in_storage(
            upload_id, current_user.id
        )
        if not upload_status.get("complete"):
            raise HTTPException(status_code=409, detail="Upload not completed")
        file_size = int(upload_status.get("total_size", 0))
        total_size += file_size
        statuses.append(upload_status)
        if total_size > MAX_TOTAL_SIZE:
            raise HTTPException(status_code=400, detail="Total attachments size exceeds 4GB")

    for upload_id, upload_status in zip(upload_ids, statuses):
        original_name = Path(upload_status.get("filename", "file")).name
        ext = Path(original_name).suffix.lower()
        uid = uuid.uuid4().hex
        safe_name = f"{message.id}_{uid}{ext or ''}"
        promoted = await service_calls.promote_resumable_upload_to_normal_in_storage(
            upload_id,
            current_user.id,
            safe_name,
        )
        stored_path = str(promoted.get("path") or f"/uploads/files/normal/{safe_name}")
        mf = MessageFile(
            message_id=message.id,
            name=original_name,
            path=stored_path,
        )
        db.add(mf)


async def _send_message_internal(
    message_request: SendMessageRequest,
    current_user: User,
    db: Session,
    files: list[UploadFile] = [],
) -> dict:
    """Internal function to send a message without requiring a Request object.
    
    This can be called from both HTTP endpoints and WebSocket handlers.
    """
    db.refresh(current_user)
    if current_user.suspended:
        raise HTTPException(
            status_code=403,
            detail="Account suspended",
            headers={"suspension_reason": current_user.suspension_reason or "No reason provided"},
        )
    if current_user.deleted:
        raise HTTPException(status_code=403, detail="Account deleted")

    if message_request.reply_to_id:
        # Check if the message being replied to exists
        original_message = db.query(Message).filter(Message.id == message_request.reply_to_id).first()
        if not original_message:
            raise HTTPException(status_code=404, detail="Original message not found")

    raw_client_id = (message_request.client_message_id or "").strip() or None
    if raw_client_id:
        existing = _find_idempotent_public_message(current_user.id, raw_client_id, db)
        if existing is not None:
            return {
                "status": "success",
                "message": convert_message_for_user(
                    existing,
                    current_user.id,
                    sender_client_message_id=raw_client_id,
                    verified_users_data=get_verified_users_data(db),
                ),
            }

    raw_content = message_request.content.strip()
    uploaded_file_ids = [
        uid.strip()
        for uid in (message_request.uploaded_file_ids or [])
        if uid and uid.strip()
    ]

    if not raw_content and not files and not uploaded_file_ids:
        raise HTTPException(
            status_code=400,
            detail="No content provided"
        )

    # Check for profanity and reject the message instead of censoring
    if raw_content and contains_profanity(raw_content):
        raise HTTPException(
            status_code=422,  # Unprocessable Entity - content validation failed
            detail="Message contains inappropriate content and cannot be sent"
        )

    # Escape content for safe HTML display
    escaped_content = html.escape(raw_content, quote=False)

    if len(escaped_content) > 4096:
        raise HTTPException(
            status_code=400,
            detail="Message too long"
        )

    new_message = Message(
        content=escaped_content,
        user_id=current_user.id,
        reply_to_id=message_request.reply_to_id,
        timestamp=datetime.now()
    )

    db.add(new_message)
    upload_ids_for_cleanup: list[str] = []

    try:
        db.flush()

        # Handle files if provided (normal, not encrypted)
        if files:
            total_size = 0
            for up in files:
                # Accumulate size if available
                if hasattr(up, "size") and up.size is not None:
                    total_size += int(up.size)
                else:
                    # If size unknown, read into memory to determine
                    data = await up.read()
                    up.file.seek(0)
                    total_size += len(data)
                if total_size > MAX_TOTAL_SIZE:
                    raise HTTPException(status_code=400, detail="Total attachments size exceeds 4GB")

            for up in files:
                original_name = Path(up.filename or "file").name
                content = await up.read()
                up.file.seek(0)
                mf = await _store_public_normal_attachment(
                    new_message.id,
                    original_name,
                    content=content,
                )
                db.add(mf)

        if uploaded_file_ids:
            await _attach_resumable_uploads_to_message(
                new_message,
                uploaded_file_ids,
                current_user,
                db,
            )
            upload_ids_for_cleanup = list(uploaded_file_ids)

        db.commit()
        db.refresh(new_message)
    except Exception:
        db.rollback()
        raise

    for upload_id in upload_ids_for_cleanup:
        try:
            await service_calls.delete_resumable_upload_in_storage(upload_id, current_user.id)
        except Exception as cleanup_error:
            logger.warning("Failed to cleanup resumable upload %s: %s", upload_id, cleanup_error)

    if raw_client_id:
        _remember_idempotent_public_send(current_user.id, raw_client_id, new_message.id)

    client_message_id = raw_client_id

    # Send push notifications for public messages
    try:
        logger.info(
            "Public message saved: id=%s user=%s content_length=%s",
            new_message.id,
            current_user.id,
            len(new_message.content or ""),
        )
        await push_service.send_public_message_notification(db, new_message, exclude_user_id=current_user.id)
    except Exception as e:
        logger.error(f"Failed to send push notification for message {new_message.id}: {e}")

    # Realtime broadcast for HTTP uploads as well
    try:
        await messagingManager.broadcast_new_message(
            new_message,
            db,
            sender_client_message_id=client_message_id,
        )
    except Exception:
        pass

    _monitor_public_message_activity(current_user, raw_content, new_message.id, db)

    message_payload = convert_message_for_user(
        new_message,
        current_user.id,
        sender_client_message_id=client_message_id,
        verified_users_data=get_verified_users_data(db),
    )
    
    # Prepare log fields
    log_fields = {
        "message_id": new_message.id,
        "user_id": current_user.id,
        "username": current_user.username,
        "reply_to": new_message.reply_to_id,
        "attachments": len(new_message.files or []),
        "length": len(new_message.content),
        "suspended": current_user.suspended,
        "content": new_message.content,
    }
    
    log_public_chat("message_created", **log_fields)

    return {"status": "success", "message": message_payload}


@router.post("/send_message")
@rate_limit_per_ip("30/minute")
async def send_message(
    request: Request,
    message_request: SendMessageRequest | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    # Optional multipart form support
    payload: str | None = Form(default=None),
    files: list[UploadFile] = File(default=[]),
):
    # If payload is provided, prefer it for multipart requests
    if payload and message_request is None:
        # Expect JSON: {"type":"text","data":{"content": str}, "reply_to_id": number|null}
        try:
            obj = json.loads(payload)
            content = obj.get("content", "")
            reply_to_id = obj.get("reply_to_id", None)
            client_message_id = obj.get("client_message_id")
            uploaded_file_ids = obj.get("uploaded_file_ids")
            message_request = SendMessageRequest(
                content=content,
                reply_to_id=reply_to_id,
                client_message_id=client_message_id,
                uploaded_file_ids=uploaded_file_ids,
            )
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid payload JSON")

    if not message_request:
        raise HTTPException(status_code=400, detail="Missing request data")

    return await _send_message_internal(message_request, current_user, db, files)


class RegisterFcmRequest(BaseModel):
    token: str


@router.post("/push/register")
async def register_fcm_token(request: Request, body: RegisterFcmRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Register or update an FCM token for the authenticated user.
    """
    token = body.token.strip() if body and body.token else None
    if not token:
        raise HTTPException(status_code=400, detail="Missing token")

    try:
        # If token already exists (from another device), reassign it to this user.
        token_row = db.query(FcmToken).filter(FcmToken.token == token).first()
        if token_row:
            token_row.user_id = current_user.id
        else:
            # Create new token record (allow multiple tokens per user)
            new = FcmToken(user_id=current_user.id, token=token)
            db.add(new)
        db.commit()
        logger.info(
            "Registered FCM token for user %s: ...%s",
            current_user.id,
            token[-8:],
        )
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to save token")

    return {"status": "success"}


@router.post("/push/unregister")
async def unregister_fcm_token(request: Request, body: RegisterFcmRequest | None = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Unregister an FCM token. If `body.token` provided, remove only that token for the user.
    If no token provided, remove all tokens for the user.
    """
    token = body.token.strip() if body and body.token else None
    logger.info(
        "Unregister FCM request user=%s token=%s",
        current_user.id,
        f"...{token[-8:]}" if token else "ALL",
    )
    try:
        if token:
            db.query(FcmToken).filter(FcmToken.user_id == current_user.id, FcmToken.token == token).delete()
        else:
            db.query(FcmToken).filter(FcmToken.user_id == current_user.id).delete()
        db.commit()
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to remove token")

    return {"status": "success"}


@router.post("/push/test")
async def push_test(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Send a test push to the current user's registered FCM token (for manual testing).
    """
    try:
        fcm_rows = db.query(FcmToken).filter(FcmToken.user_id == current_user.id).all()
        if not fcm_rows:
            raise HTTPException(status_code=404, detail="No FCM token registered for user")
        logger.info(
            "push_test start: user=%s token_count=%s",
            current_user.id,
            len(fcm_rows),
        )

        title = "FromChat test"
        body = "This is a test push from the server"
        data = {"type": "test", "timestamp": datetime.utcnow().isoformat()}

        # Use push_service which uses Admin SDK internally; attempt to send to all tokens
        failures = []
        for fcm in fcm_rows:
            try:
                response = push_service._send_fcm_to_token(fcm.token, title, body, data)
                logger.info(
                    "push_test sent user=%s token=%s response=%s",
                    current_user.id,
                    f"{fcm.token[-8:]}",
                    response,
                )
            except Exception as e:
                logger.error(
                    "Failed to send test push to user %s token %s: %s",
                    current_user.id,
                    f"...{fcm.token[-8:]}",
                    e,
                )
                failures.append(str(e))

        if failures and len(failures) == len(fcm_rows):
            # All failed
            raise HTTPException(status_code=500, detail=f"Failed to send push to any token: {failures}")

        return {"status": "success", "sent": len(fcm_rows) - len(failures), "failed": len(failures)}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"push_test error: {e}")
        raise HTTPException(status_code=500, detail="Internal error")


MAX_MESSAGE_PAGE_LIMIT = 200


def _normalize_page_limit(limit: int | None, *, max_limit: int = MAX_MESSAGE_PAGE_LIMIT) -> int | None:
    if limit is None:
        return None
    return max(1, min(limit, max_limit))


def _paginate_rows_by_id(
    query,
    id_column,
    *,
    limit: int | None = None,
    before_id: int | None = None,
    after_id: int | None = None,
    around_id: int | None = None,
) -> tuple[list[Any], bool, bool, bool]:
    """
    Paginate rows by monotonic id. Always returns rows in ascending id order.

    Returns (rows, has_more, has_more_before, has_more_after).
    has_more mirrors has_more_before for before/around pages and has_more_after for after pages.
    """
    if limit is None:
        rows = query.order_by(id_column.asc()).all()
        return rows, False, False, False

    if around_id is not None:
        anchor = query.filter(id_column == around_id).first()
        if anchor is None:
            return [], False, False, False

        half = limit // 2
        older_count = half
        newer_count = max(0, limit - half - 1)

        older = (
            query.filter(id_column < around_id)
            .order_by(id_column.desc())
            .limit(older_count)
            .all()
        )
        older.reverse()

        newer = (
            query.filter(id_column > around_id)
            .order_by(id_column.asc())
            .limit(newer_count)
            .all()
        )

        rows = older + [anchor] + newer
        if not rows:
            return [], False, False, False

        min_id = min(getattr(row, "id") for row in rows)
        max_id = max(getattr(row, "id") for row in rows)
        has_more_before = (
            query.filter(id_column < min_id).limit(1).first() is not None
        )
        has_more_after = (
            query.filter(id_column > max_id).limit(1).first() is not None
        )
        return rows, has_more_before, has_more_before, has_more_after

    if after_id is not None:
        filtered = query.filter(id_column > after_id)
        probe = filtered.order_by(id_column.asc()).limit(limit + 1).all()
        has_more_after = len(probe) > limit
        rows = probe[:limit]
        if not rows:
            return [], False, False, False
        min_id = getattr(rows[0], "id")
        has_more_before = (
            query.filter(id_column < min_id).limit(1).first() is not None
        )
        return rows, has_more_after, has_more_before, has_more_after

    filtered = query
    if before_id is not None and query.filter(id_column == before_id).first() is not None:
        filtered = query.filter(id_column < before_id)

    probe = filtered.order_by(id_column.desc()).limit(limit + 1).all()
    has_more_before = len(probe) > limit
    rows = probe[:limit]
    rows.reverse()
    return rows, has_more_before, has_more_before, False


def _message_page_response(
    messages_data: list[dict],
    *,
    has_more: bool,
    has_more_before: bool,
    has_more_after: bool,
    status: str = "success",
) -> dict:
    return {
        "status": status,
        "messages": messages_data,
        "has_more": has_more,
        "has_more_before": has_more_before,
        "has_more_after": has_more_after,
    }


@router.get("/get_messages")
@rate_limit_per_ip("60/minute")  # Per-IP limit to prevent abuse
async def get_messages(
    request: Request,
    limit: int | None = None,
    before_id: int | None = None,
    after_id: int | None = None,
    around_id: int | None = None,
    current_user: User = Depends(get_current_user_allow_suspended),
    db: Session = Depends(get_db),
):
    page_limit = _normalize_page_limit(limit)
    if sum(x is not None for x in (before_id, after_id, around_id)) > 1:
        if around_id is not None:
            before_id = None
            after_id = None
        elif before_id is not None and after_id is not None:
            after_id = None

    base_query = db.query(Message)
    rows, has_more, has_more_before, has_more_after = _paginate_rows_by_id(
        base_query,
        Message.id,
        limit=page_limit,
        before_id=before_id,
        after_id=after_id,
        around_id=around_id,
    )

    verified_users_data = get_verified_users_data(db)
    messages_data = [convert_message(msg, verified_users_data) for msg in rows]

    return _message_page_response(
        messages_data,
        has_more=has_more,
        has_more_before=has_more_before,
        has_more_after=has_more_after,
    )


class MarkReadRequest(BaseModel):
    messageIds: list[int]


@router.get("/messages/new")
@rate_limit_per_ip("60/minute")
async def get_new_messages(request: Request, current_user: User = Depends(get_current_user_allow_suspended), db: Session = Depends(get_db)):
    """
    Return unread public messages (Message.is_read == False).
    """
    new_messages = db.query(Message).filter(Message.is_read == False).order_by(Message.timestamp.asc()).all()
    verified_users_data = get_verified_users_data(db)
    messages_data = [convert_message(msg, verified_users_data) for msg in new_messages]
    return {"status": "success", "messages": messages_data}


@router.post("/messages/read")
@rate_limit_per_ip("60/minute")
async def mark_messages_read(request: Request, read_request: MarkReadRequest, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Mark specified message IDs as read (set Message.is_read = True).
    """
    if not read_request or not isinstance(read_request.messageIds, list) or len(read_request.messageIds) == 0:
        return {"status": "success", "updated": 0}

    try:
        updated_count = db.query(Message).filter(Message.id.in_(read_request.messageIds)).update({Message.is_read: True}, synchronize_session=False)
        db.commit()
    except Exception as e:
        try:
            db.rollback()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to mark messages as read")

    return {"status": "success", "updated": int(updated_count)}




@router.get("/dm/fetch")
@rate_limit_per_ip("60/minute")  # Per-IP limit to prevent abuse
async def dm_fetch(request: Request, since: int | None = None, current_user: User = Depends(get_current_user_allow_suspended), db: Session = Depends(get_db)):
    envelopes = db.query(DMEnvelope).filter(DMEnvelope.recipient_id == current_user.id)
    if since:
        envelopes = envelopes.filter(DMEnvelope.id > since)
    envelopes = envelopes.order_by(DMEnvelope.id.asc()).all()

    return {
        "status": "ok",
        "messages": [convert_dm_envelope(db, envelope, current_user.id) for envelope in envelopes]
    }


@router.get("/dm/history/{other_user_id}")
@rate_limit_per_ip("60/minute")  # Per-IP limit to prevent abuse
async def dm_history(
    request: Request,
    other_user_id: int,
    limit: int | None = None,
    before_id: int | None = None,
    after_id: int | None = None,
    around_id: int | None = None,
    current_user: User = Depends(get_current_user_allow_suspended),
    db: Session = Depends(get_db),
):
    if other_user_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid user ID")

    if other_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot get history with yourself")

    # Verify other user exists
    other_user = db.query(User).filter(User.id == other_user_id).first()
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    page_limit = _normalize_page_limit(limit)
    if sum(x is not None for x in (before_id, after_id, around_id)) > 1:
        if around_id is not None:
            before_id = None
            after_id = None
        elif before_id is not None and after_id is not None:
            after_id = None

    base_query = db.query(DMEnvelope).filter(
        ((DMEnvelope.sender_id == current_user.id) & (DMEnvelope.recipient_id == other_user_id))
        | ((DMEnvelope.sender_id == other_user_id) & (DMEnvelope.recipient_id == current_user.id)),
        DMEnvelope.deleted_at.is_(None),
    )

    rows, has_more, has_more_before, has_more_after = _paginate_rows_by_id(
        base_query,
        DMEnvelope.id,
        limit=page_limit,
        before_id=before_id,
        after_id=after_id,
        around_id=around_id,
    )

    messages_data = [
        convert_dm_envelope(db, envelope, current_user.id) for envelope in rows
    ]

    return _message_page_response(
        messages_data,
        has_more=has_more,
        has_more_before=has_more_before,
        has_more_after=has_more_after,
        status="ok",
    )


def _get_dm_conversation_preference(
    db: Session,
    user_id: int,
    other_user_id: int,
) -> DmConversationPreference:
    pref = db.query(DmConversationPreference).filter(
        DmConversationPreference.user_id == user_id,
        DmConversationPreference.other_user_id == other_user_id,
    ).first()
    if pref is not None:
        return pref
    pref = DmConversationPreference(
        user_id=user_id,
        other_user_id=other_user_id,
        archived=False,
        last_read_envelope_id=0,
    )
    db.add(pref)
    db.flush()
    return pref


def _count_dm_unread(
    db: Session,
    user_id: int,
    other_user_id: int,
    last_read_envelope_id: int,
) -> int:
    return db.query(DMEnvelope).filter(
        DMEnvelope.sender_id == other_user_id,
        DMEnvelope.recipient_id == user_id,
        DMEnvelope.id > last_read_envelope_id,
        DMEnvelope.deleted_at.is_(None),
    ).count()


def _build_dm_conversation_list(
    db: Session,
    current_user: User,
    *,
    archived: bool,
) -> list[dict]:
    conversations_query = db.query(DMEnvelope).filter(
        (DMEnvelope.sender_id == current_user.id) | (DMEnvelope.recipient_id == current_user.id),
        DMEnvelope.deleted_at.is_(None),
    ).order_by(DMEnvelope.timestamp.desc())

    latest_by_other_user: dict[int, DMEnvelope] = {}
    for envelope in conversations_query:
        other_user_id = (
            envelope.recipient_id
            if envelope.sender_id == current_user.id
            else envelope.sender_id
        )
        if other_user_id not in latest_by_other_user:
            latest_by_other_user[other_user_id] = envelope

    prefs = {
        pref.other_user_id: pref
        for pref in db.query(DmConversationPreference).filter(
            DmConversationPreference.user_id == current_user.id,
        ).all()
    }

    result: list[dict] = []
    for other_user_id, latest_message in latest_by_other_user.items():
        pref = prefs.get(other_user_id)
        is_archived = bool(pref.archived) if pref is not None else False
        if is_archived != archived:
            continue

        other_user = db.query(User).filter(User.id == other_user_id).first()
        if not other_user:
            continue

        last_read_id = pref.last_read_envelope_id if pref is not None else 0
        unread_count = _count_dm_unread(db, current_user.id, other_user_id, last_read_id)

        result.append({
            "user": convert_user_for_dm_conversation(other_user, db, viewer_id=current_user.id),
            "lastMessage": convert_dm_envelope_for_conversation_preview(
                db, latest_message, current_user.id
            ),
            "unreadCount": unread_count,
        })

    result.sort(key=lambda x: x["lastMessage"]["timestamp"], reverse=True)
    return result


@router.get("/dm/conversations")
@rate_limit_per_ip("60/minute")  # Per-IP limit to prevent abuse
async def get_dm_conversations(request: Request, current_user: User = Depends(get_current_user_allow_suspended), db: Session = Depends(get_db)):
    return {
        "status": "success",
        "conversations": _build_dm_conversation_list(db, current_user, archived=False),
    }


@router.get("/dm/conversations/archived")
@rate_limit_per_ip("60/minute")
async def get_archived_dm_conversations(request: Request, current_user: User = Depends(get_current_user_allow_suspended), db: Session = Depends(get_db)):
    return {
        "status": "success",
        "conversations": _build_dm_conversation_list(db, current_user, archived=True),
    }


class DmMarkReadRequest(BaseModel):
    upToEnvelopeId: int | None = None


def _mark_dm_conversation_read(
    db: Session,
    user_id: int,
    other_user_id: int,
    *,
    up_to_envelope_id: int | None = None,
) -> int:
    """Advance read cursor for a DM thread; returns the new last_read_envelope_id."""
    pref = _get_dm_conversation_preference(db, user_id, other_user_id)
    if up_to_envelope_id is not None and up_to_envelope_id > 0:
        pref.last_read_envelope_id = max(pref.last_read_envelope_id, up_to_envelope_id)
    else:
        latest = db.query(DMEnvelope).filter(
            ((DMEnvelope.sender_id == user_id) & (DMEnvelope.recipient_id == other_user_id))
            | ((DMEnvelope.sender_id == other_user_id) & (DMEnvelope.recipient_id == user_id)),
            DMEnvelope.deleted_at.is_(None),
        ).order_by(DMEnvelope.id.desc()).first()
        if latest is not None:
            pref.last_read_envelope_id = max(pref.last_read_envelope_id, latest.id)
    db.flush()
    return int(pref.last_read_envelope_id)


class DmArchiveRequest(BaseModel):
    archived: bool


@router.post("/dm/conversations/{other_user_id}/archive")
@rate_limit_per_ip("60/minute")
async def set_dm_conversation_archived(
    request: Request,
    other_user_id: int,
    body: DmArchiveRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if other_user_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid user ID")
    if other_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot archive conversation with yourself")

    other_user = db.query(User).filter(User.id == other_user_id).first()
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    has_messages = db.query(DMEnvelope).filter(
        ((DMEnvelope.sender_id == current_user.id) & (DMEnvelope.recipient_id == other_user_id))
        | ((DMEnvelope.sender_id == other_user_id) & (DMEnvelope.recipient_id == current_user.id)),
        DMEnvelope.deleted_at.is_(None),
    ).first()
    if not has_messages:
        raise HTTPException(status_code=404, detail="Conversation not found")

    pref = _get_dm_conversation_preference(db, current_user.id, other_user_id)
    pref.archived = bool(body.archived)
    db.commit()

    await messagingManager.send_update_to_user(
        current_user.id,
        "dmConversationArchive",
        {
            "otherUserId": other_user_id,
            "archived": pref.archived,
        },
        db,
    )

    return {
        "status": "success",
        "otherUserId": other_user_id,
        "archived": pref.archived,
    }


@router.post("/dm/conversations/{other_user_id}/read")
@rate_limit_per_ip("60/minute")
async def mark_dm_conversation_read(
    request: Request,
    other_user_id: int,
    body: DmMarkReadRequest | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if other_user_id <= 0:
        raise HTTPException(status_code=400, detail="Invalid user ID")
    if other_user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot mark conversation with yourself as read")

    other_user = db.query(User).filter(User.id == other_user_id).first()
    if not other_user:
        raise HTTPException(status_code=404, detail="User not found")

    has_messages = db.query(DMEnvelope).filter(
        ((DMEnvelope.sender_id == current_user.id) & (DMEnvelope.recipient_id == other_user_id))
        | ((DMEnvelope.sender_id == other_user_id) & (DMEnvelope.recipient_id == current_user.id)),
        DMEnvelope.deleted_at.is_(None),
    ).first()
    if not has_messages:
        raise HTTPException(status_code=404, detail="Conversation not found")

    up_to = body.upToEnvelopeId if body is not None else None
    last_read = _mark_dm_conversation_read(
        db,
        current_user.id,
        other_user_id,
        up_to_envelope_id=up_to,
    )
    db.commit()

    return {
        "status": "success",
        "otherUserId": other_user_id,
        "lastReadEnvelopeId": last_read,
    }


async def _edit_message_internal(
    message_id: int,
    edit_request: EditMessageRequest,
    current_user: User,
    db: Session
) -> dict:
    """Internal function to edit a message without requiring a Request object.

    This can be called from both HTTP endpoints and WebSocket handlers.
    """
    db.refresh(current_user)
    if current_user.suspended:
        raise HTTPException(
            status_code=403,
            detail="Account suspended",
            headers={"suspension_reason": current_user.suspension_reason or "No reason provided"},
        )
    if current_user.deleted:
        raise HTTPException(status_code=403, detail="Account deleted")

    message = db.query(Message).filter(Message.id == message_id).first()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")
    if message.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only edit your own messages")
    raw_content = edit_request.content.strip()

    if not raw_content:
        raise HTTPException(status_code=400, detail="Message content cannot be empty")

    original_content = message.content

    # Check for profanity and reject the edit instead of censoring
    if contains_profanity(raw_content):
        raise HTTPException(
            status_code=422,  # Unprocessable Entity - content validation failed
            detail="Message contains inappropriate content and cannot be sent"
        )

    escaped_content = html.escape(raw_content, quote=False)

    if len(escaped_content) > 4096:
        raise HTTPException(status_code=400, detail="Message too long")

    # Store edit history in compliance storage before updating the message
    edit_history = MessageEditHistory(
        message_id=message.id,
        previous_content=original_content,
        edited_by_user_id=current_user.id
    )
    db.add(edit_history)

    message.content = escaped_content
    message.is_edited = True

    db.commit()
    db.refresh(message)

    verified_users_data = get_verified_users_data(db)
    payload = convert_message(message, verified_users_data)
    
    # Prepare log fields
    log_fields = {
        "message_id": message.id,
        "user_id": current_user.id,
        "username": current_user.username,
        "reply_to": message.reply_to_id,
        "content": message.content,
        "previous_content": original_content,
    }
    
    log_public_chat("message_edited", **log_fields)

    return {"status": "success", "message": payload}


@router.put("/edit_message/{message_id}")
@rate_limit_per_ip("20/minute")
async def edit_message(
    request: Request,
    message_id: int,
    edit_request: EditMessageRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return await _edit_message_internal(message_id, edit_request, current_user, db)


@router.delete("/delete_message/{message_id}")
async def delete_message(
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    message = db.query(Message).filter(Message.id == message_id).first()

    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Allow owner to delete any message
    if current_user.username != OWNER_USERNAME and message.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="You can only delete your own messages")

    original_content = message.content
    # Clear reply references so hard-delete is not blocked by the self-FK on reply_to_id
    db.query(Message).filter(Message.reply_to_id == message_id).update(
        {Message.reply_to_id: None},
        synchronize_session=False,
    )
    db.query(MessageEditHistory).filter(MessageEditHistory.message_id == message_id).delete(
        synchronize_session=False,
    )
    db.delete(message)
    db.commit()

    log_public_chat(
        "message_deleted",
        message_id=message_id,
        actor_id=current_user.id,
        actor_username=current_user.username,
        original_author_id=message.user_id,
        content=original_content,
    )

    return {"status": "success", "message_id": message_id}


@router.post("/add_reaction")
@rate_limit_per_ip("50/minute")
async def add_reaction(
    request: Request,
    reaction_request: ReactionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if message exists
    message = db.query(Message).filter(Message.id == reaction_request.message_id).first()
    if not message:
        raise HTTPException(status_code=404, detail="Message not found")

    # Check if reaction already exists
    existing_reaction = db.query(Reaction).filter(
        Reaction.message_id == reaction_request.message_id,
        Reaction.user_id == current_user.id,
        Reaction.emoji == reaction_request.emoji
    ).first()

    if existing_reaction:
        # Remove existing reaction (toggle off)
        db.delete(existing_reaction)
        action = "removed"
    else:
        # Add new reaction
        new_reaction = Reaction(
            message_id=reaction_request.message_id,
            user_id=current_user.id,
            emoji=reaction_request.emoji
        )
        db.add(new_reaction)
        action = "added"

    db.commit()

    # Refresh message to get updated reactions
    db.refresh(message)

    verified_users_data = get_verified_users_data(db)
    message_data = convert_message(message, verified_users_data)

    # Broadcast reaction update
    try:
        await messagingManager.broadcast({
            "type": "reactionUpdate",
            "data": {
                "message_id": reaction_request.message_id,
                "emoji": reaction_request.emoji,
                "action": action,
                "user_id": current_user.id,
                "username": current_user.username,
                "reactions": message_data["reactions"]
            }
        }, db)
    except Exception:
        pass

    log_public_chat(
        "reaction_update",
        message_id=reaction_request.message_id,
        user_id=current_user.id,
        username=current_user.username,
        action=action,
        emoji=reaction_request.emoji,
    )

    return {"status": "success", "action": action, "reactions": message_data["reactions"]}


@router.post("/dm/add_reaction")
@rate_limit_per_ip("50/minute")
async def add_dm_reaction(
    request: Request,
    reaction_request: DMReactionRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Check if DM envelope exists
    envelope = db.query(DMEnvelope).filter(DMEnvelope.id == reaction_request.dm_envelope_id).first()
    if not envelope:
        raise HTTPException(status_code=404, detail="DM envelope not found")

    # Check if user is part of this DM conversation
    if current_user.id not in [envelope.sender_id, envelope.recipient_id]:
        raise HTTPException(status_code=403, detail="Not authorized to react to this message")

    # Check if reaction already exists
    existing_reaction = db.query(DMReaction).filter(
        DMReaction.dm_envelope_id == reaction_request.dm_envelope_id,
        DMReaction.user_id == current_user.id,
        DMReaction.emoji == reaction_request.emoji
    ).first()

    if existing_reaction:
        # Remove existing reaction (toggle off)
        db.delete(existing_reaction)
        action = "removed"
    else:
        # Add new reaction
        new_reaction = DMReaction(
            dm_envelope_id=reaction_request.dm_envelope_id,
            user_id=current_user.id,
            emoji=reaction_request.emoji
        )
        db.add(new_reaction)
        action = "added"

    db.commit()

    # Refresh envelope to get updated reactions
    db.refresh(envelope)

    envelope_data = convert_dm_envelope(db, envelope, current_user.id)

    # Broadcast reaction update to both participants
    try:
        await messagingManager.broadcast({
            "type": "dmReactionUpdate",
            "data": {
                "dm_envelope_id": reaction_request.dm_envelope_id,
                "emoji": reaction_request.emoji,
                "action": action,
                "user_id": current_user.id,
                "username": current_user.username,
                "reactions": envelope_data["reactions"]
            }
        }, db)
    except Exception:
        pass

    log_dm(
        "reaction_update",
        dm_envelope_id=reaction_request.dm_envelope_id,
        user_id=current_user.id,
        username=current_user.username,
        action=action,
        emoji=reaction_request.emoji,
    )

    return {"status": "success", "action": action, "reactions": envelope_data["reactions"]}


class MessaggingSocketManager:
    def __init__(self) -> None:
        self.connections: list[WebSocket] = []
        self.user_by_ws: dict[WebSocket, int] = {}
        self.typing_users: dict[int, float] = {}  # user_id -> timestamp
        self.dm_typing_users: dict[int, dict[int, float]] = {}  # user_id -> {recipient_id -> timestamp}
        self.typing_state: dict[int, bool] = {}  # user_id -> is_typing (for public chat)
        self.dm_typing_state: dict[int, dict[int, bool]] = {}  # user_id -> {recipient_id -> is_typing}
        self.ws_subscriptions: dict[WebSocket, set[int]] = {}  # websocket -> set of subscribed user_ids
        self._cleanup_task = None
        # Update system: per-user sequence + durable log (multi-device safe)
        self.sequence_numbers: dict[int, int] = {}  # user_id -> current sequence number
        self.pending_updates_by_user: dict[int, list[dict]] = {}  # user_id -> pending updates
        self.update_batch_tasks_by_user: dict[int, asyncio.Task] = {}  # user_id -> batch task
        self.last_seq_by_ws: dict[WebSocket, int] = {}  # websocket -> last acked sequence
        self.stored_sequences: dict[tuple[int, int], bool] = {}  # (user_id, sequence) -> stored flag
        self.recent_updates_by_user: dict[int, set[str]] = {}  # user_id -> recent signatures
        self._sequence_lock: dict[int, asyncio.Lock] = {}  # user_id -> lock for sequence generation
        # Ephemeral updates are live-only (not written to UpdateLog / not for offline catch-up)
        self._ephemeral_update_types = {
            "typing", "stopTyping", "dmTyping", "stopDmTyping", "statusUpdate",
            "registeredUserCount",
        }
        self.get_updates_too_long_threshold = 500
        self.get_updates_chunk_size = 50
        self.update_log_retention_days = 14

    async def send_error(self, websocket: WebSocket, type: str, e: HTTPException):
        if websocket.client_state.name == "CONNECTED":
            await websocket.send_json({"type": type, "error": {"code": e.status_code, "detail": e.detail}})

    async def _get_next_sequence(self, user_id: int, db: Session | None = None) -> int:
        """Get the next sequence number for a user (shared across all their connections) - thread-safe"""
        if user_id not in self._sequence_lock:
            self._sequence_lock[user_id] = asyncio.Lock()

        async with self._sequence_lock[user_id]:
            if user_id not in self.sequence_numbers:
                # Initialize from database to avoid conflicts on restart
                if db:
                    try:
                        from ..models import UpdateLog
                        latest = db.query(UpdateLog).filter(UpdateLog.user_id == user_id).order_by(UpdateLog.sequence.desc()).first()
                        self.sequence_numbers[user_id] = latest.sequence if latest else 0
                    except Exception:
                        self.sequence_numbers[user_id] = 0
                else:
                    self.sequence_numbers[user_id] = 0
            self.sequence_numbers[user_id] += 1
            return self.sequence_numbers[user_id]

    def _get_update_signature(self, update: dict) -> str:
        """Generate a unique signature for an update to detect duplicates"""
        import hashlib
        import json
        
        update_type = update.get("type", "")
        data = update.get("data", {})
        
        # Create signature based on update type and key identifying fields
        if update_type == "newMessage":
            # Deduplicate by message ID
            sig_data = {"type": update_type, "id": data.get("id")}
        elif update_type == "messageEdited":
            # Deduplicate by message ID
            sig_data = {"type": update_type, "id": data.get("id")}
        elif update_type == "messageDeleted":
            # Deduplicate by message ID
            sig_data = {"type": update_type, "id": data.get("id") or data.get("message_id")}
        elif update_type == "dmNew":
            # Deduplicate by envelope ID
            sig_data = {"type": update_type, "id": data.get("id")}
        elif update_type == "dmEdited":
            # Deduplicate by envelope ID
            sig_data = {"type": update_type, "id": data.get("id")}
        elif update_type == "dmDeleted":
            # Deduplicate by envelope ID
            sig_data = {"type": update_type, "id": data.get("id")}
        elif update_type == "reactionUpdate":
            # Deduplicate by message ID + emoji + user ID
            sig_data = {"type": update_type, "messageId": data.get("message_id"), "emoji": data.get("emoji"), "userId": data.get("userId")}
        elif update_type == "dmReactionUpdate":
            # Deduplicate by envelope ID + emoji + user ID
            sig_data = {"type": update_type, "dmEnvelopeId": data.get("dm_envelope_id"), "emoji": data.get("emoji"), "userId": data.get("userId")}
        elif update_type == "typing" or update_type == "stopTyping":
            # Deduplicate by user ID (state tracking already handles this, but extra protection)
            sig_data = {"type": update_type, "userId": data.get("userId")}
        elif update_type == "dmTyping" or update_type == "stopDmTyping":
            # Deduplicate by user ID (recipient ID is implicit - this update is sent TO the recipient)
            sig_data = {"type": update_type, "userId": data.get("userId")}
        elif update_type == "statusUpdate":
            # Deduplicate by user ID
            sig_data = {"type": update_type, "userId": data.get("userId")}
        elif update_type == "profileUpdate":
            sig_data = {
                "type": update_type,
                "userId": data.get("id"),
                "username": data.get("username"),
                "display_name": data.get("display_name"),
                "bio": data.get("bio"),
                "profile_picture": data.get("profile_picture"),
            }
        elif update_type == "registeredUserCount":
            sig_data = {"type": update_type, "count": data.get("count")}
        elif update_type == "dmConversationArchive":
            sig_data = {
                "type": update_type,
                "otherUserId": data.get("otherUserId"),
                "archived": data.get("archived"),
            }
        else:
            # For unknown types, use full data (less efficient but safe)
            sig_data = {"type": update_type, "data": data}
        
        # Create hash of signature data
        sig_json = json.dumps(sig_data, sort_keys=True)
        return hashlib.md5(sig_json.encode()).hexdigest()

    def _add_update_for_user(self, user_id: int, update: dict) -> bool:
        """Add an update to the pending batch for a user (with deduplication). Returns False if skipped."""
        if user_id not in self.pending_updates_by_user:
            self.pending_updates_by_user[user_id] = []

        signature = self._get_update_signature(update)
        if user_id not in self.recent_updates_by_user:
            self.recent_updates_by_user[user_id] = set()

        if signature in self.recent_updates_by_user[user_id]:
            logger.warning(f"Update was skipped due to duplicate signature {signature}")
            return False

        self.pending_updates_by_user[user_id].append(update)
        self.recent_updates_by_user[user_id].add(signature)

        if len(self.recent_updates_by_user[user_id]) > 100:
            self.recent_updates_by_user[user_id] = set(list(self.recent_updates_by_user[user_id])[-50:])
        return True

    def _websockets_for_user(self, user_id: int) -> list[WebSocket]:
        return [
            websocket
            for websocket, uid in self.user_by_ws.items()
            if uid == user_id
        ]

    def _public_update_recipient_ids(self, db: Session | None) -> set[int]:
        """Connected users plus anyone with a non-revoked device session (offline catch-up)."""
        ids = set(self.user_by_ws.values())
        if db is None:
            return ids
        try:
            rows = (
                db.query(DeviceSession.user_id)
                .filter(DeviceSession.revoked.is_(False))
                .distinct()
                .all()
            )
            ids.update(uid for (uid,) in rows if uid is not None)
        except Exception as e:
            logger.warning(f"Failed to load device-session recipients for updates: {e}")
        return ids

    def get_current_sequence(self, user_id: int, db: Session | None = None) -> int:
        """Return the latest known sequence for a user (memory, else DB)."""
        if user_id in self.sequence_numbers:
            return self.sequence_numbers[user_id]
        if db is not None:
            try:
                latest = (
                    db.query(UpdateLog)
                    .filter(UpdateLog.user_id == user_id)
                    .order_by(UpdateLog.sequence.desc())
                    .first()
                )
                seq = latest.sequence if latest else 0
                self.sequence_numbers[user_id] = seq
                return seq
            except Exception:
                return 0
        return 0

    def prune_update_log(self, db: Session, user_id: int | None = None) -> int:
        """Drop UpdateLog rows older than retention. Never prune by a single device ack."""
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=self.update_log_retention_days)
        try:
            query = db.query(UpdateLog).filter(UpdateLog.timestamp < cutoff)
            if user_id is not None:
                query = query.filter(UpdateLog.user_id == user_id)
            deleted = query.delete(synchronize_session=False)
            db.commit()
            return deleted or 0
        except Exception as e:
            try:
                db.rollback()
            except Exception:
                pass
            logger.warning(f"Failed to prune update_log: {e}")
            return 0

    async def _flush_user_updates(self, user_id: int, db: Session | None = None):
        """Flush pending updates for a user: durable UpdateLog + fan-out to all devices."""
        pending = self.pending_updates_by_user.get(user_id) or []
        if not pending:
            return

        self.pending_updates_by_user[user_id] = []

        durable = [u for u in pending if u.get("type") not in self._ephemeral_update_types]
        ephemeral = [u for u in pending if u.get("type") in self._ephemeral_update_types]

        sockets = self._websockets_for_user(user_id)

        # Ephemeral: live sockets only, no seq / no UpdateLog
        if ephemeral and sockets:
            for websocket in sockets:
                if websocket.client_state.name != "CONNECTED":
                    continue
                try:
                    await websocket.send_json({
                        "type": "updates",
                        "seq": self.get_current_sequence(user_id, db),
                        "updates": ephemeral,
                    })
                except Exception as e:
                    logger.debug(f"Failed to send ephemeral updates to user {user_id}: {e}")

        if not durable:
            return

        # Offline users still get a durable log entry even with zero sockets
        seq = await self._get_next_sequence(user_id, db)

        if db:
            sequence_key = (user_id, seq)
            if sequence_key not in self.stored_sequences:
                try:
                    update_log = UpdateLog(
                        user_id=user_id,
                        sequence=seq,
                        updates=json.dumps(durable),
                    )
                    db.add(update_log)
                    db.commit()
                    self.stored_sequences[sequence_key] = True
                    # Best-effort retention prune (multi-device safe: age-based only)
                    if seq % 50 == 0:
                        self.prune_update_log(db, user_id=user_id)
                except Exception as e:
                    try:
                        db.rollback()
                    except Exception:
                        pass
                    if "UNIQUE constraint" in str(e) or "IntegrityError" in str(e.__class__.__name__):
                        self.stored_sequences[sequence_key] = True
                        logger.debug(
                            f"Update sequence {seq} for user {user_id} already stored by another connection (expected)"
                        )
                    else:
                        logger.warning(f"Unexpected error storing updates in database: {e}")

        for websocket in sockets:
            if websocket.client_state.name != "CONNECTED":
                continue
            try:
                await websocket.send_json({
                    "type": "updates",
                    "seq": seq,
                    "updates": durable,
                })
            except Exception as e:
                logger.debug(f"Failed to send updates seq={seq} to user {user_id}: {e}")

    async def _schedule_user_batch_flush(self, user_id: int, db: Session | None = None):
        """Schedule a per-user batch flush after a short delay."""
        if user_id in self.update_batch_tasks_by_user:
            self.update_batch_tasks_by_user[user_id].cancel()

        async def flush_after_delay():
            await asyncio.sleep(0.075)
            await self._flush_user_updates(user_id, db)
            if user_id in self.update_batch_tasks_by_user:
                del self.update_batch_tasks_by_user[user_id]

        self.update_batch_tasks_by_user[user_id] = asyncio.create_task(flush_after_delay())

    async def enqueue_update_for_user(
        self,
        user_id: int,
        update_type: str,
        update_data: dict,
        db: Session | None = None,
    ):
        """Queue an update for a user (logged even if they have no live connections)."""
        if not self._add_update_for_user(user_id, {"type": update_type, "data": update_data}):
            return
        await self._schedule_user_batch_flush(user_id, db)

    async def _send_update(self, websocket: WebSocket, update_type: str, update_data: dict, db: Session | None = None):
        """Send an update via the user's durable queue (requires authenticated websocket)."""
        user_id = self.user_by_ws.get(websocket)
        if user_id is None:
            logger.warning("Attempted to send update on unauthenticated websocket, skipping")
            return
        await self.enqueue_update_for_user(user_id, update_type, update_data, db)

    async def handle_connection(self, websocket: WebSocket, db: Session):
        # Initialize subscriptions for this connection
        self.ws_subscriptions[websocket] = set()
        
        # Import here to avoid circular import
        from ..websocket.handlers import handler_registry

        while True:
            try:
                data = await websocket.receive_json()
            except Exception as e:
                logger.error(f"Error receiving WebSocket message: {e}")
                break
            
            message_type = data["type"]
            handler_info = handler_registry.get_handler(message_type)
            
            if handler_info:
                handler, authRequired = handler_info
                try:
                    # Authenticate user before calling handler
                    user = authenticate_user(data, db, authRequired)
                    # Set user association for authenticated connections
                    if user:
                        self.user_by_ws[websocket] = user.id
                    
                    # Extract inner data to pass to handler
                    handler_data = data.get("data", {})
                    result = await handler(self, websocket, db, user, handler_data)
                    # If handler returns a value, send it as a WebSocket message
                    if result is not None and websocket.client_state.name == "CONNECTED":
                        await websocket.send_json({"type": message_type, "data": result})
                except HTTPException as e:
                    await self.send_error(websocket, message_type, e)
                except WebSocketDisconnect:
                    raise  # Re-raise to close connection
                except (TypeError, ValueError, KeyError) as e:
                    # Client payload errors (missing/invalid fields) — not internal 500s.
                    logger.warning(f"Client error in handler for {message_type}: {e}")
                    await self.send_error(
                        websocket,
                        message_type,
                        HTTPException(400, "Invalid request"),
                    )
                except Exception as e:
                    logger.error(f"Error in handler for {message_type}: {e}")
                    await self.send_error(websocket, message_type, HTTPException(500, "Internal server error"))
            else:
                if websocket.client_state.name == "CONNECTED":
                    await websocket.send_json({"type": message_type, "error": {"code": 400, "detail": "Invalid type"}})

    async def disconnect(self, websocket: WebSocket, code: int = 1000, message: str | None = None):
        try:
            await websocket.close(code=code, reason=message)
        finally:
            try:
                self.connections.remove(websocket)
            except ValueError:
                pass

    async def connect(self, websocket: WebSocket, db: Session):
        await websocket.accept()
        client_ip = websocket.client.host if websocket.client else None
        log_access(
            "ws_connect",
            path=str(websocket.url.path),
            ip=client_ip,
        )
        self.connections.append(websocket)
        # Initialize update system for this connection
        self.last_seq_by_ws[websocket] = 0
        try:
            await self.handle_connection(websocket, db)
        except WebSocketDisconnect as e:
            logger.info(f"WebSocket disconnected with code {e.code}: {e.reason}")
            log_access(
                "ws_disconnect",
                severity="warning" if e.code != 1000 else "info",
                path=str(websocket.url.path),
                ip=client_ip,
                code=e.code,
                reason=e.reason,
            )
        finally:
            # Flush durable pending updates for this user before tearing down the socket
            user_id = self.user_by_ws.get(websocket)
            if user_id is not None and user_id in self.pending_updates_by_user:
                await self._flush_user_updates(user_id, db)
            # Cleanup connection
            try:
                self.connections.remove(websocket)
            except ValueError:
                pass
            if websocket in self.user_by_ws:
                user_id = self.user_by_ws[websocket]
                try:
                    became_offline, last_seen = presence_service.unregister_connection(user_id, websocket)
                    if became_offline and last_seen is not None:
                        await self.clear_typing_for_user(user_id, db)
                        await self.broadcast_status_change(
                            user_id,
                            False,
                            last_seen.isoformat(),
                            db,
                        )
                except Exception as e:
                    logger.error(f"Failed to set user offline during cleanup: {e}")
                finally:
                    del self.user_by_ws[websocket]
            # Cleanup subscriptions
            if websocket in self.ws_subscriptions:
                del self.ws_subscriptions[websocket]
            if websocket in self.last_seq_by_ws:
                del self.last_seq_by_ws[websocket]

    async def broadcast(self, message: dict, db: Session | None = None):
        """Broadcast a message to all recipients as a durable per-user update."""
        message_type = message.get("type", "")
        update_data = message.get("data", {})
        if message_type in self._ephemeral_update_types:
            # Live-only: connected sockets
            for websocket in self.connections:
                if websocket in self.user_by_ws:
                    await self._send_update(websocket, message_type, update_data, db)
            return
        for user_id in self._public_update_recipient_ids(db):
            await self.enqueue_update_for_user(user_id, message_type, update_data, db)

    async def broadcast_new_message(
        self,
        message: Message,
        db: Session | None = None,
        *,
        sender_client_message_id: str | None = None,
    ):
        """Broadcast newMessage; only the sender receives client_message_id when provided."""
        verified_users_data = get_verified_users_data(db)
        for viewer_id in self._public_update_recipient_ids(db):
            payload = convert_message_for_user(
                message,
                viewer_id,
                sender_client_message_id=sender_client_message_id,
                verified_users_data=verified_users_data,
            )
            await self.enqueue_update_for_user(viewer_id, "newMessage", payload, db)

    async def broadcast_registered_user_count(self, db: Session):
        """Notify all clients of the current non-deleted user count (public chat member count)."""
        try:
            n = db.query(User).filter(User.deleted.is_(False)).count()
        except Exception:
            return
        try:
            await self.broadcast({"type": "registeredUserCount", "data": {"count": n}}, db)
        except Exception:
            pass

    async def send_update_to_user(self, user_id: int, update_type: str, update_data: dict, db: Session | None = None):
        """Send an update to a specific user (batched, durable even if offline)."""
        await self.enqueue_update_for_user(user_id, update_type, update_data, db)

    async def send_to_user(self, user_id: int, message: dict):
        """Send a direct WebSocket message to a specific user (not batched)"""
        for websocket in self.connections:
            if self.user_by_ws.get(websocket) == user_id and websocket.client_state.name == "CONNECTED":
                await websocket.send_json(message)

    async def send_suspension_to_user(self, user_id: int, reason: str, db: Session | None = None):
        """Notify the user and clear any hanging typing indicators for peers."""
        await self.clear_typing_for_user(user_id, db)
        await self.send_update_to_user(user_id, "suspended", {
            "reason": reason
        })

    async def disconnect_user(
        self,
        user_id: int,
        *,
        code: int = 4003,
        reason: str = "Account suspended",
    ) -> None:
        """Force-close every WebSocket belonging to a user (handler finally cleans up)."""
        sockets = [
            websocket
            for websocket, uid in list(self.user_by_ws.items())
            if uid == user_id
        ]
        for websocket in sockets:
            try:
                await websocket.close(code=code, reason=reason)
            except Exception:
                pass

    async def send_unsuspension_to_user(self, user_id: int):
        """Send unsuspension message to user's WebSocket connections (as batched update)"""
        await self.send_update_to_user(user_id, "unsuspended", {})

    async def send_deletion_to_user(self, user_id: int, db: Session | None = None):
        """Notify the user and clear any hanging typing indicators for peers."""
        await self.clear_typing_for_user(user_id, db)
        await self.send_update_to_user(user_id, "account_deleted", {})

    async def clear_typing_for_user(self, user_id: int, db: Session | None = None):
        """Force-stop public and DM typing for a user (suspend/delete/disconnect)."""
        user = None
        if db is not None:
            try:
                user = db.query(User).filter(User.id == user_id).first()
            except Exception:
                user = None
        username = public_display_username(user, fallback=deleted_username_for(user_id))

        was_public_typing = self.typing_state.get(user_id, False)
        self.typing_users.pop(user_id, None)
        self.typing_state[user_id] = False
        if was_public_typing:
            await self.broadcast({
                "type": "stopTyping",
                "data": {
                    "userId": user_id,
                    "username": username,
                },
            }, db)

        recipients = list(self.dm_typing_users.get(user_id, {}).keys())
        was_dm = {
            recipient_id: self.dm_typing_state.get(user_id, {}).get(recipient_id, False)
            for recipient_id in recipients
        }
        self.dm_typing_users.pop(user_id, None)
        self.dm_typing_state.pop(user_id, None)
        for recipient_id in recipients:
            if was_dm.get(recipient_id):
                await self.send_update_to_user(recipient_id, "stopDmTyping", {
                    "userId": user_id,
                    "username": username,
                }, db)

    async def broadcast_status_change(self, user_id: int, online: bool, last_seen: str, db: Session | None = None):
        """Broadcast status change to all connections that are subscribed to this user"""
        # Send to all connections that have this user in their subscriptions
        for websocket in self.connections:
            if websocket in self.ws_subscriptions and user_id in self.ws_subscriptions[websocket]:
                await self._send_update(websocket, "statusUpdate", {
                    "userId": user_id,
                    "online": online,
                    "lastSeen": last_seen
                }, db)

    async def broadcast_profile_update(self, user_id: int, update_data: dict, db: Session | None = None):
        """Broadcast profile update to connections subscribed to this user."""
        for websocket in self.connections:
            if websocket in self.ws_subscriptions and user_id in self.ws_subscriptions[websocket]:
                await self._send_update(websocket, "profileUpdate", update_data, db)

    async def cleanup_stale_typing_indicators(self, db: Session):
        """Periodically cleanup typing indicators that haven't been updated in 3+ seconds"""
        while True:
            try:
                current_time = time.time()
                stale_threshold = 3.0  # 3 seconds

                # Cleanup public chat typing indicators
                stale_public_typing = [
                    user_id for user_id, timestamp in self.typing_users.items()
                    if current_time - timestamp > stale_threshold
                ]

                for user_id in stale_public_typing:
                    was_typing = self.typing_state.get(user_id, False)
                    del self.typing_users[user_id]
                    
                    # Only send update if state changed (stopped typing)
                    if was_typing:
                        self.typing_state[user_id] = False
                        # Get username from database
                        user = db.query(User).filter(User.id == user_id).first()
                        username = public_display_username(user)
                        # Broadcast stop typing
                        await self.broadcast({
                            "type": "stopTyping",
                            "data": {
                                "userId": user_id,
                                "username": username
                            }
                        }, db)

                # Cleanup DM typing indicators
                stale_dm_typing = []
                for user_id, recipients in self.dm_typing_users.items():
                    for recipient_id, timestamp in list(recipients.items()):
                        if current_time - timestamp > stale_threshold:
                            stale_dm_typing.append((user_id, recipient_id))

                for user_id, recipient_id in stale_dm_typing:
                    was_typing = False
                    if user_id in self.dm_typing_state:
                        was_typing = self.dm_typing_state[user_id].get(recipient_id, False)
                    
                    if user_id in self.dm_typing_users and recipient_id in self.dm_typing_users[user_id]:
                        del self.dm_typing_users[user_id][recipient_id]
                        if not self.dm_typing_users[user_id]:
                            del self.dm_typing_users[user_id]
                    
                    # Only send update if state changed (stopped typing)
                    if was_typing:
                        if user_id in self.dm_typing_state:
                            self.dm_typing_state[user_id][recipient_id] = False
                        # Get username from database
                        user = db.query(User).filter(User.id == user_id).first()
                        username = public_display_username(user)
                        # Send stop typing to recipient
                        await self.send_update_to_user(recipient_id, "stopDmTyping", {
                            "userId": user_id,
                            "username": username
                        }, db)

                # Wait 1 second before next cleanup
                await asyncio.sleep(1.0)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                logger.error(f"Error in typing cleanup task: {e}")
                await asyncio.sleep(1.0)

    def start_cleanup_task(self):
        """Start the cleanup task if not already running"""
        if self._cleanup_task is None or self._cleanup_task.done():
            from ..db import SessionLocal
            async def cleanup_with_db():
                try:
                    with SessionLocal() as db:
                        await self.cleanup_stale_typing_indicators(db)
                except asyncio.CancelledError:
                    raise
                except Exception as e:
                    logger.error(f"Error in cleanup task wrapper: {e}")
            self._cleanup_task = asyncio.create_task(cleanup_with_db())

    async def shutdown(self) -> None:
        """Stop background work and close WebSockets so uvicorn can exit."""
        if self._cleanup_task is not None and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            try:
                await self._cleanup_task
            except asyncio.CancelledError:
                pass
            self._cleanup_task = None

        for task in list(self.update_batch_tasks.values()):
            if not task.done():
                task.cancel()
        self.update_batch_tasks.clear()

        for websocket in list(self.connections):
            try:
                await websocket.close(code=1001)
            except Exception:
                pass
        self.connections.clear()
        self.user_by_ws.clear()
        self.ws_subscriptions.clear()
        self.pending_updates.clear()
        self.last_seq_by_ws.clear()
        self.recent_updates.clear()

messagingManager = MessaggingSocketManager()

@router.websocket("/chat/ws")
async def chat_websocket(
    websocket: WebSocket,
    db: Session = Depends(get_db)
):
    await messagingManager.connect(websocket, db)


# File serving proxy endpoints
# Proxy file requests to file_storage service

import httpx


@router.api_route("/uploads/files/normal/{filename:path}", methods=["GET"])
async def proxy_normal_file(
    request: Request,
    filename: str,
    current_user: User = Depends(get_current_user_allow_suspended)
):
    """Proxy file requests to file_storage service."""
    from fastapi.responses import FileResponse, Response

    safe_name = Path(filename).name
    if filename != safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")

    file_storage_url = _get_file_storage_url()
    target_url = f"{file_storage_url}/uploads/files/normal/{safe_name}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(target_url, headers=headers)
            if response.status_code == 200:
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("content-type")
                )
            if response.status_code != 404:
                return Response(
                    content=response.content,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    media_type=response.headers.get("content-type")
                )
        except httpx.RequestError as e:
            logger.error("Failed to proxy file request: %s", e)
            raise HTTPException(status_code=500, detail="File service unavailable")

    legacy_path = FILES_NORMAL_DIR / safe_name
    if legacy_path.is_file():
        return FileResponse(str(legacy_path))

    raise HTTPException(status_code=404, detail="File not found")


@router.api_route("/uploads/files/thumbs/{filename:path}", methods=["GET"])
async def proxy_thumb_file(
    request: Request,
    filename: str,
    current_user: User = Depends(get_current_user_allow_suspended),
):
    """Proxy public-chat thumbnail requests to file_storage THUMBS_DIR."""
    from fastapi.responses import Response

    safe_name = Path(filename).name
    if filename != safe_name:
        raise HTTPException(status_code=400, detail="Invalid file name")

    file_storage_url = _get_file_storage_url()
    target_url = f"{file_storage_url}/uploads/files/thumbs/{safe_name}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(target_url, headers=headers)
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type", "image/jpeg"),
            )
        except httpx.RequestError as e:
            logger.error("Failed to proxy thumb request: %s", e)
            raise HTTPException(status_code=500, detail="File service unavailable")


@router.get("/test-proxy")
async def test_proxy():
    """Test proxy connectivity to file_storage service."""
    file_storage_url = _get_file_storage_url()
    target_url = f"{file_storage_url}/health"

    logger.info(f"Testing proxy to: {target_url}")

    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            response = await client.get(target_url, follow_redirects=False)
            logger.info(f"Test proxy response: {response.status_code}")
            return {"status": "ok", "response_code": response.status_code}
        except Exception as e:
            logger.error(f"Test proxy failed: {e}")
            return {"status": "error", "error": str(e)}


@router.api_route("/uploads/files/encrypted/{filename:path}", methods=["GET"])
async def proxy_encrypted_file(
    request: Request,
    filename: str,
    current_user: User = Depends(get_current_user_allow_suspended)
):
    """Proxy file requests to file_storage service."""
    file_storage_url = _get_file_storage_url()
    target_url = f"{file_storage_url}/uploads/files/encrypted/{filename}"
    headers = {k: v for k, v in request.headers.items() if k.lower() != "host"}
    headers["X-User-ID"] = str(current_user.id)
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.get(target_url, headers=headers, follow_redirects=False)
            from fastapi.responses import Response
            return Response(
                content=response.content,
                status_code=response.status_code,
                headers=dict(response.headers),
                media_type=response.headers.get("content-type")
            )
        except Exception as e:
            logger.error("Failed to proxy file request: %s", e)
            raise HTTPException(status_code=500, detail="File service unavailable")


@router.get("/compliance/edit-history/message/{message_id}")
async def get_message_edit_history_for_compliance(
    request: Request,
    message_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get complete edit history for a public message (compliance access only).

    RESTRICTED: Only accessible by user ID 1 (compliance officer).
    This endpoint returns the full edit history for a public message,
    including all previous content versions.

    Args:
        message_id: ID of the public message
        current_user: Current authenticated user (must be user_id 1)
        db: Database session

    Returns:
        Complete edit history for the message
    """
    client_ip = getattr(request.client, 'host', 'unknown') if request.client else 'unknown'

    # Log compliance access attempt
    log_security("message_edit_history_access_attempt", "warning",
                user_id=current_user.id,
                username=current_user.username,
                ip=client_ip,
                message_id=message_id)

    # Only user_id 1 (compliance officer) can access
    if current_user.id != 1:
        log_security("message_edit_history_access_denied", "error",
                    user_id=current_user.id,
                    username=current_user.username,
                    ip=client_ip,
                    reason="Unauthorized user (compliance officer access required)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. This endpoint is restricted to compliance officers."
        )

    try:
        # Get the original message
        message = db.query(Message).filter(Message.id == message_id).first()
        if not message:
            log_security("message_edit_history_access_failed", "warning",
                        user_id=current_user.id,
                        ip=client_ip,
                        message_id=message_id,
                        reason="Message not found")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Message not found"
            )

        # Get edit history
        edit_history = db.query(MessageEditHistory).filter(
            MessageEditHistory.message_id == message_id
        ).order_by(MessageEditHistory.edited_at).all()

        # Convert to response format
        history_entries = []
        for entry in edit_history:
            edited_by_user = db.query(User).filter(User.id == entry.edited_by_user_id).first()
            history_entries.append({
                "id": entry.id,
                "message_id": entry.message_id,
                "previous_content": entry.previous_content,
                "edited_at": entry.edited_at.isoformat(),
                "edited_by_username": edited_by_user.username if edited_by_user else "unknown",
                "edited_by_user_id": entry.edited_by_user_id
            })

        # Current message data
        current_data = {
            "id": message.id,
            "content": message.content,
            "user_id": message.user_id,
            "timestamp": message.timestamp.isoformat(),
            "is_edited": message.is_edited
        }

        result = {
            "message_id": message_id,
            "current_version": current_data,
            "edit_history": history_entries,
            "total_edits": len(history_entries)
        }

        log_security("message_edit_history_access_success", "info",
                    user_id=current_user.id,
                    username=current_user.username,
                    ip=client_ip,
                    message_id=message_id,
                    edit_count=len(history_entries))

        return result

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Error retrieving message edit history: %s", e)
        log_security("message_edit_history_access_error", "error",
                    user_id=current_user.id,
                    ip=client_ip,
                    message_id=message_id,
                    error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve edit history"
        )