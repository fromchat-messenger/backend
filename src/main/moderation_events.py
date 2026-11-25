"""Persist chat-filter rejections for the admin panel."""

from __future__ import annotations

from fastapi import Request
from sqlalchemy.orm import Session

from .models import ModerationEvent, User


def _preview(text: str, limit: int = 200) -> str:
    trimmed = (text or "").strip()
    if len(trimmed) <= limit:
        return trimmed
    return trimmed[: limit - 1] + "…"


def record_moderation_event(
    db: Session,
    *,
    source: str,
    reason_code: str,
    reason_detail: str,
    text: str,
    user: User | None = None,
    request: Request | None = None,
    message_id: int | None = None,
) -> None:
    ip = None
    if request is not None:
        from .utils import get_client_ip

        ip = get_client_ip(request)
    row = ModerationEvent(
        source=source,
        user_id=user.id if user else None,
        ip=ip,
        text_preview=_preview(text),
        reason_code=reason_code or "unknown",
        reason_detail=reason_detail or "Content rejected",
        message_id=message_id,
    )
    db.add(row)
    try:
        db.commit()
    except Exception:
        db.rollback()