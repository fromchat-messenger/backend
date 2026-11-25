"""Raise HTTP 422 and record moderation events when the chat filter rejects content."""

from __future__ import annotations

from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from ..models import User
from ..moderation_events import record_moderation_event
from .chat_filter import evaluate_content


def assert_content_allowed(
    db: Session,
    *,
    text: str,
    source: str,
    request: Request | None = None,
    user: User | None = None,
    message_id: int | None = None,
    detail: str = "Content contains prohibited material",
) -> None:
    verdict = evaluate_content(text)
    if not verdict["blocked"]:
        return
    record_moderation_event(
        db,
        source=source,
        reason_code=verdict["reason_code"],
        reason_detail=verdict["reason_detail"],
        text=text,
        user=user,
        request=request,
        message_id=message_id,
    )
    raise HTTPException(status_code=422, detail=detail)