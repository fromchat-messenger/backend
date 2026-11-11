from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from ..models import ModerationEvent


def record_moderation_event(
    db: Session,
    *,
    event_type: str,
    user_id: int | None = None,
    message_id: int | None = None,
    reason: str | None = None,
    detail: dict[str, Any] | None = None,
    commit: bool = False,
) -> ModerationEvent:
    row = ModerationEvent(
        type=event_type,
        user_id=user_id,
        message_id=message_id,
        reason=reason,
        detail_json=json.dumps(detail, ensure_ascii=False) if detail else None,
    )
    db.add(row)
    if commit:
        db.commit()
        db.refresh(row)
    else:
        db.flush()
    return row
