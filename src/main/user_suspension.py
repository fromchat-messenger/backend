"""Bulk lift of expired timed suspensions (single integration via HTTP middleware)."""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import update
from sqlalchemy.orm import Session

from .models import User


def lift_expired_suspensions(db: Session) -> int:
    """Clear suspended users whose ``suspended_until`` is in the past. Returns rowcount."""
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    stmt = (
        update(User)
        .where(
            User.suspended.is_(True),
            User.suspended_until.is_not(None),
            User.suspended_until <= now,
        )
        .values(
            suspended=False,
            suspension_reason=None,
            suspended_until=None,
        )
    )
    result = db.execute(stmt)
    return int(result.rowcount or 0)