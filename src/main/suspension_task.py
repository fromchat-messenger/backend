from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from .admin.moderation_events import record_moderation_event
from .db import SessionLocal
from .models import User

logger = logging.getLogger("uvicorn.error")

SUSPENSION_EXPIRY_POLL_SECONDS = 60


def process_expired_suspensions(db: Session) -> list[int]:
    """Clear timed suspensions past suspension_until. Returns affected user ids."""
    now = datetime.now()
    users = (
        db.query(User)
        .filter(
            User.suspended.is_(True),
            User.suspension_until.isnot(None),
            User.suspension_until <= now,
        )
        .all()
    )
    if not users:
        return []

    user_ids: list[int] = []
    for user in users:
        user.suspended = False
        user.suspension_reason = None
        user.suspension_until = None
        record_moderation_event(
            db,
            event_type="auto_unsuspend",
            user_id=user.id,
            reason="Suspension period elapsed",
        )
        user_ids.append(user.id)

    db.commit()

    try:
        from .routes.messaging import messagingManager

        loop = asyncio.get_running_loop()
        for uid in user_ids:
            loop.create_task(messagingManager.send_unsuspension_to_user(uid))
    except RuntimeError:
        pass
    except Exception as exc:
        logger.warning("Failed to notify auto-unsuspend over WebSocket: %s", exc)

    return user_ids


async def start_suspension_expiry_task() -> None:
    while True:
        await asyncio.sleep(SUSPENSION_EXPIRY_POLL_SECONDS)
        try:
            with SessionLocal() as db:
                cleared = process_expired_suspensions(db)
                if cleared:
                    logger.info("Auto-unsuspended %s user(s): %s", len(cleared), cleared)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("Suspension expiry task error: %s", exc)
