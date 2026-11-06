"""Device session helpers: revoke + notify clients, expire short-lived incognito sessions."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime

from sqlalchemy.orm import Session

from .db import SessionLocal
from .models import DeviceSession
from .presence_service import presence_service

logger = logging.getLogger("uvicorn.error")

INCOGNITO_EXPIRY_POLL_SECONDS = 60


def revoke_sessions(
    db: Session,
    *,
    user_id: int | None = None,
    session_ids: list[str] | None = None,
    only_expired: bool = False,
) -> list[tuple[int, str]]:
    """
    Mark matching non-revoked sessions as revoked.
    Returns list of (user_id, session_id) that were revoked.
    """
    q = db.query(DeviceSession).filter(DeviceSession.revoked.is_(False))
    if user_id is not None:
        q = q.filter(DeviceSession.user_id == user_id)
    if session_ids is not None:
        if not session_ids:
            return []
        q = q.filter(DeviceSession.session_id.in_(session_ids))
    if only_expired:
        q = q.filter(
            DeviceSession.expires_at.isnot(None),
            DeviceSession.expires_at <= datetime.now(),
        )
    rows = q.all()
    revoked: list[tuple[int, str]] = []
    for row in rows:
        row.revoked = True
        revoked.append((row.user_id, row.session_id))
    if revoked:
        db.commit()
    return revoked


async def notify_sessions_ended(
    revoked: list[tuple[int, str]],
    *,
    reason: str,
) -> None:
    """Push session_ended updates and close live sockets for revoked sessions."""
    if not revoked:
        return
    try:
        from .routes.messaging import messagingManager
    except Exception as e:
        logger.warning("notify_sessions_ended: messagingManager unavailable: %s", e)
        return

    for user_id, session_id in revoked:
        try:
            await messagingManager.send_update_to_user(
                user_id,
                "session_ended",
                {"session_id": session_id, "reason": reason},
            )
        except Exception as e:
            logger.warning(
                "notify_sessions_ended: update failed user_id=%s session_id=%s: %s",
                user_id,
                session_id,
                e,
            )
        for websocket in presence_service.websockets_for_session(session_id):
            try:
                await websocket.close(code=4001, reason=reason)
            except Exception:
                pass


async def revoke_and_notify(
    db: Session,
    *,
    reason: str,
    user_id: int | None = None,
    session_ids: list[str] | None = None,
    only_expired: bool = False,
) -> list[tuple[int, str]]:
    revoked = revoke_sessions(
        db,
        user_id=user_id,
        session_ids=session_ids,
        only_expired=only_expired,
    )
    await notify_sessions_ended(revoked, reason=reason)
    return revoked


async def start_incognito_session_expiry_task() -> None:
    """Periodically revoke expired incognito sessions and notify clients."""
    while True:
        try:
            with SessionLocal() as db:
                revoked = revoke_sessions(db, only_expired=True)
            if revoked:
                logger.info(
                    "incognito expiry: revoked %s session(s)",
                    len(revoked),
                )
                await notify_sessions_ended(revoked, reason="incognito_expired")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in incognito session expiry task: %s", e)
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            continue
        try:
            await asyncio.sleep(INCOGNITO_EXPIRY_POLL_SECONDS)
        except asyncio.CancelledError:
            break
