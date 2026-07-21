"""Periodic sync of admin daily message aggregates."""

from __future__ import annotations

import asyncio
import logging

from .admin.message_stats import sync_daily_message_stats
from .db import SessionLocal

logger = logging.getLogger("uvicorn.error")

# Refresh today's live bucket often; closed days finalize on the first run after midnight.
MESSAGE_STATS_POLL_SECONDS = 5 * 60


async def start_message_stats_task(interval_seconds: int = MESSAGE_STATS_POLL_SECONDS) -> None:
    # Run once immediately so the dashboard has data after deploy/restart.
    while True:
        try:
            with SessionLocal() as db:
                sync_daily_message_stats(db)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in message stats sync task: %s", e)
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            continue
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break
