"""Periodic analytics sampling for admin live charts."""

from __future__ import annotations

import asyncio
import logging

from .admin.analytics_collector import bootstrap_from_db, collect_minute_sample
from .db import SessionLocal

logger = logging.getLogger("uvicorn.error")

ANALYTICS_POLL_SECONDS = 60


async def start_analytics_task(interval_seconds: int = ANALYTICS_POLL_SECONDS) -> None:
    try:
        with SessionLocal() as db:
            bootstrap_from_db(db)
            collect_minute_sample(db)
    except Exception as e:
        logger.error("Analytics bootstrap failed: %s", e)

    while True:
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break
        try:
            with SessionLocal() as db:
                collect_minute_sample(db)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in analytics sample task: %s", e)
            try:
                await asyncio.sleep(15)
            except asyncio.CancelledError:
                break
