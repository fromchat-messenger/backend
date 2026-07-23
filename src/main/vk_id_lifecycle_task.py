"""Periodic release of VK IDs held on soft-deleted accounts."""

from __future__ import annotations

import asyncio
import logging

from .db import SessionLocal
from .vk_id_lifecycle import release_expired_vk_ids

logger = logging.getLogger("uvicorn.error")

VK_ID_RELEASE_POLL_SECONDS = 15 * 60


async def start_vk_id_release_task(interval_seconds: int = VK_ID_RELEASE_POLL_SECONDS) -> None:
    while True:
        try:
            with SessionLocal() as db:
                release_expired_vk_ids(db)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error("Error in vk id release task: %s", e)
            try:
                await asyncio.sleep(60)
            except asyncio.CancelledError:
                break
            continue
        try:
            await asyncio.sleep(interval_seconds)
        except asyncio.CancelledError:
            break
