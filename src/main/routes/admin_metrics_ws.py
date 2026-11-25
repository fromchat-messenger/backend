"""Live admin metrics over WebSocket."""

from __future__ import annotations

import asyncio
import json
import os
from collections import deque
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, HTTPException, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import func

from ..db import SessionLocal
from ..models import DMEnvelope, Message, MessageFile, User

router = APIRouter(tags=["admin-metrics"])

_HISTORY_BUCKETS = 60
_TICK_SECONDS = 2.0


def _cpu_snapshot() -> dict[str, float]:
    try:
        import psutil

        return {
            "cpu_percent": float(psutil.cpu_percent(interval=None)),
            "memory_percent": float(psutil.virtual_memory().percent),
            "disk_percent": float(psutil.disk_usage("/").percent),
        }
    except Exception:
        return {"cpu_percent": 0.0, "memory_percent": 0.0, "disk_percent": 0.0}


def _series_counts(db, minutes: int = 60) -> dict[str, list[dict[str, Any]]]:
    now = datetime.utcnow()
    start = now - timedelta(minutes=minutes)
    bucket_size = timedelta(minutes=1)

    def bucketize(rows: list[tuple[datetime, int]]) -> list[dict[str, Any]]:
        counts: dict[datetime, int] = {}
        for ts, _ in rows:
            if ts is None:
                continue
            key = ts.replace(second=0, microsecond=0)
            counts[key] = counts.get(key, 0) + 1
        series = []
        cursor = start.replace(second=0, microsecond=0)
        while cursor <= now:
            series.append(
                {
                    "t": cursor.isoformat(),
                    "v": counts.get(cursor, 0),
                }
            )
            cursor += bucket_size
        return series[-_HISTORY_BUCKETS:]

    user_rows = (
        db.query(User.created_at)
        .filter(User.created_at >= start, User.deleted.is_(False))
        .all()
    )
    msg_rows = db.query(Message.timestamp).filter(Message.timestamp >= start).all()
    dm_rows = (
        db.query(DMEnvelope.timestamp)
        .filter(DMEnvelope.timestamp >= start, DMEnvelope.deleted_at.is_(None))
        .all()
    )
    file_ts = db.query(Message.timestamp).filter(Message.timestamp >= start).all()

    totals = {
        "users_registered": int(
            db.query(func.count(User.id)).filter(User.deleted.is_(False)).scalar() or 0
        ),
        "public_messages": int(db.query(func.count(Message.id)).scalar() or 0),
        "dm_messages": int(
            db.query(func.count(DMEnvelope.id)).filter(DMEnvelope.deleted_at.is_(None)).scalar() or 0
        ),
        "message_files": int(db.query(func.count(MessageFile.id)).scalar() or 0),
    }

    return {
        "registrations": bucketize([(r[0], 1) for r in user_rows if r[0]]),
        "public_messages": bucketize([(r[0], 1) for r in msg_rows if r[0]]),
        "dm_messages": bucketize([(r[0], 1) for r in dm_rows if r[0]]),
        "files": bucketize([(r[0], 1) for r in file_ts if r[0]]),
        "totals": totals,
    }


def get_current_user_from_token_ws(token: str):
    with SessionLocal() as db:
        from ..websocket.utils import get_current_user_from_token

        user = get_current_user_from_token(token, db)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        if user.id != 1:
            raise HTTPException(status_code=403, detail="Admin only")
        return user


@router.websocket("/admin/ws/metrics")
async def admin_metrics_socket(websocket: WebSocket, token: str = Query(...)):
    try:
        get_current_user_from_token_ws(token)
    except HTTPException:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    ring: deque[dict[str, float]] = deque(maxlen=_HISTORY_BUCKETS)

    try:
        with SessionLocal() as db:
            history = _series_counts(db)
        await websocket.send_text(
            json.dumps({"type": "history", "series": history, "host": _cpu_snapshot()})
        )
        while True:
            host = _cpu_snapshot()
            ring.append(host)
            with SessionLocal() as db:
                totals = _series_counts(db)["totals"]
            await websocket.send_text(
                json.dumps(
                    {
                        "type": "tick",
                        "host": host,
                        "totals": totals,
                        "cpu_ring": list(ring),
                        "generated_at": datetime.utcnow().isoformat(),
                    }
                )
            )
            await asyncio.sleep(_TICK_SECONDS)
    except WebSocketDisconnect:
        return
    except Exception:
        await websocket.close()