from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..admin.auth import require_admin
from ..constants import DATA_DIR, LOGS_DIR, MESSAGING_SERVICE_URL, FILE_STORAGE_SERVICE_URL
from ..dependencies import get_db
from ..models import DMEnvelope, Message, MessageFile, ModerationEvent, User
from ..routes.account import get_server_instance_id
from ..security.audit import log_security
from ..security.chat_filter import contains_profanity
from shared.message_retention import get_message_retention
from ..constants import CHAT_FILTER_DISABLED

router = APIRouter(prefix="/admin", tags=["admin"])


class ChatFilterCheckBody(BaseModel):
    text: str = Field(..., min_length=1, max_length=4096)


class MessageRetentionPatch(BaseModel):
    days: float = Field(..., description="MESSAGE_RETENTION_DAYS value")


def _user_row(u: User) -> dict[str, Any]:
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "verified": bool(u.verified),
        "suspended": bool(u.suspended),
        "suspension_reason": u.suspension_reason,
        "suspension_until": u.suspension_until.isoformat() if u.suspension_until else None,
        "deleted": bool(u.deleted),
        "created_at": u.created_at.isoformat() if u.created_at else None,
        "admin": u.id == 1,
    }


@router.get("/users")
def list_users(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    q: str | None = None,
    suspended: bool | None = None,
    deleted: bool | None = None,
    sort: Literal["created_at", "username"] = "created_at",
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(User.username.ilike(like), User.display_name.ilike(like), User.bio.ilike(like))
        )
    if suspended is not None:
        query = query.filter(User.suspended.is_(suspended))
    if deleted is not None:
        query = query.filter(User.deleted.is_(deleted))
    total = query.count()
    order = User.created_at.desc() if sort == "created_at" else User.username.asc()
    rows = query.order_by(order).offset(offset).limit(limit).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [_user_row(u) for u in rows],
    }


@router.get("/metrics/summary")
def metrics_summary(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from ..routes.messaging import messagingManager

    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    return {
        "users_total": db.query(User).filter(User.deleted.is_(False)).count(),
        "users_suspended": db.query(User).filter(User.suspended.is_(True), User.deleted.is_(False)).count(),
        "users_online": len(set(messagingManager.user_by_ws.values())),
        "public_messages_today": db.query(Message).filter(Message.timestamp >= today_start).count(),
        "dm_envelopes_total": db.query(DMEnvelope).count(),
        "files_total": db.query(MessageFile).count(),
        "instance_id": get_server_instance_id(),
    }


@router.get("/metrics/series")
def metrics_series(
    metric: Literal["registrations", "public_messages", "dm_messages"] = "registrations",
    interval: Literal["hour", "day"] = "day",
    range_days: int = Query(30, ge=1, le=366, alias="range"),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    now = datetime.now()
    start = now - timedelta(days=range_days)
    if metric == "registrations":
        model, col = User, User.created_at
    elif metric == "public_messages":
        model, col = Message, Message.timestamp
    else:
        model, col = DMEnvelope, DMEnvelope.timestamp

    trunc = func.date_trunc(interval, col)
    rows = (
        db.query(trunc.label("bucket"), func.count().label("count"))
        .filter(col >= start)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    series = [
        {
            "bucket": bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket),
            "count": int(count),
        }
        for bucket, count in rows
    ]
    return {"metric": metric, "interval": interval, "range_days": range_days, "series": series}


@router.get("/metrics/system")
def metrics_system(admin: User = Depends(require_admin)):
    out: dict[str, Any] = {"data_dir_bytes": None, "cpu_percent": None, "memory_percent": None}
    try:
        uploads = DATA_DIR / "uploads"
        total = sum(f.stat().st_size for f in uploads.rglob("*") if f.is_file()) if uploads.exists() else 0
        out["data_dir_bytes"] = total
    except Exception:
        pass
    try:
        import psutil

        out["cpu_percent"] = psutil.cpu_percent(interval=0.1)
        out["memory_percent"] = psutil.virtual_memory().percent
    except Exception:
        pass
    return out


async def _probe(url: str | None) -> dict[str, Any]:
    if not url:
        return {"status": "unconfigured"}
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{url.rstrip('/')}/health")
            return {"status": "up" if resp.status_code == 200 else "degraded", "response_code": resp.status_code}
    except Exception as exc:
        return {"status": "down", "error": str(exc)}


@router.get("/health/services")
async def health_services(admin: User = Depends(require_admin)):
    chat_filter_url = os.getenv("CHAT_FILTER_URL")
    return {
        "messaging": await _probe(MESSAGING_SERVICE_URL),
        "file_storage": await _probe(FILE_STORAGE_SERVICE_URL),
        "chat_filter": await _probe(chat_filter_url),
        "main": {"status": "up"},
    }


@router.get("/files")
def list_files(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(MessageFile)
    total = q.count()
    rows = (
        q.order_by(MessageFile.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": f.id,
                "message_id": f.message_id,
                "path": f.path,
                "name": f.name,
            }
            for f in rows
        ],
    }


@router.delete("/files/{file_id}")
def delete_file(
    file_id: int,
    force: bool = Query(False),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    row = db.query(MessageFile).filter(MessageFile.id == file_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="File not found")
    if not force and row.message_id:
        message = db.query(Message).filter(Message.id == row.message_id).first()
        if message is not None:
            raise HTTPException(
                status_code=409,
                detail="File is attached to a message; pass force=true to delete metadata only",
            )
    db.delete(row)
    db.commit()
    log_security(
        "admin_delete_file",
        "warning",
        actor=admin.username,
        actor_id=admin.id,
        file_id=file_id,
        force=force,
    )
    return {"status": "ok", "file_id": file_id}


@router.get("/settings")
def get_settings(admin: User = Depends(require_admin)):
    state = get_message_retention()
    retention_days = state.days
    compliance_pk = bool(os.getenv("COMPLIANCE_PUBLIC_KEY_B64", "").strip())
    return {
        "instance_id": get_server_instance_id(),
        "message_retention_days": retention_days,
        "compliance_mode": (
            "never_store_mek"
            if state.never_store_compliance_mek()
            else ("retention" if state.cleanup_enabled() else "retain_forever")
        ),
        "compliance_public_key_configured": compliance_pk,
        "enable_chat_filter": not CHAT_FILTER_DISABLED,
        "admin_env_path": os.getenv("ADMIN_ENV_PATH"),
    }


@router.patch("/settings/message-retention")
def patch_message_retention(
    body: MessageRetentionPatch,
    admin: User = Depends(require_admin),
):
    env_path = (os.getenv("ADMIN_ENV_PATH") or "").strip()
    if not env_path or not os.path.isfile(env_path) or not os.access(env_path, os.W_OK):
        raise HTTPException(
            status_code=409,
            detail="MESSAGE_RETENTION_DAYS can only be changed when ADMIN_ENV_PATH points to a writable .env file",
        )
    value = str(body.days)
    path = Path(env_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    updated = False
    new_lines: list[str] = []
    for line in lines:
        if line.startswith("MESSAGE_RETENTION_DAYS="):
            new_lines.append(f"MESSAGE_RETENTION_DAYS={value}")
            updated = True
        else:
            new_lines.append(line)
    if not updated:
        new_lines.append(f"MESSAGE_RETENTION_DAYS={value}")
    path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    log_security(
        "admin_message_retention_patch",
        "warning",
        actor=admin.username,
        actor_id=admin.id,
        days=body.days,
    )
    return {"status": "ok", "message_retention_days": body.days, "restart_required": True}


@router.get("/audit")
def tail_audit(
    limit: int = Query(100, ge=1, le=500),
    action: str | None = None,
    admin: User = Depends(require_admin),
):
    log_path = LOGS_DIR / "security.log"
    if not log_path.is_file():
        return {"items": [], "path": str(log_path)}
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if action:
        needle = action.lower()
        lines = [ln for ln in lines if needle in ln.lower()]
    items = lines[-limit:]
    return {"items": items, "count": len(items), "path": str(log_path)}


@router.get("/moderation/events")
def moderation_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    event_type: str | None = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    q = db.query(ModerationEvent)
    if event_type:
        q = q.filter(ModerationEvent.type == event_type)
    total = q.count()
    rows = (
        q.order_by(ModerationEvent.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": r.id,
                "type": r.type,
                "user_id": r.user_id,
                "message_id": r.message_id,
                "reason": r.reason,
                "detail": json.loads(r.detail_json) if r.detail_json else None,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ],
    }


@router.post("/chat-filter/check")
def chat_filter_check(body: ChatFilterCheckBody, admin: User = Depends(require_admin)):
    blocked = contains_profanity(body.text)
    return {"blocked": blocked, "text_length": len(body.text)}
