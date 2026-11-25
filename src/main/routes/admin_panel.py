"""Admin panel HTTP API (system user id 1)."""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..constants import FILE_STORAGE_SERVICE_URL, LOGS_DIR
from ..dependencies import get_current_user, get_db
from ..models import (
    DMEnvelope,
    Message,
    MessageFile,
    ModerationEvent,
    User,
    UserProfileResponse,
)
from ..security.chat_filter import evaluate_content
from ..presence_service import presence_service
from ..routes.profile import (
    _ensure_owner_unsuspended,
    compute_verification_status,
    get_verified_users_data,
)

router = APIRouter(prefix="/admin", tags=["admin-panel"])

_INTERNAL_AUTH = os.getenv("INTERNAL_AUTH_TOKEN", "")


def _require_system_admin(user: User) -> None:
    if user.id != 1:
        raise HTTPException(status_code=403, detail="Only admin can access this resource")


class FilterCheckRequest(BaseModel):
    text: str = ""


class AdminUsersResponse(BaseModel):
    users: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


@router.get("/users", response_model=AdminUsersResponse)
async def admin_list_users(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    q: str | None = None,
    status: Literal["all", "active", "suspended", "deleted"] = "all",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_system_admin(current_user)
    _ensure_owner_unsuspended(current_user, db)

    query = db.query(User)
    if q:
        needle = f"%{q.strip().lower()}%"
        query = query.filter(
            or_(
                func.lower(User.username).like(needle),
                func.lower(User.display_name).like(needle),
            )
        )
    if status == "active":
        query = query.filter(User.suspended.is_(False), User.deleted.is_(False))
    elif status == "suspended":
        query = query.filter(User.suspended.is_(True))
    elif status == "deleted":
        query = query.filter(User.deleted.is_(True))

    total = query.count()
    users = query.order_by(User.id.asc()).offset(offset).limit(limit).all()
    verified_users_data = get_verified_users_data(db)
    items: list[dict[str, Any]] = []
    for user in users:
        online, last_seen = presence_service.get_presence(user.id)
        verification_status = compute_verification_status(user, verified_users_data)
        payload = UserProfileResponse(
            id=user.id,
            username=user.username,
            display_name=user.display_name,
            profile_picture=user.profile_picture,
            bio=user.bio,
            online=online,
            last_seen=last_seen,
            created_at=user.created_at,
            verified=user.verified,
            verification_status=verification_status.value,
            suspended=user.suspended or False,
            suspension_reason=user.suspension_reason,
            suspended_until=user.suspended_until,
            deleted=user.deleted or False,
        ).model_dump()
        items.append(payload)
    return AdminUsersResponse(users=items, total=total, limit=limit, offset=offset)


@router.get("/moderation/events")
async def list_moderation_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    source: str | None = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    _require_system_admin(current_user)
    query = db.query(ModerationEvent).order_by(ModerationEvent.created_at.desc())
    if source:
        query = query.filter(ModerationEvent.source == source)
    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": [
            {
                "id": row.id,
                "created_at": row.created_at.isoformat() if row.created_at else None,
                "source": row.source,
                "user_id": row.user_id,
                "ip": row.ip,
                "text_preview": row.text_preview,
                "reason_code": row.reason_code,
                "reason_detail": row.reason_detail,
                "message_id": row.message_id,
            }
            for row in rows
        ],
    }


@router.post("/filter/check")
async def admin_filter_check(
    body: FilterCheckRequest,
    current_user: User = Depends(get_current_user),
):
    _require_system_admin(current_user)
    verdict = evaluate_content(body.text)
    return {
        "allowed": not verdict["blocked"],
        "reason_code": verdict["reason_code"],
        "reason_detail": verdict["reason_detail"],
    }


def _file_storage_headers() -> dict[str, str]:
    headers: dict[str, str] = {}
    if _INTERNAL_AUTH:
        headers["X-Internal-Auth"] = _INTERNAL_AUTH
    return headers


@router.get("/files")
async def admin_list_files(
    prefix: str = "",
    limit: int = Query(100, ge=1, le=500),
    cursor: str | None = None,
    current_user: User = Depends(get_current_user),
):
    _require_system_admin(current_user)
    params: dict[str, Any] = {"prefix": prefix, "limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{FILE_STORAGE_SERVICE_URL.rstrip('/')}/internal/files/list"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(url, params=params, headers=_file_storage_headers())
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="File storage unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text[:200])
    return response.json()


@router.delete("/files/{stored_name:path}")
async def admin_delete_file(
    stored_name: str,
    current_user: User = Depends(get_current_user),
):
    _require_system_admin(current_user)
    url = f"{FILE_STORAGE_SERVICE_URL.rstrip('/')}/internal/files/{stored_name}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.delete(url, headers=_file_storage_headers())
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=503, detail="File storage unavailable") from exc
    if response.status_code >= 400:
        raise HTTPException(status_code=response.status_code, detail=response.text[:200])
    return response.json()


@router.get("/security-log")
async def admin_security_log(
    tail: int = Query(200, ge=1, le=2000),
    current_user: User = Depends(get_current_user),
):
    _require_system_admin(current_user)
    log_dir = Path(LOGS_DIR)
    candidates = sorted(log_dir.glob("security*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        candidates = sorted(log_dir.glob("*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not candidates:
        return {"lines": []}
    path = candidates[0]
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            lines = handle.readlines()
    except OSError:
        return {"lines": []}
    return {"path": str(path), "lines": [line.rstrip("\n") for line in lines[-tail:]]}


@router.get("/stats/summary")
async def admin_stats_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Lightweight counters for dashboard bootstrap before WebSocket history."""
    _require_system_admin(current_user)
    users_total = db.query(func.count(User.id)).filter(User.deleted.is_(False)).scalar() or 0
    messages_total = db.query(func.count(Message.id)).scalar() or 0
    dm_total = db.query(func.count(DMEnvelope.id)).filter(DMEnvelope.deleted_at.is_(None)).scalar() or 0
    files_total = db.query(func.count(MessageFile.id)).scalar() or 0
    return {
        "users_registered": int(users_total),
        "public_messages": int(messages_total),
        "dm_messages": int(dm_total),
        "message_files": int(files_total),
        "generated_at": datetime.utcnow().isoformat(),
    }