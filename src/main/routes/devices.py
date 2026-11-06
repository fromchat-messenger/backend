import asyncio
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..dependencies import get_current_user, get_db
from ..device_session_lifecycle import notify_sessions_ended
from ..models import User, DeviceSession
from ..presence_service import presence_service
from ..utils import verify_token
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

router = APIRouter()
security = HTTPBearer()


def _get_current_session_id(credentials: HTTPAuthorizationCredentials) -> str:
    token = credentials.credentials
    payload = verify_token(token)
    if not payload or "session_id" not in payload:
        raise HTTPException(status_code=401, detail="Invalid session")
    return payload["session_id"]


def _schedule_session_ended(revoked: list[tuple[int, str]], reason: str) -> None:
    if not revoked:
        return
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        return
    loop.create_task(notify_sessions_ended(revoked, reason=reason))


@router.get("")
def list_devices(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_session_id = _get_current_session_id(credentials)
    sessions = (
        db.query(DeviceSession)
        .filter(DeviceSession.user_id == current_user.id, DeviceSession.revoked == False)
        .order_by(DeviceSession.last_seen.desc())
        .all()
    )
    return {
        "devices": [
            {
                "session_id": s.session_id,
                "session_kind": getattr(s, "session_kind", None) or "standard",
                "device_type": s.device_type,
                "device_name": s.device_name,
                "os_name": s.os_name,
                "os_version": s.os_version,
                "browser_name": s.browser_name,
                "browser_version": s.browser_version,
                "brand": s.brand,
                "model": s.model,
                "created_at": s.created_at.isoformat() if s.created_at else None,
                "last_seen": s.last_seen.isoformat() if s.last_seen else None,
                "expires_at": s.expires_at.isoformat() if getattr(s, "expires_at", None) else None,
                "online": presence_service.is_session_online(s.session_id),
                "revoked": s.revoked,
                "current": s.session_id == current_session_id,
            }
            for s in sessions
        ]
    }


@router.delete("/{session_id}")
def revoke_device(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not session_id or len(session_id) > 64 or len(session_id) < 1:
        raise HTTPException(status_code=400, detail="Invalid session ID")
    
    s = (
        db.query(DeviceSession)
        .filter(DeviceSession.user_id == current_user.id, DeviceSession.session_id == session_id)
        .first()
    )
    if not s:
        raise HTTPException(status_code=404, detail="Device session not found")
    already = s.revoked
    s.revoked = True
    db.commit()
    if not already:
        _schedule_session_ended([(current_user.id, session_id)], reason="revoked")
    return {"status": "success"}


@router.post("/logout-all")
def logout_all_except_current(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_session_id = _get_current_session_id(credentials)
    others = (
        db.query(DeviceSession)
        .filter(
            DeviceSession.user_id == current_user.id,
            DeviceSession.session_id != current_session_id,
            DeviceSession.revoked.is_(False),
        )
        .all()
    )
    revoked = [(current_user.id, s.session_id) for s in others]
    for s in others:
        s.revoked = True
    db.commit()
    _schedule_session_ended(revoked, reason="revoked")
    return {"status": "success"}


