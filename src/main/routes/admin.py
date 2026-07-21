from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..admin.access_log import access_log_path, follow_new_bytes, list_requests
from ..admin.auth import require_admin
from ..admin.compliance_bundle import (
    build_compliance_zip,
    conversations_for_user,
    messages_for_pair,
    users_with_dms,
)
from ..admin.ip_bans import ban_ip, list_bans, unban_ip
from ..admin.ip_history import get_ips_for_user
from ..admin.rate_limits import list_rate_limited
from ..admin.ssh_config import ssh_enabled, ssh_host, ssh_port, ssh_status
from ..admin.stats_store import get_stats
from ..dependencies import get_db
from ..models import DMEnvelope, DeviceSession, Message, User
from ..security.audit import log_security
from ..utils import verify_token

logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/admin", tags=["admin"])


class BanIpBody(BaseModel):
    ip: str = Field(..., min_length=1)
    reason: str | None = None


class BundleBody(BaseModel):
    message_ids: list[int] = Field(..., min_length=1)


def _user_summary(u: User) -> dict[str, Any]:
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "bio": u.bio,
        "profile_picture": getattr(u, "profile_picture", None),
        "verified": bool(u.verified),
        "suspended": bool(u.suspended),
        "suspension_reason": u.suspension_reason,
        "deleted": bool(u.deleted),
        "admin": u.id == 1,
        "created_at": u.created_at.isoformat() if getattr(u, "created_at", None) else None,
    }


@router.get("/stats/overview")
def stats_overview(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from ..routes.messaging import messagingManager

    registered = db.query(User).filter(User.deleted.is_(False)).count()
    suspended = db.query(User).filter(User.suspended.is_(True), User.deleted.is_(False)).count()
    verified = db.query(User).filter(User.verified.is_(True), User.deleted.is_(False)).count()
    durable = get_stats()
    online_ids = set(messagingManager.user_by_ws.values())
    return {
        "registered": registered,
        "suspended": suspended,
        "verified": verified,
        "messages_blocked": int(durable.get("messages_blocked") or 0),
        "active_websocket_connections": len(messagingManager.connections),
        "online_users": len(online_ids),
        "active_calls": 0,
    }


@router.get("/stats/analytics")
def stats_analytics(
    granularity: Literal["minute", "hour", "day", "month"] = Query("hour"),
    window: int | None = Query(None, ge=1, le=2000),
    admin: User = Depends(require_admin),
):
    from ..admin.analytics_store import DEFAULT_WINDOW, approx_size_bytes, query_all_metrics

    series = query_all_metrics(granularity, window=window)
    return {
        "granularity": granularity,
        "window": window or DEFAULT_WINDOW[granularity],
        "series": series,
        "storage_bytes": approx_size_bytes(),
    }


@router.websocket("/stats/ws")
async def stats_ws(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        auth = websocket.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    payload = verify_token(token or "")
    if not payload or payload.get("user_id") != 1:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    from ..admin.analytics_collector import add_analytics_listener, remove_analytics_listener
    from ..admin.analytics_store import DEFAULT_WINDOW, query_all_metrics

    state = {"granularity": "hour"}

    queue: asyncio.Queue = asyncio.Queue(maxsize=8)

    def on_tick(granularity: str, series: dict) -> None:
        if granularity != state["granularity"]:
            return
        try:
            queue.put_nowait({"type": "tick", "granularity": granularity, "series": series})
        except asyncio.QueueFull:
            pass

    add_analytics_listener(on_tick)
    try:
        await websocket.send_json(
            {
                "type": "snapshot",
                "granularity": state["granularity"],
                "window": DEFAULT_WINDOW[state["granularity"]],  # type: ignore[index]
                "series": query_all_metrics(state["granularity"]),  # type: ignore[arg-type]
            }
        )
        while True:
            try:
                msg = await asyncio.wait_for(websocket.receive_json(), timeout=0.5)
                if isinstance(msg, dict) and msg.get("type") == "subscribe":
                    gran = msg.get("granularity") or "hour"
                    if gran in ("minute", "hour", "day", "month"):
                        state["granularity"] = gran
                        await websocket.send_json(
                            {
                                "type": "snapshot",
                                "granularity": gran,
                                "window": DEFAULT_WINDOW[gran],  # type: ignore[index]
                                "series": query_all_metrics(gran),  # type: ignore[arg-type]
                            }
                        )
            except asyncio.TimeoutError:
                pass
            except WebSocketDisconnect:
                break

            while not queue.empty():
                try:
                    await websocket.send_json(queue.get_nowait())
                except Exception:
                    break
    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass
    finally:
        remove_analytics_listener(on_tick)


@router.get("/stats/messages")
def stats_messages(
    granularity: Literal["hour", "day", "month"] = Query("day"),
    range_days: int = Query(30, ge=1, le=366, alias="range"),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    # Day series is durable (closed days) + live today.
    if granularity == "day":
        from ..admin.message_stats import build_daily_series

        return {"granularity": granularity, "series": build_daily_series(db, range_days)}

    now = datetime.now()
    start = now - timedelta(days=range_days)
    if granularity == "hour":
        start = now - timedelta(hours=min(range_days * 24, 168))
        trunc = func.date_trunc("hour", Message.timestamp)
        trunc_dm = func.date_trunc("hour", DMEnvelope.timestamp)
    else:
        trunc = func.date_trunc("month", Message.timestamp)
        trunc_dm = func.date_trunc("month", DMEnvelope.timestamp)

    public_rows = (
        db.query(trunc.label("bucket"), func.count().label("count"))
        .filter(Message.timestamp >= start)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    dm_rows = (
        db.query(trunc_dm.label("bucket"), func.count().label("count"))
        .filter(DMEnvelope.timestamp >= start)
        .group_by("bucket")
        .order_by("bucket")
        .all()
    )
    buckets: dict[str, dict[str, int]] = {}
    for bucket, count in public_rows:
        key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket)
        buckets.setdefault(key, {"public": 0, "dm": 0, "total": 0})
        buckets[key]["public"] = int(count)
        buckets[key]["total"] += int(count)
    for bucket, count in dm_rows:
        key = bucket.isoformat() if hasattr(bucket, "isoformat") else str(bucket)
        buckets.setdefault(key, {"public": 0, "dm": 0, "total": 0})
        buckets[key]["dm"] = int(count)
        buckets[key]["total"] += int(count)
    series = [
        {"bucket": k, **v}
        for k, v in sorted(buckets.items(), key=lambda x: x[0])
    ]
    return {"granularity": granularity, "series": series}


@router.get("/connections")
def list_connections(
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from ..routes.messaging import messagingManager

    counts: dict[int, int] = {}
    for uid in messagingManager.user_by_ws.values():
        counts[uid] = counts.get(uid, 0) + 1
    users = db.query(User).filter(User.id.in_(list(counts.keys()))).all() if counts else []
    by_id = {u.id: u for u in users}
    items = []
    for uid, n in sorted(counts.items(), key=lambda x: -x[1]):
        u = by_id.get(uid)
        ips = get_ips_for_user(uid)
        items.append(
            {
                "user_id": uid,
                "username": u.username if u else f"user_{uid}",
                "display_name": u.display_name if u else None,
                "connection_count": n,
                "last_ip": ips[0]["ip"] if ips else None,
            }
        )
    return {"items": items, "total_connections": len(messagingManager.connections)}


@router.post("/connections/{user_id}/disconnect")
async def disconnect_user(
    user_id: int,
    revoke_sessions: bool = Query(False),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from ..routes.messaging import messagingManager

    if user_id == 1:
        raise HTTPException(status_code=400, detail="Cannot force-disconnect admin")
    await messagingManager.disconnect_user(user_id, code=4003, reason="Disconnected by admin")
    revoked = 0
    if revoke_sessions:
        sessions = (
            db.query(DeviceSession)
            .filter(DeviceSession.user_id == user_id, DeviceSession.revoked.is_(False))
            .all()
        )
        for s in sessions:
            s.revoked = True
            revoked += 1
        db.commit()
    log_security(
        "admin_force_disconnect",
        "warning",
        actor=admin.username,
        actor_id=admin.id,
        target_user_id=user_id,
        revoked_sessions=revoked,
    )
    return {"status": "ok", "revoked_sessions": revoked}


@router.get("/accounts")
def list_accounts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    q: str | None = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    query = db.query(User)
    if q:
        like = f"%{q}%"
        query = query.filter(
            or_(User.username.ilike(like), User.display_name.ilike(like), User.bio.ilike(like))
        )
    total = query.count()
    rows = (
        query.order_by(User.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [_user_summary(u) for u in rows],
    }


@router.get("/accounts/{user_id}")
def get_account(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return _user_summary(user)


@router.get("/accounts/{user_id}/ips")
def account_ips(
    user_id: int,
    admin: User = Depends(require_admin),
):
    return {"items": get_ips_for_user(user_id)}


@router.get("/accounts/{user_id}/devices")
def account_devices(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    sessions = (
        db.query(DeviceSession)
        .filter(DeviceSession.user_id == user_id)
        .order_by(DeviceSession.last_seen.desc())
        .all()
    )
    return {
        "devices": [
            {
                "session_id": s.session_id,
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
                "revoked": bool(s.revoked),
            }
            for s in sessions
        ]
    }


@router.post("/accounts/{user_id}/devices/revoke-all")
async def revoke_all_devices(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    from ..routes.messaging import messagingManager

    if user_id == 1:
        raise HTTPException(status_code=400, detail="Cannot revoke all admin sessions this way")
    sessions = (
        db.query(DeviceSession)
        .filter(DeviceSession.user_id == user_id, DeviceSession.revoked.is_(False))
        .all()
    )
    for s in sessions:
        s.revoked = True
    db.commit()
    await messagingManager.disconnect_user(user_id, code=4003, reason="Sessions revoked by admin")
    log_security(
        "admin_revoke_all_devices",
        "warning",
        actor=admin.username,
        actor_id=admin.id,
        target_user_id=user_id,
        count=len(sessions),
    )
    return {"status": "ok", "revoked": len(sessions)}


@router.get("/ip-bans")
def get_ip_bans(admin: User = Depends(require_admin)):
    try:
        return {"items": list_bans()}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/ip-bans")
def post_ip_ban(body: BanIpBody, admin: User = Depends(require_admin)):
    try:
        entry = ban_ip(body.ip, reason=body.reason, actor_id=admin.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    log_security(
        "admin_ip_ban",
        "warning",
        actor=admin.username,
        actor_id=admin.id,
        ip=body.ip,
        reason=body.reason,
    )
    return {"item": entry}


@router.delete("/ip-bans")
def delete_ip_ban(body: BanIpBody, admin: User = Depends(require_admin)):
    try:
        ok = unban_ip(body.ip)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    log_security(
        "admin_ip_unban",
        "info",
        actor=admin.username,
        actor_id=admin.id,
        ip=body.ip,
        removed=ok,
    )
    return {"removed": ok}


@router.get("/rate-limits")
def get_rate_limits(admin: User = Depends(require_admin)):
    return {"items": list_rate_limited()}


@router.get("/requests")
def get_requests(
    before: str | None = None,
    limit: int = Query(100, ge=1, le=500),
    admin: User = Depends(require_admin),
):
    return list_requests(before=before, limit=limit)


@router.websocket("/requests/ws")
async def requests_ws(websocket: WebSocket):
    token = websocket.query_params.get("token")
    if not token:
        auth = websocket.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    payload = verify_token(token or "")
    if not payload or payload.get("user_id") != 1:
        await websocket.close(code=4403)
        return
    await websocket.accept()
    path = access_log_path()
    offset = path.stat().st_size if path.exists() else 0
    try:
        while True:
            chunk, offset = follow_new_bytes(path, offset)
            if chunk.strip():
                from ..admin.access_log import _parse_entries

                items = [
                    {
                        "id": e.id,
                        "time": e.time,
                        "date": e.date,
                        "action": e.action,
                        "method": e.method,
                        "path": e.path,
                        "ip": e.ip,
                        "status": e.status,
                        "user": e.user,
                        "raw": e.raw,
                    }
                    for e in _parse_entries(chunk)
                ]
                await websocket.send_json({"type": "log", "chunk": chunk, "items": items})
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return
    except Exception:
        try:
            await websocket.close()
        except Exception:
            pass


@router.get("/ssh/status")
def get_ssh_status(admin: User = Depends(require_admin)):
    return ssh_status()


@router.websocket("/ssh")
async def ssh_ws(websocket: WebSocket):
    if not ssh_enabled():
        await websocket.close(code=4403)
        return
    token = websocket.query_params.get("token")
    if not token:
        auth = websocket.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth[7:].strip()
    payload = verify_token(token or "")
    if not payload or payload.get("user_id") != 1:
        await websocket.close(code=4403)
        return

    await websocket.accept()
    username = websocket.query_params.get("username") or ""
    password = websocket.query_params.get("password") or ""
    if not username:
        await websocket.send_json({"type": "error", "message": "username required"})
        await websocket.close()
        return

    try:
        import asyncssh
    except ImportError:
        await websocket.send_json({"type": "error", "message": "asyncssh not installed"})
        await websocket.close()
        return

    conn = None
    process = None
    try:
        conn = await asyncssh.connect(
            ssh_host(),
            port=ssh_port(),
            username=username,
            password=password or None,
            known_hosts=None,
        )
        term_cols = int(websocket.query_params.get("cols") or 80)
        term_rows = int(websocket.query_params.get("rows") or 24)
        process = await conn.create_process(
            term_type="xterm-256color",
            term_size=(term_cols, term_rows),
        )
        await websocket.send_json({"type": "ready"})

        async def pump_stdout() -> None:
            assert process is not None
            while True:
                data = await process.stdout.read(4096)
                if not data:
                    break
                if isinstance(data, bytes):
                    await websocket.send_bytes(data)
                else:
                    await websocket.send_text(data)

        stdout_task = asyncio.create_task(pump_stdout())
        try:
            while True:
                message = await websocket.receive()
                if message.get("type") == "websocket.disconnect":
                    break
                if "bytes" in message and message["bytes"] is not None:
                    process.stdin.write(message["bytes"])
                elif "text" in message and message["text"] is not None:
                    text = message["text"]
                    if text.startswith("{"):
                        import json

                        try:
                            payload_msg = json.loads(text)
                            if payload_msg.get("type") == "resize":
                                process.change_terminal_size(
                                    int(payload_msg.get("cols") or 80),
                                    int(payload_msg.get("rows") or 24),
                                )
                                continue
                        except Exception:
                            pass
                    process.stdin.write(text)
        finally:
            stdout_task.cancel()
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        try:
            if process:
                process.close()
                await process.wait_closed()
        except Exception:
            pass
        try:
            if conn:
                conn.close()
        except Exception:
            pass
        try:
            await websocket.close()
        except Exception:
            pass


@router.get("/compliance/users")
def compliance_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    q: str | None = None,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return users_with_dms(db, q=q, page=page, page_size=page_size)


@router.get("/compliance/users/{user_id}/conversations")
def compliance_conversations(
    user_id: int,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return {"items": conversations_for_user(db, user_id)}


@router.get("/compliance/conversations/{user_a}/{user_b}/messages")
def compliance_messages(
    user_a: int,
    user_b: int,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=200),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    return messages_for_pair(db, user_a, user_b, page=page, page_size=page_size)


@router.post("/compliance/bundle")
def compliance_bundle(
    body: BundleBody,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    try:
        data = build_compliance_zip(db, admin, body.message_ids)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    log_security(
        "admin_compliance_bundle",
        "warning",
        actor=admin.username,
        actor_id=admin.id,
        message_ids=body.message_ids,
        count=len(body.message_ids),
    )
    filename = f"compliance_bundle_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Admin router
__all__ = ["router"]
