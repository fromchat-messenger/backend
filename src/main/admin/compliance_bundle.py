from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from typing import Any

import httpx
from sqlalchemy import or_, and_
from sqlalchemy.orm import Session

from ..constants import FILE_STORAGE_SERVICE_URL
from ..models import CryptoPublicKey, DMEditHistory, DMEnvelope, DMFile, User


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:120] or "file"


def _fetch_file_bytes(path: str) -> bytes | None:
    if not path:
        return None
    base = (FILE_STORAGE_SERVICE_URL or "").rstrip("/")
    if not base:
        return None
    url = path if path.startswith("http") else f"{base}{path if path.startswith('/') else '/' + path}"
    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                return resp.content
    except Exception:
        return None
    return None


def _extract_message_payload(db: Session, message_id: int, actor: User) -> dict[str, Any] | None:
    envelope = db.query(DMEnvelope).filter(DMEnvelope.id == message_id).first()
    if not envelope:
        return None

    files = []
    for f in envelope.files or []:
        files.append(
            {
                "id": f.id,
                "name": f.name,
                "path": f.path,
                "wrapped_mek_b64": envelope.compliance_wrapped_mek_b64,
                "nonce_b64": getattr(f, "nonce_b64", None),
            }
        )

    edit_history = (
        db.query(DMEditHistory)
        .filter(DMEditHistory.message_id == message_id)
        .order_by(DMEditHistory.edited_at)
        .all()
    )
    edit_history_data = []
    for edit_entry in edit_history:
        edited_by_user = db.query(User).filter(User.id == edit_entry.edited_by).first()
        edit_history_data.append(
            {
                "edit_id": edit_entry.id,
                "edited_at": edit_entry.edited_at.isoformat() if edit_entry.edited_at else None,
                "edited_by_user_id": edit_entry.edited_by,
                "edited_by_username": edited_by_user.username if edited_by_user else "unknown",
                "previous_ciphertext_b64": edit_entry.previous_ciphertext_b64,
                "previous_iv_b64": edit_entry.previous_iv_b64,
                "previous_compliance_wrapped_mek_b64": edit_entry.previous_compliance_wrapped_mek_b64,
            }
        )

    data = {
        "message_id": envelope.id,
        "sender_id": envelope.sender_id,
        "recipient_id": envelope.recipient_id,
        "timestamp": envelope.timestamp.isoformat() if envelope.timestamp else None,
        "iv_b64": envelope.iv_b64,
        "ciphertext_b64": envelope.ciphertext_b64,
        "compliance_wrapped_mek_b64": envelope.compliance_wrapped_mek_b64,
        "files": files,
        "edit_history": edit_history_data,
        "total_edits": len(edit_history_data),
        "extraction_timestamp": datetime.now().isoformat(),
        "extracted_by_user_id": actor.id,
        "compliance_system_ready": envelope.compliance_wrapped_mek_b64 is not None,
    }
    return {"status": "success", "data": data}


def build_compliance_zip(db: Session, actor: User, message_ids: list[int]) -> bytes:
    seen: set[int] = set()
    unique_ids: list[int] = []
    for mid in message_ids:
        if mid not in seen:
            seen.add(mid)
            unique_ids.append(mid)
    if not unique_ids:
        raise ValueError("No message IDs provided")

    buf = io.BytesIO()
    manifest: dict[str, Any] = {
        "bundle_version": 1,
        "generated_at": datetime.now().isoformat(),
        "messages": [],
    }

    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for mid in unique_ids:
            payload = _extract_message_payload(db, mid, actor)
            if not payload:
                continue
            data = payload["data"]
            prefix = f"messages/{mid}"
            zf.writestr(f"{prefix}/response.json", json.dumps(payload, ensure_ascii=False, indent=2))
            zf.writestr(f"{prefix}/message.json", json.dumps(data, ensure_ascii=False, indent=2))

            sender = db.query(User).filter(User.id == data["sender_id"]).first()
            recipient = db.query(User).filter(User.id == data["recipient_id"]).first()
            sender_pk = (
                db.query(CryptoPublicKey)
                .filter(CryptoPublicKey.user_id == data["sender_id"])
                .first()
            )

            file_entries = []
            for fmeta in data.get("files") or []:
                path = fmeta.get("path")
                name = fmeta.get("name") or "file"
                file_id = fmeta.get("id")
                safe = _safe_name(str(name))
                enc_name = f"{mid}_{file_id or 'x'}_{safe}.enc"
                enc_rel = f"{prefix}/files/{enc_name}"
                content = _fetch_file_bytes(str(path)) if path else None
                if content is not None:
                    zf.writestr(enc_rel, content)
                meta_out = {
                    "kind": "dm_file",
                    "message_id": mid,
                    "dm_file_id": file_id,
                    "filename": name,
                    "path": path,
                    "nonce_b64": fmeta.get("nonce_b64"),
                    "encrypted_file_local": enc_rel,
                    "compliance_wrapped_mek_b64": fmeta.get("wrapped_mek_b64"),
                }
                meta_name = f"{mid}_{file_id or 'x'}_{safe}.meta.json"
                meta_rel = f"{prefix}/files/{meta_name}"
                zf.writestr(meta_rel, json.dumps(meta_out, ensure_ascii=False, indent=2))
                file_entries.append(
                    {
                        "dm_file_id": file_id,
                        "filename": name,
                        "encrypted_file": enc_rel,
                        "meta_file": meta_rel,
                        "size_bytes": len(content) if content else 0,
                    }
                )

            edit_entries = []
            for edit in data.get("edit_history") or []:
                edit_id = edit.get("edit_id")
                edit_rel = f"{prefix}/edits/edit_{edit_id}.json"
                zf.writestr(edit_rel, json.dumps(edit, ensure_ascii=False, indent=2))
                edit_entries.append(
                    {
                        "edit_id": edit_id,
                        "edit_data_file": edit_rel,
                        "edited_at": edit.get("edited_at"),
                        "edited_by_user_id": edit.get("edited_by_user_id"),
                        "edited_by_username": edit.get("edited_by_username"),
                    }
                )

            manifest["messages"].append(
                {
                    "message_id": mid,
                    "message_data_file": f"{prefix}/message.json",
                    "response_file": f"{prefix}/response.json",
                    "sender_id": data["sender_id"],
                    "sender_username": sender.username if sender else None,
                    "sender_display_name": sender.display_name if sender else None,
                    "recipient_id": data["recipient_id"],
                    "recipient_username": recipient.username if recipient else None,
                    "recipient_display_name": recipient.display_name if recipient else None,
                    "sender_public_key_b64": getattr(sender_pk, "public_key_b64", None) if sender_pk else None,
                    "timestamp": data.get("timestamp"),
                    "files": file_entries,
                    "edit_history": edit_entries,
                }
            )

        zf.writestr("bundle.json", json.dumps(manifest, ensure_ascii=False, indent=2))

    return buf.getvalue()


def users_with_dms(db: Session, *, q: str | None = None, page: int = 1, page_size: int = 50) -> dict[str, Any]:
    page = max(1, page)
    page_size = max(1, min(page_size, 100))
    sender_ids = {r[0] for r in db.query(DMEnvelope.sender_id).distinct().all()}
    recipient_ids = {r[0] for r in db.query(DMEnvelope.recipient_id).distinct().all()}
    user_ids = sorted(sender_ids | recipient_ids)
    query = db.query(User).filter(User.id.in_(user_ids) if user_ids else False)
    if q:
        like = f"%{q}%"
        query = query.filter(or_(User.username.ilike(like), User.display_name.ilike(like)))
    total = query.count() if user_ids else 0
    rows = (
        query.order_by(User.id.asc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
        if user_ids
        else []
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "items": [
            {
                "id": u.id,
                "username": u.username,
                "display_name": u.display_name,
            }
            for u in rows
        ],
    }


def conversations_for_user(db: Session, user_id: int) -> list[dict[str, Any]]:
    rows = (
        db.query(DMEnvelope)
        .filter(
            or_(DMEnvelope.sender_id == user_id, DMEnvelope.recipient_id == user_id),
            DMEnvelope.deleted_at.is_(None),
        )
        .all()
    )
    counts: dict[int, int] = {}
    for msg in rows:
        peer = msg.recipient_id if msg.sender_id == user_id else msg.sender_id
        counts[peer] = counts.get(peer, 0) + 1
    peers = db.query(User).filter(User.id.in_(list(counts.keys()))).all() if counts else []
    by_id = {u.id: u for u in peers}
    out = []
    for peer_id, count in sorted(counts.items(), key=lambda x: -x[1]):
        u = by_id.get(peer_id)
        out.append(
            {
                "peer_id": peer_id,
                "username": u.username if u else f"user_{peer_id}",
                "display_name": u.display_name if u else None,
                "message_count": count,
            }
        )
    return out


def messages_for_pair(
    db: Session,
    user_a: int,
    user_b: int,
    *,
    page: int = 1,
    page_size: int = 100,
) -> dict[str, Any]:
    page = max(1, page)
    page_size = max(1, min(page_size, 200))
    filt = and_(
        DMEnvelope.deleted_at.is_(None),
        or_(
            and_(DMEnvelope.sender_id == user_a, DMEnvelope.recipient_id == user_b),
            and_(DMEnvelope.sender_id == user_b, DMEnvelope.recipient_id == user_a),
        ),
    )
    total = db.query(DMEnvelope).filter(filt).count()
    rows = (
        db.query(DMEnvelope)
        .filter(filt)
        .order_by(DMEnvelope.timestamp.desc())
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
                "id": m.id,
                "sender_id": m.sender_id,
                "recipient_id": m.recipient_id,
                "timestamp": m.timestamp.isoformat() if m.timestamp else None,
            }
            for m in rows
        ],
    }
