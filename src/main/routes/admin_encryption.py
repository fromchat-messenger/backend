"""Admin endpoints for instance encryption mode."""

import logging
import os

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, field_validator
from sqlalchemy.orm import Session

from ..dependencies import get_current_user, get_db
from ..instance_encryption import (
    EncryptionMode,
    VALID_ENCRYPTION_MODES,
    build_instance_info_payload,
    read_instance_encryption_policy,
    set_instance_encryption_mode,
)
from ..models import User
from ..security.audit import log_security
from ..utils import get_client_ip
from .account import get_server_instance_id
from .messaging import messagingManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


class PatchEncryptionModeRequest(BaseModel):
    mode: EncryptionMode

    @field_validator("mode", mode="before")
    @classmethod
    def normalize_mode(cls, value: object) -> str:
        if value is None:
            raise ValueError("mode is required")
        normalized = str(value).strip().lower()
        if normalized not in VALID_ENCRYPTION_MODES:
            raise ValueError("mode must be e2ee or compliance")
        return normalized


def _compliance_mode_allowed() -> bool:
    from src.shared.message_retention import get_message_retention

    if get_message_retention().never_store_compliance_mek():
        return False
    compliance_key = (os.getenv("COMPLIANCE_PUBLIC_KEY") or "").strip()
    return bool(compliance_key)


@router.patch("/encryption-mode")
async def patch_encryption_mode(
    body: PatchEncryptionModeRequest,
    request: Request,
    broadcast: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if current_user.id != 1:
        raise HTTPException(status_code=403, detail="Only admin can change encryption mode")

    if body.mode == "compliance" and not _compliance_mode_allowed():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Switching to compliance requires COMPLIANCE_PUBLIC_KEY and "
                "MESSAGE_RETENTION_DAYS != -1"
            ),
        )

    previous = read_instance_encryption_policy()
    if previous.mode == body.mode:
        return build_instance_info_payload(get_server_instance_id())

    policy = set_instance_encryption_mode(body.mode)
    client_ip = get_client_ip(request)
    log_security(
        "admin_encryption_mode_changed",
        "warning",
        actor_id=current_user.id,
        actor_username=current_user.username,
        ip=client_ip,
        previous_mode=previous.mode,
        new_mode=policy.mode,
        version=policy.version,
    )

    ws_payload = {
        "encryption_mode": policy.mode,
        "changed_at": policy.changed_at,
        "version": policy.version,
    }
    if broadcast:
        try:
            await messagingManager.broadcast(
                {"type": "encryptionModeChanged", "data": ws_payload},
                db,
            )
        except Exception as exc:
            logger.error("Failed to broadcast encryptionModeChanged: %s", exc)

    return build_instance_info_payload(get_server_instance_id())
