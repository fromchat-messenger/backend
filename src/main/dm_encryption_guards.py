"""
DM send/edit encryption mode enforcement (server source of truth).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Mapping

from fastapi import HTTPException, status

from .instance_encryption import (
    InstanceEncryptionPolicy,
    read_instance_encryption_policy,
)

WRONG_ENCRYPTION_MODE = "wrong_encryption_mode"
ENCRYPTION_MODE_VERSION_STALE = "encryption_mode_version_stale"
INVALID_ENVELOPE_FOR_MODE = "invalid_envelope_for_mode"


class DmWritePath(str, Enum):
    COMPLIANCE_TRANSPORT = "compliance_transport"
    E2EE_ENVELOPE = "e2ee_envelope"


def encryption_mode_http_exception(code: str, message: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail={"code": code, "message": message},
    )


def _coerce_version(raw: Any) -> int | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    try:
        return int(raw)
    except (TypeError, ValueError):
        return None


def _declared_mode(body: Mapping[str, Any]) -> str | None:
    mode = body.get("encryption_mode")
    if mode is None:
        mode = body.get("encryptionMode")
    if mode is None:
        return None
    return str(mode).strip().lower()


def _declared_version(body: Mapping[str, Any]) -> int | None:
    version = body.get("encryption_mode_version")
    if version is None:
        version = body.get("encryptionModeVersion")
    return _coerce_version(version)


def require_client_encryption_mode_fields(body: Mapping[str, Any]) -> tuple[str, int]:
    mode = _declared_mode(body)
    version = _declared_version(body)
    if not mode:
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "encryption_mode is required",
        )
    if version is None:
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "encryption_mode_version is required",
        )
    return mode, version


def validate_dm_write_against_policy(
    body: Mapping[str, Any],
    *,
    path: DmWritePath,
    policy: InstanceEncryptionPolicy | None = None,
) -> InstanceEncryptionPolicy:
    """Validate path + client-declared mode/version against current instance policy."""
    if policy is None:
        policy = read_instance_encryption_policy()

    declared_mode, declared_version = require_client_encryption_mode_fields(body)

    if declared_version < policy.version:
        raise encryption_mode_http_exception(
            ENCRYPTION_MODE_VERSION_STALE,
            "encryption_mode_version is older than the server policy",
        )

    if path == DmWritePath.COMPLIANCE_TRANSPORT and policy.mode != "compliance":
        raise encryption_mode_http_exception(
            WRONG_ENCRYPTION_MODE,
            "Compliance transport send is not allowed while instance is in e2ee mode",
        )
    if path == DmWritePath.E2EE_ENVELOPE and policy.mode != "e2ee":
        raise encryption_mode_http_exception(
            WRONG_ENCRYPTION_MODE,
            "E2EE envelope send is not allowed while instance is in compliance mode",
        )

    if declared_mode != policy.mode:
        raise encryption_mode_http_exception(
            WRONG_ENCRYPTION_MODE,
            "Declared encryption_mode does not match the instance policy",
        )

    return policy


def validate_compliance_transport_body(body: Mapping[str, Any]) -> None:
    """Reject smuggled e2ee / pre-built envelope fields on compliance transport."""
    forbidden = (
        "sender_wrapped_mek_b64",
        "recipient_wrapped_mek_b64",
        "iv_b64",
        "ciphertext_b64",
        "compliance_wrapped_mek_b64",
    )
    for key in forbidden:
        if key in body and body.get(key):
            raise encryption_mode_http_exception(
                INVALID_ENVELOPE_FOR_MODE,
                f"Field {key} is not allowed on compliance transport send",
            )
    if body.get("wrapped_mek_b64"):
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "wrapped_mek_b64 is not allowed on compliance transport send",
        )


def validate_e2ee_envelope_fields(body: Mapping[str, Any]) -> None:
    """Validate client-built e2ee envelope shape."""
    transport_keys = (
        "transport_nonce_b64",
        "transport_ciphertext_b64",
        "client_public_key_b64",
        "transportNonceB64",
        "transportCiphertextB64",
        "clientPublicKeyB64",
    )
    for key in transport_keys:
        if key in body and body.get(key):
            raise encryption_mode_http_exception(
                INVALID_ENVELOPE_FOR_MODE,
                "Transport encryption fields are not allowed on e2ee envelope send",
            )

    compliance = body.get("compliance_wrapped_mek_b64") or body.get("complianceWrappedMekB64")
    if compliance:
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "compliance_wrapped_mek_b64 must be absent for e2ee messages",
        )

    sender_mek = (body.get("sender_wrapped_mek_b64") or body.get("senderWrappedMekB64") or "").strip()
    recipient_mek = (
        body.get("recipient_wrapped_mek_b64") or body.get("recipientWrappedMekB64") or ""
    ).strip()
    if not sender_mek or not recipient_mek:
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "sender_wrapped_mek_b64 and recipient_wrapped_mek_b64 are required",
        )
    if sender_mek == recipient_mek:
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "sender and recipient wrapped MEKs must differ",
        )


def require_edit_path_matches_message(
    message_encryption_mode: str,
    path: DmWritePath,
) -> None:
    stored = (message_encryption_mode or "compliance").strip().lower()
    if path == DmWritePath.COMPLIANCE_TRANSPORT and stored != "compliance":
        raise encryption_mode_http_exception(
            WRONG_ENCRYPTION_MODE,
            "Compliance transport edit is not allowed for e2ee messages",
        )
    if path == DmWritePath.E2EE_ENVELOPE and stored != "e2ee":
        raise encryption_mode_http_exception(
            WRONG_ENCRYPTION_MODE,
            "E2EE envelope edit is not allowed for compliance messages",
        )


def require_compliance_wrapped_mek_after_process(compliance_wrapped_mek: str | None) -> None:
    from src.shared.message_retention import get_message_retention

    if get_message_retention().never_store_compliance_mek():
        return
    if not (compliance_wrapped_mek or "").strip():
        raise encryption_mode_http_exception(
            INVALID_ENVELOPE_FOR_MODE,
            "Compliance wrapped MEK is required for compliance-mode messages",
        )
