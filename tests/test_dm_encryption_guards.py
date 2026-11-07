import pytest
from fastapi import HTTPException

from src.main.dm_encryption_guards import (
    ENCRYPTION_MODE_VERSION_STALE,
    INVALID_ENVELOPE_FOR_MODE,
    WRONG_ENCRYPTION_MODE,
    DmWritePath,
    require_edit_path_matches_message,
    validate_compliance_transport_body,
    validate_dm_write_against_policy,
    validate_e2ee_envelope_fields,
)
from src.main.instance_encryption import InstanceEncryptionPolicy


def _policy(mode: str = "compliance", version: int = 3) -> InstanceEncryptionPolicy:
    return InstanceEncryptionPolicy(
        mode=mode,
        changed_at="2026-01-01T00:00:00+00:00",
        version=version,
    )


def _compliance_body(version: int = 3) -> dict:
    return {"encryption_mode": "compliance", "encryption_mode_version": version}


def _e2ee_body(version: int = 3) -> dict:
    return {
        "encryption_mode": "e2ee",
        "encryption_mode_version": version,
        "sender_wrapped_mek_b64": "sender-mek",
        "recipient_wrapped_mek_b64": "recipient-mek",
        "iv_b64": "iv",
        "ciphertext_b64": "ct",
    }


def _exc_code(exc: HTTPException) -> str:
    assert isinstance(exc.detail, dict)
    return exc.detail["code"]


def test_wrong_endpoint_for_e2ee_instance():
    with pytest.raises(HTTPException) as exc:
        validate_dm_write_against_policy(
            _compliance_body(),
            path=DmWritePath.COMPLIANCE_TRANSPORT,
            policy=_policy("e2ee"),
        )
    assert exc.value.status_code == 409
    assert _exc_code(exc.value) == WRONG_ENCRYPTION_MODE


def test_wrong_endpoint_for_compliance_instance():
    with pytest.raises(HTTPException) as exc:
        validate_dm_write_against_policy(
            _e2ee_body(),
            path=DmWritePath.E2EE_ENVELOPE,
            policy=_policy("compliance"),
        )
    assert _exc_code(exc.value) == WRONG_ENCRYPTION_MODE


def test_declared_mode_mismatch_on_correct_url():
    body = _compliance_body()
    body["encryption_mode"] = "e2ee"
    with pytest.raises(HTTPException) as exc:
        validate_dm_write_against_policy(
            body,
            path=DmWritePath.COMPLIANCE_TRANSPORT,
            policy=_policy("compliance"),
        )
    assert _exc_code(exc.value) == WRONG_ENCRYPTION_MODE


def test_stale_encryption_mode_version():
    with pytest.raises(HTTPException) as exc:
        validate_dm_write_against_policy(
            _compliance_body(version=1),
            path=DmWritePath.COMPLIANCE_TRANSPORT,
            policy=_policy("compliance", version=3),
        )
    assert _exc_code(exc.value) == ENCRYPTION_MODE_VERSION_STALE


def test_e2ee_rejects_compliance_mek():
    body = _e2ee_body()
    body["compliance_wrapped_mek_b64"] = "bad"
    with pytest.raises(HTTPException) as exc:
        validate_e2ee_envelope_fields(body)
    assert _exc_code(exc.value) == INVALID_ENVELOPE_FOR_MODE


def test_e2ee_rejects_identical_meks():
    body = _e2ee_body()
    body["recipient_wrapped_mek_b64"] = body["sender_wrapped_mek_b64"]
    with pytest.raises(HTTPException) as exc:
        validate_e2ee_envelope_fields(body)
    assert _exc_code(exc.value) == INVALID_ENVELOPE_FOR_MODE


def test_compliance_rejects_smuggled_wrapped_mek():
    with pytest.raises(HTTPException) as exc:
        validate_compliance_transport_body({"sender_wrapped_mek_b64": "x"})
    assert _exc_code(exc.value) == INVALID_ENVELOPE_FOR_MODE


def test_edit_cross_mode_rejected():
    with pytest.raises(HTTPException) as exc:
        require_edit_path_matches_message("e2ee", DmWritePath.COMPLIANCE_TRANSPORT)
    assert _exc_code(exc.value) == WRONG_ENCRYPTION_MODE

    with pytest.raises(HTTPException) as exc:
        require_edit_path_matches_message("compliance", DmWritePath.E2EE_ENVELOPE)
    assert _exc_code(exc.value) == WRONG_ENCRYPTION_MODE
