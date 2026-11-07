import json
import os
from pathlib import Path

import pytest

from src.main.instance_encryption import (
    build_instance_info_payload,
    ensure_instance_encryption_file,
    read_instance_encryption_policy,
    reset_instance_encryption_for_tests,
    set_instance_encryption_mode,
)
@pytest.fixture(autouse=True)
def isolated_policy_file(monkeypatch, tmp_path):
    policy_dir = tmp_path / "data"
    policy_dir.mkdir()
    policy_path = policy_dir / "instance_encryption.json"
    monkeypatch.setattr("src.main.instance_encryption.DATA_DIR", policy_dir)
    monkeypatch.setattr("src.main.instance_encryption._INSTANCE_ENCRYPTION_FILE", policy_path)
    monkeypatch.setenv("ENCRYPTION_MODE", "compliance")
    reset_instance_encryption_for_tests(policy_path)
    yield policy_path
    reset_instance_encryption_for_tests(policy_path)


def test_ensure_creates_policy_from_env():
    policy = ensure_instance_encryption_file()
    assert policy.mode == "compliance"
    assert policy.version == 1
    assert policy.changed_at


def test_read_reload_after_write():
    ensure_instance_encryption_file()
    updated = set_instance_encryption_mode("e2ee")
    assert updated.mode == "e2ee"
    assert updated.version == 2
    reloaded = read_instance_encryption_policy()
    assert reloaded.mode == "e2ee"
    assert reloaded.version == 2


def test_build_instance_info_payload():
    ensure_instance_encryption_file()
    payload = build_instance_info_payload("test-instance-id")
    assert payload["instance_id"] == "test-instance-id"
    assert payload["encryption_mode"] == "compliance"
    assert payload["encryption_mode_version"] == 1
    assert payload["encryption_mode_changed_at"]
    assert set(payload.keys()) == {
        "instance_id",
        "encryption_mode",
        "encryption_mode_changed_at",
        "encryption_mode_version",
    }
