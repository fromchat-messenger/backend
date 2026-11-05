#!/usr/bin/env python3
"""Seed local Docker instance: owner + 5 test users with scrollable DM history."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.request

BASE = os.environ.get("FROMCHAT_API_BASE", "http://127.0.0.1:8300").rstrip("/")

TEST_USERS = [
    ("testalpha", "Alpha Test"),
    ("testbeta", "Beta Test"),
    ("testgamma", "Gamma Test"),
    ("testdelta", "Delta Test"),
    ("testepsilon", "Epsilon Test"),
]

PARAGRAPH = (
    "Synthetic compliance-mode conversation line for scroll testing. "
    "The quick brown fox jumps over the lazy dog. "
    "Numbers 1234567890 and symbols !@#$%^&*() should survive encryption. "
)


def hkdf_derive(username: str, password: str) -> str:
    import base64

    salt = f"fromchat.user:{username}".encode()
    info = b"auth-secret"
    password_bytes = password.encode()
    prk = hmac.new(salt, password_bytes, hashlib.sha256).digest()
    t = b""
    okm = b""
    for i in range(1, 5):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
    return base64.b64encode(okm[:32]).decode()


def http_json(method: str, path: str, body: dict | None = None, token: str | None = None):
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode()
        return json.loads(raw) if raw else {}


def register_user(username: str, display_name: str, password: str) -> str:
    derived = hkdf_derive(username, password)
    payload = {
        "username": username,
        "password": derived,
        "confirm_password": derived,
        "display_name": display_name,
    }
    out = http_json("POST", "/auth/steps/register/confirm", payload)
    token = out.get("token")
    if not token:
        raise RuntimeError(f"register failed for {username}: {out}")
    return token


def login_user(username: str, password: str) -> str:
    derived = hkdf_derive(username, password)
    out = http_json("POST", "/auth/steps/login/confirm", {"username": username, "password": derived})
    token = out.get("token")
    if not token:
        raise RuntimeError(f"login failed for {username}: {out}")
    return token


def send_compliance_dm(token: str, recipient_id: int, text: str, mode: str, version: int):
    # Minimal client: relies on server transport path via API fields populated by test helper endpoint
    # For seeding we use internal verbose loop calling /dm/send through httpx would need full crypto;
    # instead post plaintext via compliance test hook is unavailable — use send-envelope in compliance
    # mode requires transport. Call messaging through documented API using prebuilt transport from
    # scripts/test_encryption_modes_http patterns.
    raise NotImplementedError("Use compliance send helper after transport encryption")


def main() -> int:
    owner_password = os.environ.get("OWNER_PASSWORD", "OwnerPass1!")
    test_password = os.environ.get("TEST_PASSWORD", "TestPass1!")
    print(f"API base: {BASE}", flush=True)
    info = http_json("GET", "/instance/info")
    print("instance/info:", json.dumps(info), flush=True)
    try:
        owner_token = register_user("owner", "Owner", owner_password)
    except Exception as exc:
        print("owner register failed, trying login:", exc, flush=True)
        owner_token = login_user("owner", owner_password)
    owner = http_json("GET", "/check_auth", token=owner_token)
    print("owner:", owner, flush=True)
    tokens: dict[str, str] = {"owner": owner_token}
    ids: dict[str, int] = {"owner": int(owner.get("user_id") or owner.get("id") or 1)}
    for username, display in TEST_USERS:
        try:
            tokens[username] = register_user(username, display, test_password)
        except Exception:
            tokens[username] = login_user(username, test_password)
        prof = http_json("GET", "/check_auth", token=tokens[username])
        uid = prof.get("user_id") or prof.get("id")
        if uid is None:
            raise RuntimeError(f"no user id for {username}")
        ids[username] = int(uid)
        print(f"registered {username} id={ids[username]}", flush=True)
    print("Seed accounts ready. DM history seeding requires compliance transport crypto — run app manual send or extend script.", flush=True)
    print(json.dumps({"owner_id": ids.get("owner"), "test_ids": ids, "passwords": {"owner": owner_password, "test": test_password}}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
