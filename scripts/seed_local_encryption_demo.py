#!/usr/bin/env python3
"""Seed local Docker instance: owner + 5 users with compliance DM history."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request

try:
    import nacl.bindings as sodium
except ImportError as exc:
    raise SystemExit("PyNaCl required: pip install pynacl") from exc

BASE = os.environ.get("FROMCHAT_API_BASE", "http://127.0.0.1:8300").rstrip("/")

TEST_USERS = [
    ("encuser1", "Enc User One"),
]

MESSAGES_PER_PAIR = int(os.environ.get("SEED_MESSAGES_PER_PAIR", "12"))


def hkdf_derive(username: str, password: str) -> str:
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


def http_json(
    method: str,
    path: str,
    body: dict | None = None,
    token: str | None = None,
) -> dict:
    data = None
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if body is not None:
        data = json.dumps(body).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"{method} {path} → {exc.code}: {detail[:400]}") from exc


def login_user(username: str, password: str) -> tuple[str, int]:
    derived = hkdf_derive(username, password)
    out = http_json("POST", "/auth/steps/password", {"username": username, "password": derived})
    token = out.get("token")
    if not token:
        raise RuntimeError(f"login failed for {username}: {out}")
    user = out.get("user") or {}
    uid = user.get("id")
    if uid is None:
        raise RuntimeError(f"login missing user id for {username}")
    return token, int(uid)


def register_user(username: str, display_name: str, password: str) -> tuple[str, int]:
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
    user = out.get("user") or {}
    uid = user.get("id")
    if uid is None:
        raise RuntimeError(f"register missing user id for {username}")
    return token, int(uid)


def ensure_user(username: str, display_name: str, password: str) -> tuple[str, int]:
    try:
        return login_user(username, password)
    except RuntimeError as exc:
        if "→ 429:" in str(exc) or "→ 403:" in str(exc):
            raise
        time.sleep(2.0)
        return register_user(username, display_name, password)


def ensure_identity_key(token: str) -> str:
    existing = http_json("GET", "/crypto/public-key", token=token)
    pk = existing.get("publicKey")
    if pk:
        return pk
    sk, pk_bytes = sodium.crypto_box_keypair()
    pk_b64 = base64.b64encode(pk_bytes).decode()
    http_json("POST", "/crypto/public-key", {"publicKey": pk_b64}, token=token)
    _ = sk  # ephemeral; server only needs public half for envelope wrapping
    return pk_b64


def fetch_transport_public_key() -> str:
    out = http_json("GET", "/dm/key/transport/public")
    key = out.get("public_key_b64") or out.get("publicKey")
    if not key:
        raise RuntimeError(f"no transport key in {out}")
    return key


def encrypt_transport(plaintext: str, transport_public_b64: str) -> tuple[str, str, str]:
    transport_pk = base64.b64decode(transport_public_b64)
    client_sk, client_pk = sodium.crypto_box_keypair()
    nonce = secrets.token_bytes(24)
    ciphertext = sodium.crypto_box_easy(plaintext.encode(), nonce, transport_pk, client_sk)
    return (
        base64.b64encode(client_pk).decode(),
        base64.b64encode(nonce).decode(),
        base64.b64encode(ciphertext).decode(),
    )


def send_compliance_dm(
    token: str,
    recipient_id: int,
    recipient_pk_b64: str,
    sender_pk_b64: str,
    text: str,
    mode: str,
    version: int,
    transport_public_b64: str,
) -> int:
    client_pub, nonce_b64, cipher_b64 = encrypt_transport(text, transport_public_b64)
    body = {
        "recipient_id": recipient_id,
        "client_public_key_b64": client_pub,
        "transport_nonce_b64": nonce_b64,
        "transport_ciphertext_b64": cipher_b64,
        "sender_public_key_b64": sender_pk_b64,
        "recipient_public_key_b64": recipient_pk_b64,
        "encryption_mode": mode,
        "encryption_mode_version": version,
    }
    out = http_json("POST", "/dm/send", body, token=token)
    mid = out.get("id")
    if mid is None:
        raise RuntimeError(f"send failed: {out}")
    return int(mid)


def public_key_of(user_id: int, token: str) -> str:
    out = http_json("GET", f"/crypto/public-key/of/{user_id}", token=token)
    pk = out.get("publicKey")
    if not pk:
        raise RuntimeError(f"user {user_id} has no public key")
    return pk


def main() -> int:
    owner_password = os.environ.get("OWNER_PASSWORD", "OwnerPass1!")
    test_password = os.environ.get("TEST_PASSWORD", "EncPass1!")
    print(f"API base: {BASE}", flush=True)
    info = http_json("GET", "/instance/info")
    print("instance/info:", json.dumps(info), flush=True)
    mode = info.get("encryption_mode", "compliance")
    version = int(info.get("encryption_mode_version") or 1)

    owner_token, owner_id = ensure_user("owner", "Owner", owner_password)
    time.sleep(1.0)
    owner = http_json("GET", "/check_auth", token=owner_token)
    print("owner:", owner, flush=True)

    tokens: dict[str, str] = {"owner": owner_token}
    ids: dict[str, int] = {"owner": owner_id}
    sender_pks: dict[str, str] = {"owner": ensure_identity_key(owner_token)}

    for username, display in TEST_USERS:
        token, uid = ensure_user(username, display, test_password)
        tokens[username] = token
        ids[username] = uid
        sender_pks[username] = ensure_identity_key(token)
        print(f"ready {username} id={uid}", flush=True)
        time.sleep(1.2)

    transport_pk = fetch_transport_public_key()
    message_ids: list[int] = []
    paragraph = (
        "Synthetic compliance-mode line for scroll testing. "
        "The quick brown fox jumps over the lazy dog. "
    )

    pairs = [("owner", "encuser1")]
    for a, b in pairs:
        a_id, b_id = ids[a], ids[b]
        a_tok, b_tok = tokens[a], tokens[b]
        a_pk = sender_pks[a]
        b_pk = sender_pks[b]
        for n in range(MESSAGES_PER_PAIR):
            text_a = f"{paragraph} [{a}→{b} #{n + 1}]"
            text_b = f"{paragraph} [{b}→{a} #{n + 1}]"
            mid = send_compliance_dm(
                a_tok,
                b_id,
                public_key_of(b_id, a_tok),
                a_pk,
                text_a,
                mode,
                version,
                transport_pk,
            )
            message_ids.append(mid)
            mid2 = send_compliance_dm(
                b_tok,
                a_id,
                public_key_of(a_id, b_tok),
                b_pk,
                text_b,
                mode,
                version,
                transport_pk,
            )
            message_ids.append(mid2)
            if n % 3 == 0:
                transport_pk = fetch_transport_public_key()
            time.sleep(0.05)

    summary = {
        "owner_id": owner_id,
        "test_ids": ids,
        "passwords": {"owner": owner_password, "test": test_password},
        "sample_message_ids": message_ids[:5],
        "last_message_id": message_ids[-1] if message_ids else None,
        "message_count": len(message_ids),
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
