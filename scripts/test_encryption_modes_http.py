#!/usr/bin/env python3
"""Quick HTTP smoke tests for encryption modes against a running local API."""
from __future__ import annotations

import json
import sys
import time

import httpx

BASE = "http://localhost:8300"
USERNAME = "encuser1"
PASSWORD = "11111"


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=30.0)
    failures: list[str] = []

    def check(name: str, ok: bool, detail: str = "") -> None:
        if ok:
            print(f"OK  {name}")
        else:
            msg = f"FAIL {name}" + (f": {detail}" if detail else "")
            print(msg)
            failures.append(msg)

    info = client.get("/instance/info").json()
    check("GET /instance/info", "encryption_mode" in info and "instance_id" in info, json.dumps(info))

    version = int(info.get("encryption_mode_version") or 1)
    mode = info.get("encryption_mode")

    r = client.post(
        "/auth/steps/password",
        json={"username": USERNAME, "password": PASSWORD},
    )
    if r.status_code != 200:
        check("login", False, f"{r.status_code} {r.text[:200]}")
        return 1
    token = r.json().get("token")
    check("login", bool(token))
    headers = {"Authorization": f"Bearer {token}"}

    # Missing encryption fields on compliance send → 409
    r = client.post(
        "/dm/send",
        headers=headers,
        json={
            "recipient_id": 2,
            "client_public_key_b64": "YQ==",
            "transport_nonce_b64": "YQ==",
            "transport_ciphertext_b64": "YQ==",
            "sender_public_key_b64": "YQ==",
            "recipient_public_key_b64": "YQ==",
        },
    )
    check(
        "POST /dm/send without mode fields → 4xx",
        r.status_code in (409, 422),
        str(r.status_code) + " " + r.text[:120],
    )
    time.sleep(1.2)

    wrong_mode_body = {
        "recipient_id": 2,
        "client_public_key_b64": "YQ==",
        "transport_nonce_b64": "YQ==",
        "transport_ciphertext_b64": "YQ==",
        "sender_public_key_b64": "YQ==",
        "recipient_public_key_b64": "YQ==",
        "encryption_mode": "e2ee",
        "encryption_mode_version": version,
    }
    if mode == "compliance":
        r = client.post("/dm/send", headers=headers, json=wrong_mode_body)
        check(
            "compliance instance + e2ee mode field → 409",
            r.status_code == 409,
            str(r.status_code),
        )
        time.sleep(1.2)

    stale = {
        "recipient_id": 2,
        "iv_b64": "YQ==",
        "ciphertext_b64": "YQ==",
        "sender_wrapped_mek_b64": "YQ==",
        "recipient_wrapped_mek_b64": "YQ==",
        "encryption_mode": "e2ee",
        "encryption_mode_version": max(0, version - 1),
    }
    r = client.post("/dm/send-envelope", headers=headers, json=stale)
    check(
        "stale encryption_mode_version on send-envelope → 409",
        r.status_code == 409,
        str(r.status_code),
    )
    time.sleep(1.2)

    if mode == "compliance":
        r = client.post(
            "/dm/send-envelope",
            headers=headers,
            json={
                "recipient_id": 2,
                "iv_b64": "YQ==",
                "ciphertext_b64": "YQ==",
                "sender_wrapped_mek_b64": "YQ==",
                "recipient_wrapped_mek_b64": "YQ==",
                "encryption_mode": "e2ee",
                "encryption_mode_version": version,
            },
        )
        check("send-envelope while compliance instance → 409", r.status_code == 409, str(r.status_code))
        time.sleep(1.2)

    # Admin switch to e2ee (user id 1)
    admin = client.post("/auth/steps/password", json={"username": "test", "password": PASSWORD})
    # Try user 1 - might be different username; skip if not admin
    r = client.patch(
        "/admin/encryption-mode",
        headers=headers,
        json={"mode": "e2ee"},
    )
    if r.status_code == 403:
        check("admin PATCH encryption-mode (skipped non-admin)", True)
    elif r.status_code == 200:
        check("admin PATCH → e2ee", True)
        time.sleep(0.5)
        info2 = client.get("/instance/info").json()
        check("instance/info after patch", info2.get("encryption_mode") == "e2ee")
        time.sleep(1.2)
        r = client.post(
            "/dm/send",
            headers=headers,
            json={
                **wrong_mode_body,
                "encryption_mode": "compliance",
                "encryption_mode_version": int(info2.get("encryption_mode_version") or version),
            },
        )
        check("POST /dm/send on e2ee instance → 409", r.status_code == 409, str(r.status_code))
    else:
        check("admin PATCH encryption-mode", False, f"{r.status_code} {r.text[:120]}")

    print()
    if failures:
        print(f"{len(failures)} failure(s)")
        return 1
    print("All HTTP smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
