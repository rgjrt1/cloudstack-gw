#!/usr/bin/env python3
"""
Smoke-test script for local development.

Sends requests to the running middleware (localhost:8080) with fake
oauth2-proxy headers so you can verify the full provisioning flow without
needing an actual IdP.

Usage:
    # 1. Start the middleware in one terminal:
    #    source .env.local && python -m src.main
    #
    # 2. In another terminal:
    #    python smoke_test.py

The script tests three scenarios:
  A. Single group (cloud-admins) — admin user flow
  B. Multiple groups — primary + project membership
  C. Re-login for same user — should hit cache, no reprovisioning
"""
import json
import sys
import time

import httpx

BASE = "http://127.0.0.1:8080"


def _headers(sub: str, email: str, groups: list[str], username: str = "") -> dict:
    return {
        "X-Forwarded-User": sub,
        "X-Forwarded-Email": email,
        "X-Forwarded-Groups": ",".join(groups),
        "X-Forwarded-Preferred-Username": username or sub,
    }


def check(label: str, resp: httpx.Response, expected_status: int = 200) -> None:
    icon = "✅" if resp.status_code == expected_status else "❌"
    print(f"{icon}  {label}  →  HTTP {resp.status_code}")
    if resp.status_code != expected_status:
        print(f"    Body: {resp.text[:300]}")
        sys.exit(1)


def main() -> None:
    client = httpx.Client(base_url=BASE, timeout=60)

    # ------------------------------------------------------------------ healthz
    print("\n── Health / readiness ──────────────────────────────────────────")
    check("GET /healthz", client.get("/healthz"))
    r = client.get("/readyz")
    check("GET /readyz", r, expected_status=r.status_code)
    if r.status_code != 200:
        print("  ⚠️  CloudStack not reachable — check CS_API_KEY / CS_SECRET_KEY")
        sys.exit(1)

    # ------------------------------------------------------------------ scenario A
    print("\n── Scenario A: single group (cloud-admins) ─────────────────────")
    r = client.get(
        "/client/api?command=listZones&response=json",
        headers=_headers("alice@example.com", "alice@example.com", ["cloud-admins"], "alice"),
    )
    check("First login — alice in cloud-admins (full provision)", r)

    # ------------------------------------------------------------------ scenario B
    print("\n── Scenario B: multiple groups (cloud-admins + developers) ──────")
    r = client.get(
        "/client/api?command=listZones&response=json",
        headers=_headers("bob@example.com", "bob@example.com", ["cloud-admins", "developers"], "bob"),
    )
    check("First login — bob in cloud-admins + developers (project membership)", r)

    # ------------------------------------------------------------------ scenario C: cache hit
    print("\n── Scenario C: re-login (should be cache hit) ──────────────────")
    t0 = time.monotonic()
    r = client.get(
        "/client/api?command=listZones&response=json",
        headers=_headers("alice@example.com", "alice@example.com", ["cloud-admins"], "alice"),
    )
    elapsed = time.monotonic() - t0
    check(f"Re-login — alice (cache hit, {elapsed:.2f}s)", r)

    # ------------------------------------------------------------------ scenario D: no groups
    print("\n── Scenario D: user with unknown group (default mapping) ────────")
    r = client.get(
        "/client/api?command=listZones&response=json",
        headers=_headers("carol@example.com", "carol@example.com", ["some-unknown-group"], "carol"),
    )
    check("Login — carol with unknown group → default role", r)

    # ------------------------------------------------------------------ scenario E: no headers → 401
    print("\n── Scenario E: missing OIDC headers → 401 ──────────────────────")
    r = client.get("/client/api?command=listZones&response=json")
    check("Request without OIDC headers → 401", r, expected_status=401)

    # ------------------------------------------------------------------ admin endpoints
    print("\n── Admin endpoints ──────────────────────────────────────────────")
    check("POST /admin/cache/clear", client.post("/admin/cache/clear"))
    check("POST /admin/reconcile",   client.post("/admin/reconcile"))

    print("\n🎉  All smoke tests passed!\n")


if __name__ == "__main__":
    main()
