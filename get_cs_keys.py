#!/usr/bin/env python3
"""
Retrieve the root admin API key + secret from a CloudStack management server
using the username/password login flow (no existing API keys needed).

Usage:
    python get_cs_keys.py [--url http://192.168.0.144:8080] [--user admin] [--password admin]

Prints export statements you can paste into .env.local.
"""
import argparse
import hashlib
import getpass
import sys
import urllib.parse

import httpx


def login(base_url: str, username: str, password: str, domain: str = "/") -> str:
    """Log in and return the JSESSIONID cookie value."""
    url = f"{base_url}/client/api"
    md5_pass = hashlib.md5(password.encode()).hexdigest()
    params = {
        "command": "login",
        "username": username,
        "password": md5_pass,
        "domain": domain,
        "response": "json",
    }
    r = httpx.post(url, data=params, follow_redirects=True)
    # CloudStack uses non-standard HTTP status codes (e.g. 531) — parse JSON directly
    try:
        body = r.json()
    except Exception:
        print(f"Unexpected response (HTTP {r.status_code}):\n{r.text[:500]}", file=sys.stderr)
        sys.exit(1)
    data = body.get("loginresponse", {})
    if "errorcode" in data:
        print(f"Login failed (errorcode {data['errorcode']}): {data.get('errortext')}", file=sys.stderr)
        sys.exit(1)
    session = r.cookies.get("JSESSIONID") or data.get("sessionkey", "")
    return session, data.get("userid", "")


def get_user_keys(base_url: str, session_cookie: str, user_id: str) -> tuple[str, str]:
    """Retrieve API key + secret for the given user ID."""
    url = f"{base_url}/client/api"
    params = {
        "command": "getUserKeys",
        "id": user_id,
        "response": "json",
        "sessionkey": session_cookie,
    }
    r = httpx.get(url, params=params, cookies={"JSESSIONID": session_cookie})
    r.raise_for_status()
    inner = r.json().get("getuserkeysresponse", {})
    if "errorcode" in inner:
        # Keys may not exist yet — register them
        return register_keys(base_url, session_cookie, user_id)
    keys = inner.get("userkeys", inner)
    return keys.get("apikey", ""), keys.get("secretkey", "")


def register_keys(base_url: str, session_cookie: str, user_id: str) -> tuple[str, str]:
    url = f"{base_url}/client/api"
    params = {
        "command": "registerUserKeys",
        "id": user_id,
        "response": "json",
        "sessionkey": session_cookie,
    }
    r = httpx.get(url, params=params, cookies={"JSESSIONID": session_cookie})
    r.raise_for_status()
    inner = r.json().get("registeruserkeysresponse", {})
    keys = inner.get("userkeys", inner)
    return keys.get("apikey", ""), keys.get("secretkey", "")


def main() -> None:
    parser = argparse.ArgumentParser(description="Fetch CloudStack admin API keys")
    parser.add_argument("--url",      default="http://192.168.0.144:8080", help="CloudStack base URL")
    parser.add_argument("--user",     default="admin",                     help="Admin username")
    parser.add_argument("--password", default=None,                         help="Admin password (prompted if omitted)")
    parser.add_argument("--domain",   default="/",                          help="Domain (default: /)")
    args = parser.parse_args()

    password = args.password or getpass.getpass(f"Password for {args.user}@{args.url}: ")

    print(f"Logging in to {args.url} as '{args.user}'...", file=sys.stderr)
    session, user_id = login(args.url, args.user, password, args.domain)

    if not user_id:
        print("Could not determine user ID from login response.", file=sys.stderr)
        sys.exit(1)

    print(f"Fetching API keys for user ID {user_id}...", file=sys.stderr)
    api_key, secret_key = get_user_keys(args.url, session, user_id)

    if not api_key:
        print("No API keys returned. Check that the admin account has keys registered.", file=sys.stderr)
        sys.exit(1)

    # Print export statements ready to paste into .env.local
    print(f'\nexport CS_API_KEY="{api_key}"')
    print(f'export CS_SECRET_KEY="{secret_key}"')
    print(f'export CONFIG_PATH="config.yaml"\n')
    print("# Paste the above into .env.local, then:", file=sys.stderr)
    print("# source .env.local && python -m src.main", file=sys.stderr)


if __name__ == "__main__":
    main()
