#!/usr/bin/env python3
"""rcx.py — Reconix Operator CLI and REST/MCP Bridge Helper.

Zero external dependencies (uses standard library only).
Provides token caching, health verification, action hashing, and API execution.
"""

import argparse
import json
import os
import stat
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8000"
SESSION_CACHE_DIR = Path.home() / ".reconix"
SESSION_CACHE_FILE = SESSION_CACHE_DIR / "session.json"


def get_base_url() -> str:
    """Return the configured base URL for Reconix Core API without trailing slash."""
    url = os.environ.get("RECONIX_CORE_API_URL", DEFAULT_BASE_URL).strip()
    return url.rstrip("/")


def request(
    path: str,
    method: str = "GET",
    data: dict[str, Any] | None = None,
    token: str | None = None,
    timeout: int = 30,
) -> Any:
    """Send an HTTP request to the Reconix Core API and parse the JSON response."""
    base = get_base_url()
    url = f"{base}/{path.lstrip('/')}"
    parsed_url = urllib.parse.urlparse(url)
    if parsed_url.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported URL scheme: {parsed_url.scheme}")

    headers = {"Accept": "application/json"}
    body: bytes | None = None

    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")

    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=body, headers=headers, method=method)  # noqa: S310

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read()
            if not raw:
                return None
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed = json.loads(err_body)
            msg = parsed.get("message") or parsed.get("detail") or err_body
        except Exception:
            msg = err_body
        raise RuntimeError(f"HTTP {exc.code} from {url}: {msg}") from exc
    except urllib.error.URLError as exc:
        raise ConnectionError(
            f"Cannot connect to Reconix Core API at {base}: {exc.reason}. "
            "Ensure Reconix is running (e.g. `docker compose up -d`)."
        ) from exc


def check_status() -> dict[str, Any]:
    """Ping /health to check system readiness."""
    health = request("/health")
    return health if isinstance(health, dict) else {"status": "ok"}


def get_session_token(force_refresh: bool = False) -> str:
    """Return an active session bearer token, retrieving or refreshing as needed."""
    env_token = os.environ.get("RECONIX_SESSION_TOKEN")
    if env_token and not force_refresh:
        return env_token.strip()

    if not force_refresh and SESSION_CACHE_FILE.exists():
        try:
            cached = json.loads(SESSION_CACHE_FILE.read_text(encoding="utf-8"))
            token = cached.get("token")
            if token:
                return token
        except (OSError, json.JSONDecodeError, KeyError):
            pass

    # Create new session via REST API
    res = request("/api/v1/sessions", method="POST", data={})
    if not isinstance(res, dict) or "token" not in res:
        raise RuntimeError(f"Unexpected response when creating session: {res}")

    token = res["token"]

    # Cache securely with user-only permissions
    SESSION_CACHE_DIR.mkdir(mode=stat.S_IRWXU, parents=True, exist_ok=True)
    SESSION_CACHE_FILE.write_text(json.dumps({"token": token}), encoding="utf-8")
    os.chmod(SESSION_CACHE_FILE, stat.S_IRUSR | stat.S_IWUSR)

    return token


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconix Operator Assistant CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", help="Check Reconix Core health")

    # session
    subparsers.add_parser("session", help="Get or refresh session token")

    args = parser.parse_args()

    if args.command == "status":
        status = check_status()
        print(json.dumps(status, indent=2))
    elif args.command == "session":
        token = get_session_token()
        print(token)


if __name__ == "__main__":
    main()
