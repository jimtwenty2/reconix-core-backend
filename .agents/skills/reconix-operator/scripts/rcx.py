#!/usr/bin/env python3
"""rcx.py — Reconix Operator CLI and REST/MCP Bridge Helper.

Zero external dependencies (uses standard library only).
Provides token caching, health verification, action hashing, and API execution.
"""

import argparse
import hashlib
import json
import os
import stat
import sys
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


def compute_action_hash(action_dict: dict[str, Any]) -> str:
    """Compute the deterministic SHA-256 action hash required for single-use approval."""
    canonical = json.dumps(action_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def create_scope(
    target: str,
    max_risk: str = "MEDIUM",
    exclusions: list[str] | None = None,
) -> dict[str, Any]:
    """Define and register a target scope with the Core API."""
    token = get_session_token()
    targets = [t.strip() for t in target.split(",") if t.strip()]
    payload = {
        "targets": targets,
        "exclusions": exclusions or [],
        "max_risk": max_risk.upper(),
    }
    res = request("/api/v1/scopes", method="POST", data=payload, token=token)
    return res if isinstance(res, dict) else {}


def submit_approval(
    action_id: str,
    action_hash: str,
    target_confirmation: str | None = None,
) -> dict[str, Any]:
    """Submit approval for a MEDIUM or HIGH risk action with SHA-256 verification."""
    token = get_session_token()
    payload = {
        "action_id": action_id,
        "action_hash": action_hash,
    }
    if target_confirmation:
        payload["target_confirmation"] = target_confirmation
    res = request("/api/v1/approvals", method="POST", data=payload, token=token)
    return res if isinstance(res, dict) else {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconix Operator Assistant CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", help="Check Reconix Core health")

    # session
    subparsers.add_parser("session", help="Get or refresh session token")

    # scope
    scope_parser = subparsers.add_parser("scope", help="Create an assessment scope")
    scope_parser.add_argument(
        "--target", required=True, help="Target IP, domain, or CIDR (comma-separated)"
    )
    scope_parser.add_argument("--max-risk", default="MEDIUM", choices=["LOW", "MEDIUM", "HIGH"])
    scope_parser.add_argument("--exclude", help="Excluded targets (comma-separated)")

    # action-hash
    hash_parser = subparsers.add_parser(
        "action-hash", help="Compute deterministic SHA-256 action hash"
    )
    hash_parser.add_argument("--action-json", required=True, help="Raw JSON of the proposed action")

    # approve
    app_parser = subparsers.add_parser("approve", help="Approve a gated action")
    app_parser.add_argument("--action-id", required=True, help="ID of the action to approve")
    app_parser.add_argument("--action-hash", required=True, help="SHA-256 hash of the action")
    app_parser.add_argument(
        "--confirm-target", help="Explicit target confirmation string (required for HIGH risk)"
    )

    args = parser.parse_args()

    if args.command == "status":
        status = check_status()
        print(json.dumps(status, indent=2))
    elif args.command == "session":
        token = get_session_token()
        print(token)
    elif args.command == "scope":
        exclusions = [e.strip() for e in args.exclude.split(",")] if args.exclude else None
        res = create_scope(args.target, max_risk=args.max_risk, exclusions=exclusions)
        print(json.dumps(res, indent=2))
    elif args.command == "action-hash":
        try:
            action_data = json.loads(args.action_json)
        except json.JSONDecodeError as exc:
            print(f"Invalid JSON: {exc}", file=sys.stderr)
            sys.exit(1)
        h = compute_action_hash(action_data)
        print(h)
    elif args.command == "approve":
        res = submit_approval(
            args.action_id, args.action_hash, target_confirmation=args.confirm_target
        )
        print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
