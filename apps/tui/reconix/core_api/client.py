"""The HTTP calls to the local Core API (`services/api`), with the standard library only.

Every piece of data the app shows comes from here: the API runs the checks and approvals
and calls Kali; the app never calls a tool or makes data up (apps/CLAUDE.md "Data").

The API listens on this computer only, so the address must be a loopback one
(RECONIX_CORE_API, default "http://127.0.0.1:8000"); anything else is refused before a
call, because every call carries the session token. The token lives in memory only: never
in a log, a snapshot, `~/.reconix` or the chat.
"""

import ipaddress
import json
import os
import urllib.error
import urllib.request
from typing import Any, Optional
from urllib.parse import urlsplit

from ..llm import LLMError

ENV_URL = "RECONIX_CORE_API"
DEFAULT_URL = "http://127.0.0.1:8000"
NOT_RUNNING = "the Core API is not running: start it with ./deploy/dev.sh"
API_PREFIX = "/api/v1"
# A plan or an answer from a thinking model can take minutes (the API waits for the model).
TIMEOUT_SECONDS = 600


class CoreApiError(LLMError):
    """A Core API call failed. `code` is the API's UPPERCASE error code (or our own).

    It is an LLMError, so every place that falls back when the model fails falls back the
    same way when the API does."""

    def __init__(self, code: str, message: str, status: int = 0,
                 details: Optional[dict] = None) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.details = details or {}


def base_url() -> str:
    """The API's address (RECONIX_CORE_API, else the default). Raises CoreApiError for an
    address that isn't on this computer."""
    url = os.environ.get(ENV_URL, "").strip().rstrip("/") or DEFAULT_URL
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if parts.scheme not in ("http", "https") or not local or parts.path or parts.query:
        raise CoreApiError(
            "NOT_LOCAL", f"{ENV_URL} must be this computer, e.g. http://127.0.0.1:8000."
        )
    return url


def enabled() -> bool:
    """Always: the app has no other data source. (Kept for callers being moved over.)"""
    return True


def call(method: str, path: str, body: Any = None, token: str = "",
         gzip_body: Optional[bytes] = None) -> Any:
    """One API call: the decoded JSON answer (None for 204). Raises CoreApiError with the
    API's own code and message, which are safe to show (the API masks them).
    `gzip_body` is a ready tar.gz sent as it is (the code upload) instead of JSON `body`."""
    url = base_url()
    data = gzip_body if gzip_body is not None else (
        None if body is None else json.dumps(body).encode())
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/gzip" if gzip_body is not None \
            else "application/json"
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(
        url + API_PREFIX + path, data=data, headers=headers, method=method
    )
    return _send(request)


def _send(request: urllib.request.Request) -> Any:
    """The network call itself (tests replace this)."""
    try:
        # The address was checked to be this computer in base_url().
        with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise _api_error(exc.code, exc.read()) from None
    except (urllib.error.URLError, OSError):
        raise CoreApiError("UNREACHABLE", NOT_RUNNING) from None
    return json.loads(raw) if raw else None


def _api_error(status: int, raw: bytes) -> CoreApiError:
    """The API's error shape {"code", "message", "details"} as a CoreApiError."""
    try:
        body = json.loads(raw)
        code, message = str(body["code"]), str(body["message"])
        details = body.get("details") if isinstance(body.get("details"), dict) else {}
    except (ValueError, KeyError, TypeError, AttributeError):
        code, message, details = "HTTP_ERROR", f"the Core API answered HTTP {status}", {}
    return CoreApiError(code, message, status, details)
