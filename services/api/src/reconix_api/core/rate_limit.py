"""Too many requests: a simple limit per caller, per minute, kept in memory.

The API is one process on this computer, so a counter in memory is enough. Each caller
may send so many requests in the current minute; after that it gets 429 TOO_MANY_REQUESTS
with a Retry-After header until the next minute starts. The window is fixed, so up to twice
the limit can pass across the turn of a minute; fine for a local tool.

Who is a caller:
- a session token (only its hash is kept);
- signing in (POST /sessions, POST /sessions/web-sign-in), with its own, smaller limit;
- requests from a web page that is not the local web (any other Origin): their own bucket,
  so a page open in the user's browser can never use up the real callers' limits;
- anything else without a token.
CORS preflights and GET /health are not counted. WebSockets are not counted here (the
terminal allows one per session).
"""

import hashlib
import logging
import math
import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from reconix_api.core.errors import error_response

logger = logging.getLogger(__name__)

WINDOW_SECONDS = 60
MAX_CALLERS = 10_000  # callers counted per minute; more (made-up tokens) share one bucket
SIGN_IN_PATHS = {"/api/v1/sessions", "/api/v1/sessions/web-sign-in"}
NOT_COUNTED = {("GET", "/api/v1/health")}


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(
        self,
        app,
        per_minute: int,
        sign_in_per_minute: int,
        web_origins: list[str],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        super().__init__(app)
        self.per_minute = per_minute
        self.sign_in_per_minute = sign_in_per_minute
        self.web_origins = set(web_origins)
        self.clock = clock
        self.window = -1
        self.counts: dict[str, int] = {}

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.method == "OPTIONS" or (request.method, request.url.path) in NOT_COUNTED:
            return await call_next(request)
        key, limit = self._bucket(request)
        now = self.clock()
        window = int(now // WINDOW_SECONDS)
        if window != self.window:  # a new minute: every counter starts again
            self.window, self.counts = window, {}
        if key not in self.counts and len(self.counts) >= MAX_CALLERS:
            key = "overflow"
        self.counts[key] = self.counts.get(key, 0) + 1
        if self.counts[key] <= limit:
            return await call_next(request)
        retry_after = max(1, math.ceil((window + 1) * WINDOW_SECONDS - now))
        if self.counts[key] == limit + 1:  # once per caller and minute, never the token
            bucket = "session" if len(key) == 64 else key
            logger.warning(
                "Too many requests from one %s caller; refused for %ss", bucket, retry_after
            )
        response = error_response(
            429,
            "TOO_MANY_REQUESTS",
            "Too many requests. Wait a moment and try again.",
            {"retry_after_seconds": retry_after},
        )
        response.headers["Retry-After"] = str(retry_after)
        return response

    def _bucket(self, request: Request) -> tuple[str, int]:
        origin = request.headers.get("origin")
        if origin is not None and origin not in self.web_origins:
            return "other-web-page", self.per_minute
        if request.method == "POST" and request.url.path in SIGN_IN_PATHS:
            return "sign-in", self.sign_in_per_minute
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() == "bearer" and token:
            return hashlib.sha256(token.encode()).hexdigest(), self.per_minute
        return "no-token", self.per_minute
