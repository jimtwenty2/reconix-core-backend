"""Request protections and who-is-calling dependencies."""

from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from reconix_api.core.errors import ApiError, error_response
from reconix_api.core.interfaces import Interfaces, Operator


class HostCheckMiddleware(BaseHTTPMiddleware):
    """Rejects a request whose Host header is not this computer (stops DNS rebinding)."""

    def __init__(self, app, allowed_hosts: list[str]) -> None:
        super().__init__(app)
        self.allowed_hosts = set(allowed_hosts)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not host_is_allowed(request.headers.get("host", ""), self.allowed_hosts):
            return error_response(400, "INVALID_HOST", "The Host header is not allowed.")
        return await call_next(request)


def host_is_allowed(host: str, allowed_hosts: list[str] | set[str]) -> bool:
    """The middleware above only sees HTTP requests; WebSocket routes call this themselves."""
    return _host_name(host) in set(allowed_hosts)


def _host_name(host: str) -> str:
    """'127.0.0.1:8000' -> '127.0.0.1', '[::1]:8000' -> '::1'."""
    if host.startswith("["):
        return host[1 : host.find("]")]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def get_interfaces(request: Request) -> Interfaces:
    return request.app.state.interfaces


# Declared so the API docs (Swagger) show an Authorize button and send the token.
# auto_error=False keeps our own error shape for a missing or wrong header.
bearer = HTTPBearer(
    auto_error=False,
    scheme_name="SessionToken",
    description="The token from POST /api/v1/sessions.",
)


def current_operator(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    interfaces: Annotated[Interfaces, Depends(get_interfaces)],
) -> Operator:
    """Use on every endpoint except /health and POST /sessions. There are no roles: a
    valid token may do everything."""
    if credentials is None or not credentials.credentials:
        raise ApiError(401, "UNAUTHORIZED", "Send the session token as a Bearer token.")
    try:
        return interfaces.get_operator(credentials.credentials)
    except PermissionError as error:
        raise ApiError(401, "UNAUTHORIZED", "The session token is not valid.") from error


CurrentOperator = Annotated[Operator, Depends(current_operator)]
CurrentInterfaces = Annotated[Interfaces, Depends(get_interfaces)]
