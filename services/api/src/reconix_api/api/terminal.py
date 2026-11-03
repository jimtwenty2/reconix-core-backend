"""WS /api/v1/terminal: the terminal app (TUI) in the web Terminal page."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, WebSocket

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.security import host_is_allowed
from reconix_api.core.terminal import Terminal, TerminalAppMissing, default_command
from reconix_api.services import terminal as terminal_service
from reconix_api.services.audit import audit

router = APIRouter(tags=["terminal"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]

PROTOCOL = "reconix.terminal"  # the subprotocol the server picks
AUTH_SUBPROTOCOL_PREFIX = "token."  # a browser sends its token as the subprotocol "token.<token>"

# Close codes before the connection is accepted (the page sees them as a failed handshake).
BAD_HOST_OR_ORIGIN, NO_TOKEN, ALREADY_OPEN = 4403, 4401, 4409
SESSION_CHECK_SECONDS = 1.0  # a closed session ends its terminal within this


@router.websocket("/terminal")
async def terminal(websocket: WebSocket, settings: CurrentSettings) -> None:
    """Opens the terminal app for the web Terminal page.

    A browser cannot send an Authorization header on a WebSocket, so it sends its session
    token as a subprotocol: new WebSocket(url, ["reconix.terminal", "token." + token]).
    Other clients may send `Authorization: Bearer <token>`. Only the local web's Origin is
    accepted, and one terminal per session. Screen output comes as binary frames; send keys
    as binary frames or {"type": "input", "data": "..."}, and {"type": "resize", "cols": 120,
    "rows": 32} when the page changes size."""
    if not host_is_allowed(websocket.headers.get("host", ""), settings.allowed_hosts):
        await websocket.close(code=BAD_HOST_OR_ORIGIN)
        return
    if websocket.headers.get("origin") not in settings.web_origins:
        await websocket.close(code=BAD_HOST_OR_ORIGIN)
        return
    interfaces = websocket.app.state.interfaces
    token = _token(websocket)
    try:
        operator = interfaces.get_operator(token)
    except PermissionError:
        await websocket.close(code=NO_TOKEN)
        return
    open_terminals: set[UUID] = _open_terminals(websocket)
    if operator.session_id in open_terminals:
        _refused(interfaces, operator, "ALREADY_OPEN")
        await websocket.close(code=ALREADY_OPEN)
        return

    open_terminals.add(operator.session_id)
    try:
        offered = websocket.scope.get("subprotocols", [])
        await websocket.accept(subprotocol=PROTOCOL if PROTOCOL in offered else None)
        try:
            command = default_command()
        except TerminalAppMissing:
            _refused(interfaces, operator, "TERMINAL_APP_MISSING")
            await terminal_service.close(websocket, "TERMINAL_APP_MISSING")
            return
        await terminal_service.run_terminal(
            websocket,
            Terminal(command, terminal_service.DEFAULT_COLS, terminal_service.DEFAULT_ROWS),
            interfaces.write_audit,
            operator,
            lambda: _still_signed_in(interfaces, token),
            min(settings.stream_heartbeat_seconds, SESSION_CHECK_SECONDS),
        )
    finally:
        open_terminals.discard(operator.session_id)


def _token(websocket: WebSocket) -> str:
    """From the "token.<token>" subprotocol, or else the Authorization header. Never echoed."""
    for protocol in websocket.scope.get("subprotocols", []):
        if protocol.startswith(AUTH_SUBPROTOCOL_PREFIX):
            return protocol.removeprefix(AUTH_SUBPROTOCOL_PREFIX)
    scheme, _, value = websocket.headers.get("authorization", "").partition(" ")
    return value.strip() if scheme.lower() == "bearer" else ""


def _refused(interfaces, operator, reason: str) -> None:
    """One audit line for a signed-in caller who gets no terminal."""
    audit(interfaces.write_audit, "TERMINAL_REFUSED", operator, details={"reason": reason})


def _open_terminals(websocket: WebSocket) -> set[UUID]:
    state = websocket.app.state
    if not hasattr(state, "open_terminals"):
        state.open_terminals = set()
    return state.open_terminals


def _still_signed_in(interfaces, token: str) -> bool:
    try:
        interfaces.get_operator(token)
    except PermissionError:
        return False
    return True
