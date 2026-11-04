"""The web Terminal page: one terminal app (TUI) per session, over a WebSocket.

The route (api/terminal.py) has already checked the Host, the Origin and the session
token. This passes keys in and screen output out until either side closes, and ends
the terminal when the session is closed.
"""

import asyncio
import json
from collections.abc import Callable

import anyio
from fastapi import WebSocket, WebSocketDisconnect

from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.terminal import Terminal
from reconix_api.services.audit import audit

MAX_INPUT_BYTES = 65536  # one message of keys or pasted text
MIN_SIZE, MAX_COLS, MAX_ROWS = 2, 500, 200
DEFAULT_COLS, DEFAULT_ROWS = 120, 32
SESSION_CLOSED = 4401  # close code: the session token stopped working


class BadMessage(ValueError):
    """A message from the page that is not input or resize."""


async def run_terminal(
    websocket: WebSocket,
    terminal: Terminal,
    write_audit: WriteAudit,
    operator: Operator,
    still_signed_in: Callable[[], bool],
    check_seconds: float,
) -> None:
    """Runs until the TUI exits, the page leaves, or the session is closed. Always stops
    the TUI, and writes one audit line when it opens and one when it closes (or one
    TERMINAL_REFUSED line if the TUI cannot start)."""
    reason = "PAGE_CLOSED"
    tasks: set[asyncio.Task] = set()
    try:
        await terminal.start()
        audit(write_audit, "TERMINAL_OPENED", operator, details={"pid": terminal.process.pid})
        tasks = {
            asyncio.create_task(_screen_to_page(websocket, terminal), name="TUI_EXITED"),
            asyncio.create_task(_page_to_keys(websocket, terminal), name="PAGE_CLOSED"),
            asyncio.create_task(
                _watch_session(still_signed_in, check_seconds), name="SESSION_CLOSED"
            ),
        }
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        first = done.pop()
        reason = first.get_name()
        if not first.cancelled() and isinstance(first.exception(), BadMessage):
            reason = "BAD_MESSAGE"
    except OSError:
        reason = "START_FAILED"  # e.g. the command cannot be run
    finally:
        for task in tasks:
            task.cancel()
        # Shielded twice: the anyio scope keeps a first cancel (shutdown, a dropped
        # connection) from cutting the cleanup short, and its own task keeps going even if
        # a second cancel arrives. Either way the TUI is stopped and the audit line written.
        cleanup = asyncio.ensure_future(
            _clean_up(websocket, terminal, write_audit, operator, reason)
        )
        with anyio.CancelScope(shield=True):
            await asyncio.shield(cleanup)


async def _clean_up(
    websocket: WebSocket,
    terminal: Terminal,
    write_audit: WriteAudit,
    operator: Operator,
    reason: str,
) -> None:
    exit_code = await terminal.stop()
    await close(websocket, reason)
    if reason == "START_FAILED":
        audit(write_audit, "TERMINAL_REFUSED", operator, details={"reason": reason})
        return
    details = {"reason": reason, "exit_code": exit_code}
    audit(write_audit, "TERMINAL_CLOSED", operator, details=details)


def parse_message(message: dict) -> tuple[str, bytes | tuple[int, int]]:
    """A WebSocket message -> ("input", keys) or ("resize", (cols, rows)).

    Binary frames are keys. Text frames are JSON: {"type": "input", "data": "..."} or
    {"type": "resize", "cols": 120, "rows": 32}."""
    if message.get("bytes") is not None:
        return "input", _limited(message["bytes"])
    try:
        data = json.loads(message.get("text") or "")
    except json.JSONDecodeError:
        raise BadMessage("NOT_JSON") from None
    if not isinstance(data, dict):
        raise BadMessage("NOT_AN_OBJECT")
    if data.get("type") == "input" and isinstance(data.get("data"), str):
        return "input", _limited(data["data"].encode())
    if data.get("type") == "resize":
        return "resize", terminal_size(data.get("cols"), data.get("rows"))
    raise BadMessage("UNKNOWN_TYPE")


def terminal_size(cols: object, rows: object) -> tuple[int, int]:
    for value, highest in ((cols, MAX_COLS), (rows, MAX_ROWS)):
        if isinstance(value, bool) or not isinstance(value, int):
            raise BadMessage("BAD_SIZE")
        if not MIN_SIZE <= value <= highest:
            raise BadMessage("BAD_SIZE")
    return cols, rows


def _limited(data: bytes) -> bytes:
    if len(data) > MAX_INPUT_BYTES:
        raise BadMessage("TOO_LONG")
    return data


async def _screen_to_page(websocket: WebSocket, terminal: Terminal) -> None:
    while (data := await terminal.read()) is not None:
        await websocket.send_bytes(data)


async def _page_to_keys(websocket: WebSocket, terminal: Terminal) -> None:
    while True:
        message = await websocket.receive()
        if message["type"] == "websocket.disconnect":
            raise WebSocketDisconnect(message.get("code", 1000))
        kind, value = parse_message(message)
        if kind == "input":
            await terminal.write(value)
        else:
            terminal.resize(*value)


async def _watch_session(still_signed_in: Callable[[], bool], check_seconds: float) -> None:
    while still_signed_in():
        await asyncio.sleep(check_seconds)


async def close(websocket: WebSocket, reason: str) -> None:
    """Closes with a code the page can act on, and the reason; safe if already closed."""
    code = {
        "SESSION_CLOSED": SESSION_CLOSED,
        "BAD_MESSAGE": 1003,
        "START_FAILED": 1011,
        "TERMINAL_APP_MISSING": 1011,
    }.get(reason, 1000)
    try:
        await websocket.close(code=code, reason=reason)
    except RuntimeError:
        pass  # the page already closed it
