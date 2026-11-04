"""GET /stream: audit events as Server-Sent Events, while the session token stays valid."""

import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import GetOperator
from reconix_api.core.live_events import Listener
from reconix_api.repositories import assessments as assessment_repo

PING = ": ping\n\n"  # an SSE comment: keeps the connection open, clients ignore it


def check_assessment(db: Db, assessment_id: UUID) -> None:
    if assessment_repo.get(db, assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")


async def frames(
    listener: Listener,
    get_operator: GetOperator,
    token: str,
    assessment_id: UUID | None,
    heartbeat_seconds: float,
    is_disconnected: Callable[[], Awaitable[bool]],
) -> AsyncIterator[str]:
    """Ends when the client leaves, the session is closed, or the listener is dropped.
    With an assessment_id, only that assessment's events are sent."""
    wanted = str(assessment_id) if assessment_id else None
    record: dict[str, Any] | str | None
    while True:
        try:
            record = await asyncio.wait_for(listener.get(), heartbeat_seconds)
        except TimeoutError:
            record = PING
        # A closed session gets nothing more, not even one more event.
        if record is None or not _still_signed_in(get_operator, token):
            return
        if record is PING:
            if await is_disconnected():
                return
            yield PING
        elif wanted is None or record["assessment_id"] == wanted:
            yield frame(record)


def frame(record: dict[str, Any]) -> str:
    return sse(record["event_type"], record)


def sse(event: str, data: dict[str, Any]) -> str:
    """One SSE message. json.dumps never writes a raw newline, so data stays one line."""
    return f"event: {event}\ndata: {json.dumps(data, ensure_ascii=True)}\n\n"


def _still_signed_in(get_operator: GetOperator, token: str) -> bool:
    try:
        get_operator(token)
    except PermissionError:
        return False
    return True
