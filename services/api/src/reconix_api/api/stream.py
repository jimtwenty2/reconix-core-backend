"""Live updates for the terminal app and the web."""

from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.live_events import LiveEvents
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, bearer
from reconix_api.services import stream

router = APIRouter(tags=["stream"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]
Credentials = Annotated[HTTPAuthorizationCredentials, Depends(bearer)]


@router.get(
    "/stream",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def read_stream(
    request: Request,
    _: CurrentOperator,
    credentials: Credentials,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
    assessment_id: UUID | None = None,
) -> StreamingResponse:
    """Streams every audit event live as Server-Sent Events, the moment it is written.

    Business Rules:
    - With ?assessment_id=, you receive only that assessment's events.
    - The stream ends when the session is closed; reconnect and reload your lists to catch up.

    Execution Behavior:
    - Each message is `event: <EVENT_TYPE>` with `data: {event_type, assessment_id, session_id,
      actor, at, details}`, masked.
    - A `: ping` comment arrives every few seconds to keep the connection open.

    Security:
    - Requires a valid session token, sent as a Bearer header (read the stream with fetch, not
      EventSource).
    """
    live: LiveEvents = request.app.state.live_events

    async def body() -> AsyncIterator[str]:
        # Added here, not in the route, so it is always removed: a response cancelled
        # before its body starts would never reach the finally below.
        listener = live.add()
        try:
            async for part in stream.frames(
                listener,
                interfaces.get_operator,
                credentials.credentials,
                assessment_id,
                settings.stream_heartbeat_seconds,
                request.is_disconnected,
            ):
                yield part
        finally:
            live.remove(listener)

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(body(), media_type="text/event-stream", headers=headers)
