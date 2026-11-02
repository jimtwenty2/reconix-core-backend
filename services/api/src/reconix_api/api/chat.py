"""Chat with the agent in a session."""

from uuid import UUID

from fastapi import APIRouter, status
from fastapi.responses import StreamingResponse

from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.messages import ChatOut, MessageCreate
from reconix_api.services import chat as chat_service

router = APIRouter(prefix="/sessions/{session_id}/chat", tags=["messages"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def chat(
    session_id: UUID,
    body: MessageCreate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
) -> ChatOut:
    """Saves the person's message and gives back the agent's answer. The agent only
    answers: it never changes the scope, the plan or an approval, and runs no tool."""
    return await chat_service.chat(db, interfaces, mask, operator, session_id, body.content)


@router.post(
    "/stream",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def chat_stream(
    session_id: UUID,
    body: MessageCreate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
) -> StreamingResponse:
    """POST /chat, with the answer streamed as Server-Sent Events while the agent writes:

    - `event: PIECE`, `data: {"text": "..."}`: the next masked piece of the answer.
    - `event: DONE`, `data:` the same ChatOut as POST /chat. Show its reply in place of
      the pieces: it is the saved answer, and the last words come only here.
    - `event: ERROR`, `data: {"code", "message", "details"}`: the ask failed.

    A wrong session or a chat already running fails before the stream starts, with the
    usual error and status. If the client leaves, the answer is still saved."""
    started = chat_service.start(db, interfaces, mask, operator, session_id, body.content)
    ask = chat_service.ask_in_background(db, interfaces, mask, operator, started)
    events = chat_service.stream_events(ask)
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(events, media_type="text/event-stream", headers=headers)
