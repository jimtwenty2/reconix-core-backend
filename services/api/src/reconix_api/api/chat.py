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
    """Saves the person's message and returns the agent's answer.

    Business Rules:
    - The agent only answers. It never changes the scope, the plan, or an approval, and it never
      runs a tool.

    Execution Behavior:
    - Calls the agent to answer the message.

    State Changes:
    - Saves the message and the agent's reply.

    Security:
    - Requires a valid session token.
    - Secrets in the message are masked before it is saved.
    """
    return await chat_service.chat(
        db, interfaces, mask, operator, session_id, body.content, assessment_id=body.assessment_id
    )


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
    """Streams the agent's answer as Server-Sent Events while it is written, like POST /chat.

    Business Rules:
    - A wrong session, or a chat already running, fails before the stream starts, with the usual
      error and status code.

    Execution Behavior:
    - Emits three event types:
      - `event: PIECE`, `data: {"text": "..."}`: the next part of the masked answer.
      - `event: DONE`, `data:` the same ChatOut as POST /chat. Show its reply in place of the
        pieces; it is the answer that was saved, and the final words arrive only here.
      - `event: ERROR`, `data: {"code", "message", "details"}`: the question could not be answered.

    State Changes:
    - Saves the message and the agent's reply, even if the client disconnects.

    Security:
    - Requires a valid session token.
    """
    started = chat_service.start(
        db, interfaces, mask, operator, session_id, body.content, assessment_id=body.assessment_id
    )
    ask = chat_service.ask_in_background(db, interfaces, mask, operator, started)
    events = chat_service.stream_events(ask)
    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(events, media_type="text/event-stream", headers=headers)
