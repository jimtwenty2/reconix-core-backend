"""Chat with the agent in a session."""

from uuid import UUID

from fastapi import APIRouter, status

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
