"""Request and response shapes for /sessions/{session_id}/messages."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class MessageCreate(BaseModel):
    content: str = Field(min_length=1, max_length=20000)  # masked before it is saved


class MessageOut(BaseModel):
    message_id: UUID
    sequence_no: int
    role: str  # user, assistant or system
    content_masked: str
    created_at: datetime
    session_id: UUID


class ChatOut(BaseModel):
    """The person's message as saved, and the agent's answer to it. Both are masked."""

    message: MessageOut
    reply: MessageOut
    agent_run_id: UUID  # the CHAT run: the model that answered, its status and end
