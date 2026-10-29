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
