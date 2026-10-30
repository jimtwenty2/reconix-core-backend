"""Request and response shapes for /sessions."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from reconix_api.models.enums import SessionStatus


class SessionCreate(BaseModel):
    interface: Literal["web", "cli"]


class SessionRead(BaseModel):
    """A session as stored."""

    session_id: UUID
    interface: str
    session_status: SessionStatus
    created_at: datetime
    closed_at: datetime | None


class SessionCreated(SessionRead):
    """The new session and its token."""

    token: str  # send as "Authorization: Bearer <token>"; shown only once
