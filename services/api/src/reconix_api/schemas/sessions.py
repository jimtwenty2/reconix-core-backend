"""Request and response shapes for /sessions."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

from reconix_api.models.enums import Role, SessionStatus


class SessionCreate(BaseModel):
    interface: Literal["web", "cli"]


class SessionOut(BaseModel):
    session_id: UUID
    interface: str
    role: Role
    session_status: SessionStatus
    created_at: datetime


class SessionCreated(SessionOut):
    token: str  # send as "Authorization: Bearer <token>"; shown only once


class SessionRead(BaseModel):
    """A session as stored. The role lives with the token, so it is not shown here."""

    session_id: UUID
    interface: str
    session_status: SessionStatus
    created_at: datetime
    closed_at: datetime | None
