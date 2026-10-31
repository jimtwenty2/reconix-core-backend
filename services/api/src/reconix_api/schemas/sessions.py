"""Request and response shapes for /sessions."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

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


class WebSignInCode(BaseModel):
    """A one-time code for the web sign-in link that `/web` prints."""

    code: str
    expires_at: datetime


class WebSignIn(BaseModel):
    code: str = Field(min_length=1, max_length=100)
