"""Request and response shapes for /sessions."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.models.enums import SessionStatus

Interface = Literal["web", "cli", "vscode"]


class SessionCreate(BaseModel):
    interface: Interface
    # Who is at the computer, e.g. "vanneth@kshrd-laptop". The client (TUI, the web's server
    # side, VS Code) runs on that computer and sends it; when it is left out, the API's own
    # OS user@host is used. A label for the audit log, not a credential.
    operator: str | None = Field(default=None, max_length=100)


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
