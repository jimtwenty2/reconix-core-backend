"""Request and response shapes for the system routes."""

from datetime import datetime

from pydantic import BaseModel


class KaliStatus(BaseModel):
    """Whether the Kali MCP tool container answers. For a reachability indicator in the
    apps; it never carries the access token."""

    connected: bool
    host: str | None  # the Kali MCP host (and port), no credentials; None if the URL is unset
    checked_at: datetime
