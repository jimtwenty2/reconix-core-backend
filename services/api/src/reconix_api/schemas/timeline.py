"""Shapes for GET /assessments/{id}/timeline: audit log lines, as the harness wrote them."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class TimelineEventOut(BaseModel):
    event_type: str  # e.g. SCOPE_APPROVED, TOOL_RUN_STARTED
    at: datetime
    actor: str  # masked
    session_id: UUID
    details: dict[str, Any]  # masked when written, and again when read


class TimelineOut(BaseModel):
    events: list[TimelineEventOut]  # oldest first
    has_older: bool  # True: older events were left out (raise ?limit=)
