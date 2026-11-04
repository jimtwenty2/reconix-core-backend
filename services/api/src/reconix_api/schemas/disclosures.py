"""Request and response shapes for showing one masked value (disclosure)."""

from uuid import UUID

from pydantic import BaseModel, Field


class HiddenValueOut(BaseModel):
    """A masked value that can be shown with a `disclosure` approval; never the value."""

    index: int
    kind: str  # e.g. "password", the same as its [MASKED:password] label


class DisclosureRequest(BaseModel):
    index: int = Field(ge=0)


class DisclosedValueOut(BaseModel):
    evidence_id: UUID
    approval_id: UUID
    index: int
    kind: str
    value: str  # the real value, shown once
