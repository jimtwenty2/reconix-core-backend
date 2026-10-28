"""Request and response shapes for /approvals."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.models.enums import ApprovalStatus, RiskLevel

ApprovalKind = Literal["scope", "action", "disclosure", "configuration", "review"]


class ApprovalDecision(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)
    typed_target: str | None = Field(default=None, max_length=2048)  # required for HIGH actions


class ApprovalOut(BaseModel):
    approval_id: UUID
    kind: str
    subject_snapshot: dict[str, Any]
    subject_hash: str
    risk_level: RiskLevel | None
    approval_status: ApprovalStatus
    confirmation_verified: bool
    reason: str | None
    decided_by: str | None
    requested_at: datetime
    decided_at: datetime | None
    consumed_at: datetime | None
    expires_at: datetime
    action_id: UUID | None
    manifest_id: UUID | None
