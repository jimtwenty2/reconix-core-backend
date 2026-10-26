"""Approval rules: 30-minute expiry, single use, typed target for HIGH risk.

Pure functions, so they are easy to test. The database layer stores the fields below.
"""

from datetime import datetime, timedelta

from pydantic import BaseModel

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import RiskLevel
from reconix_api.models.enums import ApprovalStatus


class ApprovalState(BaseModel):
    status: ApprovalStatus
    risk: RiskLevel
    target: str
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None


def expires_at(created_at: datetime, ttl_minutes: int) -> datetime:
    return created_at + timedelta(minutes=ttl_minutes)


def ensure_can_decide(approval: ApprovalState, now: datetime, typed_target: str | None) -> None:
    """Called when a person approves. Raises if the approval can no longer be given."""
    if approval.status != ApprovalStatus.PENDING:
        raise ApiError(409, "APPROVAL_ALREADY_DECIDED", "This approval was already decided.")
    if now >= approval.expires_at:
        raise ApiError(409, "APPROVAL_EXPIRED", "This approval expired. Send the action again.")
    if approval.risk == RiskLevel.HIGH and typed_target != approval.target:
        raise ApiError(
            422, "TARGET_CONFIRMATION_MISMATCH", "Type the exact target to approve a HIGH action."
        )


def ensure_can_use(approval: ApprovalState, now: datetime) -> None:
    """Called right before the approved thing runs. An approval works once."""
    if approval.status != ApprovalStatus.APPROVED:
        raise ApiError(409, "APPROVAL_NOT_GRANTED", "This action is not approved.")
    if approval.used_at is not None:
        raise ApiError(409, "APPROVAL_ALREADY_USED", "This approval was already used.")
    if now >= approval.expires_at:
        raise ApiError(409, "APPROVAL_EXPIRED", "This approval expired. Send the action again.")
