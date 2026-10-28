"""Approval rules: 30-minute expiry, single use, typed target for HIGH risk.

Pure functions, so they are easy to test. The database layer stores the fields below.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import RiskLevel
from reconix_api.models import Approval
from reconix_api.models.enums import ApprovalStatus


class ApprovalState(BaseModel):
    """risk and target are only set for action approvals."""

    status: ApprovalStatus
    risk: RiskLevel | None = None
    target: str | None = None
    created_at: datetime
    expires_at: datetime
    used_at: datetime | None = None


def snapshot_hash(snapshot: dict[str, Any]) -> str:
    """SHA-256 of a snapshot in a fixed form, stored as approvals.subject_hash."""
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


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


def approval_state(approval: Approval, ttl_minutes: int) -> ApprovalState:
    """The fields the rules above need, from a saved approval."""
    return ApprovalState(
        status=approval.approval_status,
        risk=approval.risk_level,
        target=approval.subject_snapshot.get("target"),
        created_at=approval.requested_at,
        expires_at=expires_at(approval.requested_at, ttl_minutes),
        used_at=approval.consumed_at,
    )
