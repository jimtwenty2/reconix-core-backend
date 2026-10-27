"""Approving or rejecting any approval. The rules live in services/approvals.py;
what happens next depends on the approval's kind."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Interfaces, Operator, WriteAudit
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Approval
from reconix_api.models.enums import ApprovalStatus
from reconix_api.repositories import approvals as approval_repo
from reconix_api.schemas.approvals import ApprovalDecision, ApprovalOut
from reconix_api.services import actions, scopes
from reconix_api.services.approvals import approval_state, ensure_can_decide, expires_at


async def approve(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    approval_id: UUID,
    decision: ApprovalDecision,
) -> ApprovalOut:
    """An approved action runs right away, inside this request."""
    ttl_minutes = settings.approval_ttl_minutes
    approval = _get_pending(db, approval_id, ttl_minutes)
    ensure_can_decide(
        approval_state(approval, ttl_minutes), datetime.now(UTC), decision.typed_target
    )
    if approval.kind == "scope":
        scopes.approve_scope(db, interfaces.write_audit, operator, approval)
    elif approval.kind == "action":
        await actions.approve_action(db, interfaces, mask, settings, operator, approval)
    else:
        _not_supported(approval)
    return approval_out(approval, ttl_minutes)


def reject(
    db: Db,
    write_audit: WriteAudit,
    operator: Operator,
    ttl_minutes: int,
    approval_id: UUID,
    decision: ApprovalDecision,
) -> ApprovalOut:
    approval = _get_pending(db, approval_id, ttl_minutes)
    if approval.kind == "scope":
        scopes.reject_scope(db, write_audit, operator, approval, decision.reason)
    elif approval.kind == "action":
        actions.reject_action(db, write_audit, operator, approval, decision.reason)
    else:
        _not_supported(approval)
    return approval_out(approval, ttl_minutes)


def read_approval(db: Db, approval_id: UUID, ttl_minutes: int) -> ApprovalOut:
    return approval_out(_get(db, approval_id), ttl_minutes)


def list_pending(db: Db, ttl_minutes: int) -> list[ApprovalOut]:
    approvals = approval_repo.list_by_status(db, ApprovalStatus.PENDING)
    return [approval_out(approval, ttl_minutes) for approval in approvals]


def approval_out(approval: Approval, ttl_minutes: int) -> ApprovalOut:
    return ApprovalOut(
        approval_id=approval.approval_id,
        kind=approval.kind,
        subject_snapshot=approval.subject_snapshot,
        subject_hash=approval.subject_hash,
        risk_level=approval.risk_level,
        approval_status=approval.approval_status,
        confirmation_verified=approval.confirmation_verified,
        reason=approval.reason,
        decided_by=approval.decided_by,
        requested_at=approval.requested_at,
        decided_at=approval.decided_at,
        consumed_at=approval.consumed_at,
        expires_at=expires_at(approval.requested_at, ttl_minutes),
        action_id=approval.action_id,
        manifest_id=approval.manifest_id,
    )


def _get(db: Db, approval_id: UUID, lock: bool = False) -> Approval:
    if lock:
        approval = approval_repo.get_for_update(db, approval_id)
    else:
        approval = approval_repo.get(db, approval_id)
    if approval is None:
        raise ApiError(404, "APPROVAL_NOT_FOUND", "No approval with this id.")
    return approval


def _get_pending(db: Db, approval_id: UUID, ttl_minutes: int) -> Approval:
    """Locks the approval. A PENDING one past its expiry is saved as EXPIRED first."""
    approval = _get(db, approval_id, lock=True)
    if approval.approval_status != ApprovalStatus.PENDING:
        raise ApiError(409, "APPROVAL_ALREADY_DECIDED", "This approval was already decided.")
    if datetime.now(UTC) >= expires_at(approval.requested_at, ttl_minutes):
        approval.approval_status = ApprovalStatus.EXPIRED
        db.commit()
        raise ApiError(409, "APPROVAL_EXPIRED", "This approval expired. Submit it again.")
    return approval


def _not_supported(approval: Approval) -> None:
    raise ApiError(
        409,
        "APPROVAL_KIND_NOT_SUPPORTED",
        "This kind of approval cannot be decided yet.",
        {"kind": approval.kind},
    )
