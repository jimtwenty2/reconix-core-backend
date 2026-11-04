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
from reconix_api.services import (
    actions,
    disclosures,
    limit_settings,
    llm_providers,
    plans,
    reports,
    scopes,
)
from reconix_api.services.approvals import approval_state, ensure_can_decide, expires_at
from reconix_api.services.audit import audit


async def approve(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    approval_id: UUID,
    decision: ApprovalDecision,
) -> ApprovalOut:
    """An approved action runs right away, inside this request, and the plan that
    suggested it (if any) gets the decision."""
    ttl_minutes = settings.approval_ttl_minutes
    write_audit = interfaces.write_audit
    approval = _get_pending(db, write_audit, operator, approval_id, ttl_minutes)
    try:
        ensure_can_decide(
            approval_state(approval, ttl_minutes), datetime.now(UTC), decision.typed_target
        )
    except ApiError as error:
        # The approval stays PENDING (a typo is not a rejection), but the refusal is recorded.
        _audit_refused(db, write_audit, operator, approval, error.code)
        raise
    if approval.kind == "scope":
        scopes.approve_scope(db, interfaces.write_audit, operator, approval)
    elif approval.kind == "action":
        try:
            await actions.approve_action(db, interfaces, mask, settings, operator, approval)
        except ApiError:
            if approval.approval_status == ApprovalStatus.EXPIRED:
                # The second check refused it: the plan hears REJECTED, nothing ran.
                await plans.resume_after_decision(db, interfaces, operator, approval, "REJECTED")
            raise
        await plans.resume_after_decision(db, interfaces, operator, approval, "APPROVED")
    elif approval.kind == "review":
        reports.approve_review(db, interfaces.write_audit, operator, approval)
    elif llm_providers.is_activation(approval):
        llm_providers.approve_activation(db, interfaces.write_audit, operator, approval)
    elif limit_settings.is_limit_change(approval):
        limit_settings.approve_limit_change(db, interfaces.write_audit, operator, approval)
    elif disclosures.is_disclosure(approval):
        disclosures.approve_disclosure(db, interfaces.write_audit, operator, approval)
    else:
        _not_supported(approval)
    return approval_out(approval, ttl_minutes)


async def reject(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    ttl_minutes: int,
    approval_id: UUID,
    decision: ApprovalDecision,
) -> ApprovalOut:
    approval = _get_pending(db, interfaces.write_audit, operator, approval_id, ttl_minutes)
    if approval.kind == "scope":
        scopes.reject_scope(db, interfaces.write_audit, operator, approval, decision.reason)
    elif approval.kind == "action":
        actions.reject_action(db, interfaces.write_audit, operator, approval, decision.reason)
        await plans.resume_after_decision(db, interfaces, operator, approval, "REJECTED")
    elif approval.kind == "review":
        reports.reject_review(db, interfaces.write_audit, operator, approval, decision.reason)
    elif llm_providers.is_activation(approval):
        llm_providers.reject_activation(
            db, interfaces.write_audit, operator, approval, decision.reason
        )
    elif limit_settings.is_limit_change(approval):
        limit_settings.reject_limit_change(
            db, interfaces.write_audit, operator, approval, decision.reason
        )
    elif disclosures.is_disclosure(approval):
        disclosures.reject_disclosure(
            db, interfaces.write_audit, operator, approval, decision.reason
        )
    else:
        _not_supported(approval)
    return approval_out(approval, ttl_minutes)


def read_approval(db: Db, approval_id: UUID, ttl_minutes: int) -> ApprovalOut:
    return approval_out(_get(db, approval_id), ttl_minutes)


def list_approvals(
    db: Db, ttl_minutes: int, status: ApprovalStatus, kind: str | None
) -> list[ApprovalOut]:
    approvals = approval_repo.list_by_status(db, status, kind)
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
        report_id=approval.report_id,
        evidence_id=approval.evidence_id,
        config_change=approval.config_change,
    )


def _get(db: Db, approval_id: UUID, lock: bool = False) -> Approval:
    if lock:
        approval = approval_repo.get_for_update(db, approval_id)
    else:
        approval = approval_repo.get(db, approval_id)
    if approval is None:
        raise ApiError(404, "APPROVAL_NOT_FOUND", "No approval with this id.")
    return approval


def _get_pending(
    db: Db, write_audit: WriteAudit, operator: Operator, approval_id: UUID, ttl_minutes: int
) -> Approval:
    """Locks the approval. A PENDING one past its expiry is saved as EXPIRED first, with
    one audit line."""
    approval = _get(db, approval_id, lock=True)
    if approval.approval_status != ApprovalStatus.PENDING:
        _audit_refused(db, write_audit, operator, approval, "APPROVAL_ALREADY_DECIDED")
        raise ApiError(409, "APPROVAL_ALREADY_DECIDED", "This approval was already decided.")
    if datetime.now(UTC) >= expires_at(approval.requested_at, ttl_minutes):
        approval.approval_status = ApprovalStatus.EXPIRED
        db.commit()
        assessment_id = approval_repo.assessment_of(db, approval)
        details = _details(approval, "EXPIRED")
        audit(write_audit, "APPROVAL_EXPIRED", operator, assessment_id, details)
        raise ApiError(409, "APPROVAL_EXPIRED", "This approval expired. Submit it again.")
    return approval


def _audit_refused(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str
) -> None:
    """One APPROVAL_REFUSED line: the approval stays as it was."""
    assessment_id = approval_repo.assessment_of(db, approval)
    audit(write_audit, "APPROVAL_REFUSED", operator, assessment_id, _details(approval, reason))


def _details(approval: Approval, reason: str) -> dict[str, str]:
    """Which approval, what it was for, and why: never the snapshot itself."""
    details = {"approval_id": str(approval.approval_id), "kind": approval.kind, "reason": reason}
    for name in ("action_id", "manifest_id", "report_id", "evidence_id"):
        value = getattr(approval, name)
        if value is not None:
            details[name] = str(value)
    return details


def _not_supported(approval: Approval) -> None:
    raise ApiError(
        409,
        "APPROVAL_KIND_NOT_SUPPORTED",
        "This kind of approval cannot be decided yet.",
        {"kind": approval.kind},
    )
