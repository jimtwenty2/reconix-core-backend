"""Showing one masked value, once, after a `disclosure` approval.

The real values are kept encrypted in the vault (core/disclosure.py) when the evidence
is saved. Asking creates a PENDING approval; approving it allows one reveal; the reveal
uses the approval up. A real value is never saved in the database, logged, written to
the audit log or sent to the AI: it goes only into the reveal's answer.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.config import Settings
from reconix_api.core.disclosure import DisclosureError, DisclosureVault, HiddenValue
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.models import Approval, Evidence
from reconix_api.models.enums import ApprovalStatus
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.schemas.disclosures import DisclosedValueOut, HiddenValueOut
from reconix_api.services.approvals import approval_state, ensure_can_use, snapshot_hash
from reconix_api.services.audit import audit

ERRORS = {
    "NOT_FOUND": (404, "HIDDEN_VALUE_NOT_FOUND", "This evidence has no value that can be shown."),
    "BAD_INDEX": (404, "HIDDEN_VALUE_NOT_FOUND", "This evidence has no value with this index."),
    "BAD_EVIDENCE_ID": (404, "EVIDENCE_NOT_FOUND", "No evidence with this id."),
    "UNREADABLE": (
        409,
        "HIDDEN_VALUE_UNREADABLE",
        "The kept value cannot be read with RECONIX_PROVIDER_ENCRYPTION_KEY.",
    ),
}


def list_hidden_values(db: Db, vault: DisclosureVault, evidence_id: UUID) -> list[HiddenValueOut]:
    _get_evidence(db, evidence_id)
    try:
        kinds = vault.kinds(evidence_id)
    except DisclosureError as error:
        raise _disclosure_error(error) from None
    return [HiddenValueOut(index=item.index, kind=item.kind) for item in kinds]


def request_disclosure(
    db: Db,
    write_audit: WriteAudit,
    operator: Operator,
    vault: DisclosureVault,
    evidence_id: UUID,
    index: int,
) -> Approval:
    """A PENDING `disclosure` approval for one value of one evidence."""
    evidence = _get_evidence(db, evidence_id)
    by_index = {item.index: item for item in list_hidden_values(db, vault, evidence_id)}
    if index not in by_index:
        raise _disclosure_error(DisclosureError("BAD_INDEX"))
    snapshot = {
        "evidence_id": str(evidence_id),
        "index": index,
        "kind": by_index[index].kind,
        "location": evidence.location,
    }
    approval = approval_repo.add(
        db,
        Approval(
            kind="disclosure",
            subject_snapshot=snapshot,
            subject_hash=snapshot_hash(snapshot),
            evidence_id=evidence_id,
        ),
    )
    db.commit()
    assessment_id = _assessment_id(db, evidence)
    audit(write_audit, "APPROVAL_REQUESTED", operator, assessment_id, _details(approval))
    return approval


def is_disclosure(approval: Approval) -> bool:
    return approval.kind == "disclosure"


def approve_disclosure(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval
) -> None:
    """Called from services/decisions.py, which has locked the approval. The value is
    not shown here: the person reveals it once with reveal_value()."""
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
    db.commit()
    audit(
        write_audit,
        "APPROVAL_GRANTED",
        operator,
        _approval_assessment(db, approval),
        _details(approval),
    )


def reject_disclosure(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str | None
) -> None:
    approval.approval_status = ApprovalStatus.REJECTED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
    approval.reason = reason
    db.commit()
    audit(
        write_audit,
        "APPROVAL_REJECTED",
        operator,
        _approval_assessment(db, approval),
        _details(approval),
    )


def reveal_value(
    db: Db,
    write_audit: WriteAudit,
    operator: Operator,
    vault: DisclosureVault,
    settings: Settings,
    evidence_id: UUID,
    approval_id: UUID,
) -> DisclosedValueOut:
    """The real value, once: an approved, unused, unexpired disclosure approval is used up.
    A refused reveal writes one DISCLOSURE_REFUSED audit line with the reason."""
    try:
        approval, hidden = _use_approval(db, vault, settings, evidence_id, approval_id)
    except ApiError as error:
        db.rollback()
        details = {
            "approval_id": str(approval_id),
            "evidence_id": str(evidence_id),
            "reason": error.code,
        }
        evidence = finding_repo.get_evidence(db, evidence_id)
        assessment_id = _assessment_id(db, evidence) if evidence is not None else None
        audit(write_audit, "DISCLOSURE_REFUSED", operator, assessment_id, details)
        raise
    # The audit line says what was shown, never the value itself.
    assessment_id = _approval_assessment(db, approval)
    audit(write_audit, "DISCLOSURE_SHOWN", operator, assessment_id, _details(approval))
    return DisclosedValueOut(
        evidence_id=evidence_id,
        approval_id=approval.approval_id,
        index=hidden.index,
        kind=hidden.kind,
        value=hidden.value,
    )


def _use_approval(
    db: Db, vault: DisclosureVault, settings: Settings, evidence_id: UUID, approval_id: UUID
) -> tuple[Approval, HiddenValue]:
    approval = approval_repo.get_for_update(db, approval_id)
    if approval is None or not is_disclosure(approval) or approval.evidence_id != evidence_id:
        raise ApiError(404, "APPROVAL_NOT_FOUND", "No disclosure approval with this id.")
    ensure_can_use(approval_state(approval, settings.approval_ttl_minutes), datetime.now(UTC))
    if snapshot_hash(approval.subject_snapshot) != approval.subject_hash:
        raise ApiError(409, "APPROVAL_CHANGED", "This approval was changed after it was asked.")
    try:
        hidden = vault.reveal(evidence_id, approval.subject_snapshot["index"])
    except DisclosureError as error:
        raise _disclosure_error(error) from None
    approval.consumed_at = datetime.now(UTC)
    db.commit()
    return approval, hidden


def _get_evidence(db: Db, evidence_id: UUID) -> Evidence:
    evidence = finding_repo.get_evidence(db, evidence_id)
    if evidence is None:
        raise ApiError(404, "EVIDENCE_NOT_FOUND", "No evidence with this id.")
    return evidence


def _assessment_id(db: Db, evidence: Evidence) -> UUID | None:
    if evidence.finding_id is None:
        return None
    finding = finding_repo.get(db, evidence.finding_id)
    return finding.assessment_id if finding is not None else None


def _approval_assessment(db: Db, approval: Approval) -> UUID | None:
    return _assessment_id(db, _get_evidence(db, approval.evidence_id))


def _details(approval: Approval) -> dict[str, object]:
    """Which value of which evidence: never the value."""
    return {
        "approval_id": str(approval.approval_id),
        "kind": approval.kind,
        "evidence_id": str(approval.evidence_id),
        "index": approval.subject_snapshot["index"],
        "value_kind": approval.subject_snapshot["kind"],
    }


def _disclosure_error(error: DisclosureError) -> ApiError:
    status, code, message = ERRORS.get(
        error.code, (409, "HIDDEN_VALUE_UNREADABLE", "The kept value cannot be read.")
    )
    return ApiError(status, code, message)
