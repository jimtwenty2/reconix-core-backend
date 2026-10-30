"""Findings: list, read and review."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks

from reconix_api.core.db import Db
from reconix_api.core.finding_memory import CurrentFindingMemory
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus
from reconix_api.schemas.findings import FindingOut, FindingReview
from reconix_api.services import findings

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
def list_findings(
    db: Db,
    _: CurrentOperator,
    assessment_id: UUID | None = None,
    severity_status: SeverityStatus | None = None,
    validation_status: ValidationStatus | None = None,
    finding_status: FindingStatus | None = None,
) -> list[FindingOut]:
    """Every finding newest first, or one assessment's with ?assessment_id= in the order
    they were found. Filter with ?severity_status=, ?validation_status= and
    ?finding_status=; each one given must match."""
    return findings.list_findings(
        db, assessment_id, severity_status, validation_status, finding_status
    )


@router.get("/{finding_id}")
def read_finding(finding_id: UUID, db: Db, _: CurrentOperator) -> FindingOut:
    return findings.read_finding(db, finding_id)


@router.patch("/{finding_id}")
def review_finding(
    finding_id: UUID,
    body: FindingReview,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    memory: CurrentFindingMemory,
    background: BackgroundTasks,
) -> FindingOut:
    """Mark a finding OPEN, FALSE_POSITIVE or FIXED. OPEN and FIXED are accepted, and the
    AI remembers them."""
    reviewed = findings.review_finding(db, interfaces.write_audit, operator, finding_id, body)
    # After the response: a slow memory never holds the person or a database connection.
    background.add_task(findings.update_memory, memory, reviewed)
    return reviewed
