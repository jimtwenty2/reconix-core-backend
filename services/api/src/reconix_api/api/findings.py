"""Findings: list, read and review."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Query, status

from reconix_api.core.db import Db
from reconix_api.core.finding_memory import CurrentFindingMemory
from reconix_api.core.interfaces import ToolName
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus
from reconix_api.schemas.findings import (
    FindingFilters,
    FindingOut,
    FindingReview,
    ValidationRunIn,
    ValidationRunOut,
)
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
    tool: ToolName | None = None,
    target: str | None = Query(default=None, max_length=200),
    q: str | None = Query(default=None, max_length=200),
) -> list[FindingOut]:
    """Every finding newest first, or one assessment's with ?assessment_id= in the order
    they were found. Filter with ?severity_status=, ?validation_status=,
    ?finding_status=, ?tool= (a tool that found it), ?target= (part of the target) and
    ?q= (part of the code, title, target, description or a CWE id); each one given must
    match."""
    filters = FindingFilters(
        assessment_id=assessment_id,
        severity_status=severity_status,
        validation_status=validation_status,
        finding_status=finding_status,
        tool=tool,
        target=target,
        q=q,
    )
    return findings.list_findings(db, filters)


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


@router.post("/{finding_id}/validation-runs", status_code=status.HTTP_201_CREATED)
def check_finding(
    finding_id: UUID,
    body: ValidationRunIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
) -> ValidationRunOut:
    """A person's own check: CONFIRMED, UNCONFIRMED or INCONCLUSIVE, with what was checked.
    The finding takes this newest result as its validation_status."""
    return findings.check_finding(db, interfaces.write_audit, mask, operator, finding_id, body)


@router.get("/{finding_id}/validation-runs")
def list_validation_runs(finding_id: UUID, db: Db, _: CurrentOperator) -> list[ValidationRunOut]:
    """Every check of the finding, newest first."""
    return findings.list_validation_runs(db, finding_id)
