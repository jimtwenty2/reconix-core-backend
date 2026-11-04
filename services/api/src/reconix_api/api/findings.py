"""Findings: list, read and review."""

from uuid import UUID

from fastapi import APIRouter, BackgroundTasks, Query, status

from reconix_api.core.db import Db
from reconix_api.core.finding_memory import CurrentFindingMemory
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
    tool: str | None = Query(default=None, max_length=100),
    target: str | None = Query(default=None, max_length=200),
    q: str | None = Query(default=None, max_length=200),
) -> list[FindingOut]:
    """Lists the findings, newest first.

    Business Rules:
    - With ?assessment_id=, lists only that assessment's findings, in the order they were found.
    - Filter with ?severity_status=, ?validation_status=, ?finding_status=, ?tool= (a Kali
      catalog tool that found it, in any case), ?target= (part of the target), and ?q= (part
      of the code, title, target, description, or a CWE id).
    - Every filter you provide must match.
    - A ?tool= that is not in the Kali catalog returns 422 UNKNOWN_TOOL.

    Security:
    - Requires a valid session token.
    """
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
    """Returns one finding with its severity, CVSS score, CWE and CVE ids, remediation, and review
    status.

    Business Rules:
    - Returns 404 FINDING_NOT_FOUND if no finding has this id.

    Security:
    - Requires a valid session token.
    """
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
    """Marks a finding OPEN, FALSE_POSITIVE, or FIXED.

    Business Rules:
    - OPEN and FIXED count as accepted.

    Execution Behavior:
    - Records accepted findings in the AI's memory for later.

    State Changes:
    - Updates the finding's review status.

    Security:
    - Requires a valid session token.
    """
    reviewed = findings.review_finding(db, interfaces.write_audit, operator, finding_id, body)
    # After the response: a slow memory never holds the person or a database connection.
    background.add_task(findings.update_memory, memory, reviewed)
    return reviewed


@router.post("/{finding_id}/validation-runs", status_code=status.HTTP_201_CREATED)
async def check_finding(
    finding_id: UUID,
    body: ValidationRunIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
) -> ValidationRunOut:
    """Confirms a finding with a proof of concept.

    Business Rules:
    - Provide the id of a COMPLETED tool run.
    - The finding takes the newest result as its validation_status; no one sets the verdict by hand.

    Execution Behavior:
    - The AI reads the tool run's real output and sets the verdict (CONFIRMED, UNCONFIRMED, or
      INCONCLUSIVE).

    State Changes:
    - Creates a validation run and updates the finding's validation_status.

    Security:
    - Requires a valid session token.
    """
    return await findings.check_finding(db, interfaces, mask, operator, finding_id, body)


@router.get("/{finding_id}/validation-runs")
def list_validation_runs(finding_id: UUID, db: Db, _: CurrentOperator) -> list[ValidationRunOut]:
    """Lists every check of the finding, newest first.

    Security:
    - Requires a valid session token.
    """
    return findings.list_validation_runs(db, finding_id)
