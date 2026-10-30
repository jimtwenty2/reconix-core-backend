"""Findings: list, read and review."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.schemas.findings import FindingOut, FindingReview
from reconix_api.services import findings

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get("")
def list_findings(
    db: Db, _: CurrentOperator, assessment_id: UUID | None = None
) -> list[FindingOut]:
    """Every finding, or only one assessment's with ?assessment_id=."""
    return findings.list_findings(db, assessment_id)


@router.get("/{finding_id}")
def read_finding(finding_id: UUID, db: Db, _: CurrentOperator) -> FindingOut:
    return findings.read_finding(db, finding_id)


@router.patch("/{finding_id}")
def review_finding(
    finding_id: UUID,
    body: FindingReview,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
) -> FindingOut:
    """Mark a finding OPEN, FALSE_POSITIVE or FIXED."""
    return findings.review_finding(db, interfaces.write_audit, operator, finding_id, body)
