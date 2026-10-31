"""Assessments: list, read, rename or complete, and cancel; and the overview."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.models.enums import AssessmentStatus
from reconix_api.schemas.assessments import AssessmentOverviewOut, AssessmentRowOut
from reconix_api.schemas.scopes import AssessmentOut, AssessmentUpdate
from reconix_api.services import assessments, scopes

router = APIRouter(prefix="/assessments", tags=["assessments"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.get("")
def list_assessments(
    db: Db, _: CurrentOperator, settings: CurrentSettings, status: AssessmentStatus | None = None
) -> list[AssessmentRowOut]:
    """Newest first, each with its approved targets, finding count, worst severity and
    pending approvals. False positives are left out of the count and the severity."""
    return assessments.list_assessments(db, status, settings.approval_ttl_minutes)


@router.get("/{assessment_id}")
def read_assessment(assessment_id: UUID, db: Db, _: CurrentOperator) -> AssessmentOut:
    return scopes.read_assessment(db, assessment_id)


@router.get("/{assessment_id}/overview")
def read_overview(
    assessment_id: UUID, db: Db, _: CurrentOperator, settings: CurrentSettings
) -> AssessmentOverviewOut:
    """The run overview's counts in one call: findings by severity, validation and status,
    actions by status, plan progress, tool run totals and pending approvals. Only
    findings_by_status counts false positives; the other finding counts leave them out."""
    return assessments.overview(db, assessment_id, settings.approval_ttl_minutes)


@router.patch("/{assessment_id}")
def update_assessment(
    assessment_id: UUID,
    body: AssessmentUpdate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
) -> AssessmentOut:
    """Rename it, or set assessment_status to COMPLETED when the work is done."""
    return assessments.update_assessment(db, interfaces.write_audit, operator, assessment_id, body)


@router.delete("/{assessment_id}")
def cancel_assessment(
    assessment_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> AssessmentOut:
    """Cancels the assessment (status CANCELLED). Nothing is erased."""
    return assessments.cancel_assessment(db, interfaces.write_audit, operator, assessment_id)
