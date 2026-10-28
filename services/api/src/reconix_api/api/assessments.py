"""Assessments: list, read, rename or complete, and cancel."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.models.enums import AssessmentStatus
from reconix_api.schemas.scopes import AssessmentOut, AssessmentUpdate
from reconix_api.services import assessments, scopes

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("")
def list_assessments(
    db: Db, _: CurrentOperator, status: AssessmentStatus | None = None
) -> list[AssessmentOut]:
    return assessments.list_assessments(db, status)


@router.get("/{assessment_id}")
def read_assessment(assessment_id: UUID, db: Db, _: CurrentOperator) -> AssessmentOut:
    return scopes.read_assessment(db, assessment_id)


@router.patch("/{assessment_id}")
def update_assessment(
    assessment_id: UUID,
    body: AssessmentUpdate,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
) -> AssessmentOut:
    """Rename it, or set assessment_status to COMPLETED when the work is done."""
    return assessments.update_assessment(db, interfaces.write_audit, operator, assessment_id, body)


@router.delete("/{assessment_id}")
def cancel_assessment(
    assessment_id: UUID, db: Db, operator: RequireOperator, interfaces: CurrentInterfaces
) -> AssessmentOut:
    """Cancels the assessment (status CANCELLED). Nothing is erased."""
    return assessments.cancel_assessment(db, interfaces.write_audit, operator, assessment_id)
