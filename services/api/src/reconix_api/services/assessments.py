"""Assessments: list, read, rename or complete, and cancel."""

from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.models import Assessment
from reconix_api.models.enums import AssessmentStatus
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.schemas.scopes import AssessmentOut, AssessmentUpdate
from reconix_api.services.audit import audit

FINISHED = (AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLED)


def list_assessments(db: Db, status: AssessmentStatus | None) -> list[AssessmentOut]:
    return [_out(row) for row in assessment_repo.list_all(db, status)]


def update_assessment(
    db: Db, write_audit: WriteAudit, operator: Operator, assessment_id: UUID, body: AssessmentUpdate
) -> AssessmentOut:
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    assessment = _get_open(db, assessment_id)
    if "assessment_status" in changes and assessment.assessment_status != AssessmentStatus.ACTIVE:
        raise ApiError(409, "ASSESSMENT_NOT_ACTIVE", "Only an ACTIVE assessment can be completed.")
    for field, value in changes.items():
        setattr(assessment, field, value)
    db.commit()
    audit(write_audit, "ASSESSMENT_UPDATED", operator, assessment_id, {"fields": sorted(changes)})
    return _out(assessment)


def cancel_assessment(
    db: Db, write_audit: WriteAudit, operator: Operator, assessment_id: UUID
) -> AssessmentOut:
    """Cancelled, never erased: its actions, findings and audit lines stay."""
    assessment = _get_open(db, assessment_id)
    assessment.assessment_status = AssessmentStatus.CANCELLED
    db.commit()
    audit(write_audit, "ASSESSMENT_CANCELLED", operator, assessment_id)
    return _out(assessment)


def _get_open(db: Db, assessment_id: UUID) -> Assessment:
    assessment = assessment_repo.get_for_update(db, assessment_id)
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    if assessment.assessment_status in FINISHED:
        raise ApiError(
            409,
            "ASSESSMENT_FINISHED",
            "This assessment is already completed or cancelled.",
            {"assessment_status": assessment.assessment_status},
        )
    return assessment


def _out(assessment: Assessment) -> AssessmentOut:
    return AssessmentOut.model_validate(assessment, from_attributes=True)
