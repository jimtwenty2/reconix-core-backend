"""Assessments: list, read, rename or complete, and cancel; and the overview."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

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
    db: Db,
    _: CurrentOperator,
    settings: CurrentSettings,
    status: AssessmentStatus | None = None,
    type: Annotated[str | None, Query(max_length=60)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
) -> list[AssessmentRowOut]:
    """Lists the assessments, newest first.

    Business Rules:
    - Each row includes its approved targets, finding count, worst severity, pending
      approvals, plan progress, and the time of its last activity.
    - False positives are excluded from the finding count and the worst severity.
    - Filter with `status` and `type` (for example `web_url`), and search with `q`: it
      matches the engagement code, the name, or a target, ignoring case.

    Security:
    - Requires a valid session token.
    """
    return assessments.list_assessments(db, status, settings.approval_ttl_minutes, type, q)


@router.get("/{assessment_id}")
def read_assessment(assessment_id: UUID, db: Db, _: CurrentOperator) -> AssessmentOut:
    """Returns one assessment with its name, type, and status.

    Business Rules:
    - Returns 404 ASSESSMENT_NOT_FOUND if no assessment has this id.

    Security:
    - Requires a valid session token.
    """
    return scopes.read_assessment(db, assessment_id)


@router.get("/{assessment_id}/overview")
def read_overview(
    assessment_id: UUID, db: Db, _: CurrentOperator, settings: CurrentSettings
) -> AssessmentOverviewOut:
    """Returns the counts for the run overview in one call: findings by severity, validation, and
    status; actions by status; plan progress; tool run totals; and pending approvals.

    Business Rules:
    - Only findings_by_status counts false positives; the other finding counts exclude them.

    Security:
    - Requires a valid session token.
    """
    return assessments.overview(db, assessment_id, settings.approval_ttl_minutes)


@router.patch("/{assessment_id}")
def update_assessment(
    assessment_id: UUID,
    body: AssessmentUpdate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
) -> AssessmentOut:
    """Renames the assessment, or marks it COMPLETED when the work is done.

    Business Rules:
    - Set assessment_status to COMPLETED to complete the assessment.

    State Changes:
    - Updates the assessment's name or status.

    Security:
    - Requires a valid session token.
    """
    return assessments.update_assessment(db, interfaces.write_audit, operator, assessment_id, body)


@router.delete("/{assessment_id}")
def cancel_assessment(
    assessment_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> AssessmentOut:
    """Cancels the assessment.

    State Changes:
    - Sets the assessment status to CANCELLED. Nothing is erased.

    Security:
    - Requires a valid session token.
    """
    return assessments.cancel_assessment(db, interfaces.write_audit, operator, assessment_id)
