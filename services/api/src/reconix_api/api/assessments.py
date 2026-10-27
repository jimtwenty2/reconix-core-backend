"""Reading assessments."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.scopes import AssessmentOut
from reconix_api.services import scopes

router = APIRouter(prefix="/assessments", tags=["assessments"])


@router.get("/{assessment_id}")
def read_assessment(assessment_id: UUID, db: Db, _: CurrentOperator) -> AssessmentOut:
    return scopes.read_assessment(db, assessment_id)
