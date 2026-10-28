"""Reading the findings of an assessment."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.findings import FindingOut
from reconix_api.services import findings

router = APIRouter(tags=["findings"])


@router.get("/assessments/{assessment_id}/findings")
def list_findings(assessment_id: UUID, db: Db, _: CurrentOperator) -> list[FindingOut]:
    return findings.list_findings(db, assessment_id)
