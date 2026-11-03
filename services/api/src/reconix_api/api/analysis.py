"""Asking the agent to analyze an assessment's findings."""

from uuid import UUID

from fastapi import APIRouter, status

from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.agent_runs import AnalysisOut
from reconix_api.services import analysis

router = APIRouter(tags=["analysis"])


@router.post("/assessments/{assessment_id}/analyze", status_code=status.HTTP_201_CREATED)
async def analyze(
    assessment_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
) -> AnalysisOut:
    """Asks the agent for suggestions on each OPEN finding, 10 findings at a time. Nothing about a
    finding changes until a person accepts a suggestion with PATCH /findings/{id}."""
    return await analysis.analyze(db, interfaces, mask, operator, assessment_id)
