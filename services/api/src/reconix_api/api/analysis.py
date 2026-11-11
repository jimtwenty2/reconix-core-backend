"""Asking the agent to analyze an assessment's findings."""

from uuid import UUID

from fastapi import APIRouter, status

from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.agent_runs import AnalysisOut, AnalyzeIn
from reconix_api.services import analysis

router = APIRouter(tags=["analysis"])


@router.post("/assessments/{assessment_id}/analyze", status_code=status.HTTP_201_CREATED)
async def analyze(
    assessment_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    body: AnalyzeIn | None = None,
) -> AnalysisOut:
    """Analyzes the OPEN findings with the agent, 10 findings at a time.

    Business Rules:
    - body.finding_ids limits it to those findings (per-step analysis, as a step finds them);
      omitted, it analyzes every OPEN finding. 422 NO_FINDINGS when none match.
    - The agent's explanation, impact and remediation (and a CVSS score when missing) are
      written onto each finding; the review status stays a person's via PATCH /findings/{id}.

    Execution Behavior:
    - Calls the agent to analyze the findings and persists the analysis onto them.

    Security:
    - Requires a valid session token.
    """
    finding_ids = body.finding_ids if body else None
    return await analysis.analyze(db, interfaces, mask, operator, assessment_id, finding_ids)
