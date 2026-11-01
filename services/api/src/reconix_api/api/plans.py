"""Asking the agent for a plan for an assessment, and for the next step."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.interfaces import AgentTask
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.agent_runs import PlanOut
from reconix_api.services import plans

router = APIRouter(tags=["plans"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/assessments/{assessment_id}/plan", status_code=status.HTTP_201_CREATED)
async def start_plan(
    assessment_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
    draft: bool = False,
) -> PlanOut:
    """The agent plans and suggests one step. The step goes through the same checks as
    any action: BLOCKED, run now (LOW), or wait for the approval in action.approval_id.
    With draft=true nothing is sent yet: the person reads the plan first, then sends it
    (POST /agent-runs/{id}/send) or drops it (POST /agent-runs/{id}/cancel)."""
    return await plans.start_plan(
        db, interfaces, mask, settings, operator, assessment_id, draft=draft
    )


@router.post("/assessments/{assessment_id}/next-step", status_code=status.HTTP_201_CREATED)
async def suggest_next_step(
    assessment_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> PlanOut:
    """After a step has run: the agent reads the newest tool outputs (masked), thinks
    again (ReflAct) and suggests the next step, which goes through the same checks as
    any action. 409 NO_TOOL_RESULTS before any tool has run."""
    return await plans.start_plan(
        db, interfaces, mask, settings, operator, assessment_id, task=AgentTask.SUGGEST
    )


@router.post("/agent-runs/{agent_run_id}/send")
async def send_plan(
    agent_run_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> PlanOut:
    """Send a drafted plan's first step, through the same checks as any action."""
    return await plans.send_draft(db, interfaces, mask, settings, operator, agent_run_id)
