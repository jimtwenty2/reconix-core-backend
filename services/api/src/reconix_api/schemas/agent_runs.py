"""Response shapes for /assessments/{id}/plan and /sessions/{id}/agent-runs."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.core.interfaces import BlockedStep, PlanStep
from reconix_api.models.enums import AgentRunStatus
from reconix_api.schemas.actions import ActionOut


class AgentRunOut(BaseModel):
    agent_run_id: UUID
    agent_runs_status: AgentRunStatus
    model_name: str
    plan: dict[str, Any] | None  # what the agent said; see PlanOut for a plan
    started_at: datetime
    finished_at: datetime | None
    session_id: UUID
    assessment_id: UUID | None


class PlanOut(BaseModel):
    """A plan and its first step.

    action is the step the agent suggested, after the API's own check: BLOCKED,
    run already (LOW), or waiting for the approval in action.approval_id.
    """

    agent_run: AgentRunOut
    text: str
    plan: list[PlanStep] = Field(default_factory=list)
    blocked: list[BlockedStep] = Field(default_factory=list)  # steps the agent's check refused
    action: ActionOut | None = None
