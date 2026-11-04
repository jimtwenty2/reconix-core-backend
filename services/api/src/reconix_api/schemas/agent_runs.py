"""Response shapes for /assessments/{id}/plan, /assessments/{id}/analyze and
/sessions/{id}/agent-runs."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.core.interfaces import BlockedStep, FindingAnalysis, PlanStep
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


class AgentRunDetailOut(AgentRunOut):
    """A run and the actions filed under it: a plan or next-step run files its one
    suggested step, so actions[0] shows that step's status."""

    actions: list[ActionOut] = Field(default_factory=list)


class PlanOut(BaseModel):
    """A plan and its first step.

    action is the step the agent suggested, after the API's own check: BLOCKED,
    run already (LOW), or waiting for the approval in action.approval_id.
    A draft has no action yet: nothing was sent until a person sends it with
    POST /agent-runs/{id}/send (or drops it with POST /agent-runs/{id}/cancel).
    """

    agent_run: AgentRunOut
    text: str
    plan: list[PlanStep] = Field(default_factory=list)
    blocked: list[BlockedStep] = Field(default_factory=list)  # steps the agent's check refused
    action: ActionOut | None = None
    draft: bool = False


class AnalysisOut(BaseModel):
    """The agent's suggestions for each OPEN finding. Nothing here changes a finding: a
    person accepts a suggestion with PATCH /findings/{id}. A next_step is a validation
    step: send it to POST /assessments/{id}/actions with purpose "validation", where it
    is checked and waits for an approval like any MEDIUM action."""

    agent_run: AgentRunOut
    summary: str
    analysis: list[FindingAnalysis] = Field(default_factory=list)
