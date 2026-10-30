"""Agent runs: one per plan, analysis or report the AI works on."""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator
from reconix_api.models import AgentRun
from reconix_api.models.enums import AgentRunStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.agent_runs import AgentRunOut


def new_agent_run(
    db: Db, operator: Operator, assessment_id: UUID, task: str | None = None
) -> AgentRun:
    """A RUNNING run with the active provider. task marks a plan, analysis or report run
    (plan = {"task": ...}); a run without one is shared by a person's actions. The
    caller commits."""
    provider = agent_run_repo.active_provider(db)
    if provider is None:
        raise ApiError(503, "NO_ACTIVE_PROVIDER", "No AI provider is active.")
    agent_run = AgentRun(
        model_name=provider.model_name,
        session_id=operator.session_id,
        assessment_id=assessment_id,
        llm_provider_id=provider.llm_provider_id,
        plan={"task": task} if task else None,
    )
    agent_run_repo.add(db, agent_run)
    return agent_run


def finish(agent_run: AgentRun, status: AgentRunStatus) -> None:
    agent_run.agent_runs_status = status
    agent_run.finished_at = datetime.now(UTC)


def list_for_session(db: Db, session_id: UUID) -> list[AgentRunOut]:
    if session_repo.get(db, session_id) is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    return [agent_run_out(run) for run in agent_run_repo.list_by_session(db, session_id)]


def agent_run_out(agent_run: AgentRun) -> AgentRunOut:
    return AgentRunOut.model_validate(agent_run, from_attributes=True)
