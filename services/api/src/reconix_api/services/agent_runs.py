"""Agent runs: one per plan, analysis or report the AI works on."""

from collections.abc import Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session as Db
from sqlalchemy.orm import sessionmaker

from reconix_api.core.agent import ProviderConfig, provider_config
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    AgentRequest,
    AgentResponse,
    Interfaces,
    OnPiece,
    Operator,
)
from reconix_api.models import AgentRun, LlmProvider
from reconix_api.models.enums import AgentRunStatus, ProviderType
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.agent_runs import AgentRunOut
from reconix_api.services.audit import audit


def new_agent_run(
    db: Db, operator: Operator, assessment_id: UUID | None, task: str | None = None
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


async def ask_agent(
    db: Db, interfaces: Interfaces, request: AgentRequest, on_piece: OnPiece | None = None
) -> AgentResponse:
    """Ask the agent with no transaction left open: a model call can take minutes, and
    the locks and the connection this request holds must not wait on it. on_piece gets
    a CHAT answer in masked pieces as it is written."""
    db.commit()
    if on_piece is None:
        return await interfaces.ask_agent(request)
    return await interfaces.ask_agent(request, on_piece=on_piece)


def make_provider_for_run(
    session_factory: sessionmaker[Db], settings: Settings
) -> Callable[[UUID], ProviderConfig]:
    """The model settings of the provider a run was started with, key decrypted, for the
    AI Service's model calls. Read on every ask, so a resume uses the same provider."""

    def provider_for_run(agent_run_id: UUID) -> ProviderConfig:
        with session_factory() as db:
            agent_run = agent_run_repo.get(db, agent_run_id)
            if agent_run is None:
                raise ApiError(404, "AGENT_RUN_NOT_FOUND", "The agent run does not exist.")
            provider = provider_repo.get(db, agent_run.llm_provider_id)
            return provider_config(settings, active_provider_of(provider), agent_run.model_name)

    return provider_for_run


def active_provider_of(provider: LlmProvider) -> LlmProvider:
    """Only the active row is locked against edits, and a cloud row becomes active only
    through an approval of its exact settings. A row that is no longer active may have
    been changed since, with no approval, so its settings are never used. The built-in
    RECONIX row never gives its settings: its address and model come from RECONIX_MODEL_*
    and only its key can be changed."""
    if provider.provider_type != ProviderType.RECONIX and not provider.is_active:
        raise ApiError(
            409,
            "PROVIDER_CHANGED",
            "The AI provider this run started with is no longer active. Start a new run.",
        )
    return provider


def agent_provider(db: Db, agent_run: AgentRun) -> tuple[str, str | None]:
    """The provider type and model the run was started with, for its AgentRequest, so
    the run records the model that is really called. The built-in RECONIX provider sends
    no model: the agent uses its own."""
    provider = provider_repo.get(db, agent_run.llm_provider_id)
    if provider.provider_type == ProviderType.RECONIX:
        return ProviderType.RECONIX.value, None
    return provider.provider_type.value, agent_run.model_name


def finish(agent_run: AgentRun, status: AgentRunStatus) -> None:
    agent_run.agent_runs_status = status
    agent_run.finished_at = datetime.now(UTC)


def end(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    agent_run: AgentRun,
    status: AgentRunStatus,
    details: dict[str, str],
) -> None:
    """Ends a run and writes its one audit line, e.g. AGENT_RUN_COMPLETED."""
    finish(agent_run, status)
    db.commit()
    audit(
        interfaces.write_audit,
        f"AGENT_RUN_{status}",
        operator,
        agent_run.assessment_id,
        {"agent_run_id": str(agent_run.agent_run_id), **details},
    )


def fail(
    db: Db, interfaces: Interfaces, operator: Operator, agent_run: AgentRun, error: Exception
) -> None:
    """Any error ends the run FAILED, so no run is left RUNNING. A run that has already
    ended keeps its end and its one audit line (e.g. the audit write after it failed)."""
    db.rollback()
    if agent_run.finished_at is not None:
        return
    code = error.code if isinstance(error, ApiError) else "UNEXPECTED_ERROR"
    end(db, interfaces, operator, agent_run, AgentRunStatus.FAILED, {"code": code})


def list_for_session(db: Db, session_id: UUID) -> list[AgentRunOut]:
    if session_repo.get(db, session_id) is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    return [agent_run_out(run) for run in agent_run_repo.list_by_session(db, session_id)]


def agent_run_out(agent_run: AgentRun) -> AgentRunOut:
    return AgentRunOut.model_validate(agent_run, from_attributes=True)
