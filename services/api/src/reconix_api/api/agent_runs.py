"""Agent runs: a session's runs, one run with its actions, and stopping a waiting run."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.agent_runs import AgentRunDetailOut, AgentRunOut
from reconix_api.services import actions, agent_runs, plans

router = APIRouter(tags=["agent runs"])


@router.get("/sessions/{session_id}/agent-runs")
def list_agent_runs(session_id: UUID, db: Db, _: CurrentOperator) -> list[AgentRunOut]:
    """Newest first."""
    return agent_runs.list_for_session(db, session_id)


@router.get("/agent-runs/{agent_run_id}")
def read_agent_run(agent_run_id: UUID, db: Db, _: CurrentOperator) -> AgentRunDetailOut:
    """The run and the actions filed under it, e.g. a plan's suggested step and its status."""
    return actions.read_agent_run(db, agent_run_id)


@router.post("/agent-runs/{agent_run_id}/cancel")
def cancel_agent_run(
    agent_run_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> AgentRunOut:
    """Stop a plan or next-step run that waits for a person: its step is CANCELLED and
    can never run. 409 while the agent is still answering, or when the run has ended."""
    return plans.cancel_run(db, interfaces, operator, agent_run_id)
