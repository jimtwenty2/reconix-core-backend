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
    """Lists the agent's runs in this session, newest first."""
    return agent_runs.list_for_session(db, session_id)


@router.get("/agent-runs/{agent_run_id}")
def read_agent_run(agent_run_id: UUID, db: Db, _: CurrentOperator) -> AgentRunDetailOut:
    """Returns one agent run and the actions filed under it, for example the step a plan suggested
    and where that step is now."""
    return actions.read_agent_run(db, agent_run_id)


@router.post("/agent-runs/{agent_run_id}/cancel")
def cancel_agent_run(
    agent_run_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> AgentRunOut:
    """Stops a plan or next-step run that is waiting for a person. Its step becomes CANCELLED and
    can never run. Returns 409 while the agent is still answering, or if the run has already
    ended."""
    return plans.cancel_run(db, interfaces, operator, agent_run_id)
