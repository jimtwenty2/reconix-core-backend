"""Reading the agent runs of a session."""

from uuid import UUID

from fastapi import APIRouter

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.agent_runs import AgentRunOut
from reconix_api.services import agent_runs

router = APIRouter(tags=["agent runs"])


@router.get("/sessions/{session_id}/agent-runs")
def list_agent_runs(session_id: UUID, db: Db, _: CurrentOperator) -> list[AgentRunOut]:
    """Newest first."""
    return agent_runs.list_for_session(db, session_id)
