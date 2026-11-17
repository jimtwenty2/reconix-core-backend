"""Database access for tool_runs: the run an agent run waited on, and its action."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Action, ToolRun
from reconix_api.models.enums import ActionStatus, ToolRunStatus


def latest_finished(db: Db, agent_run_id: UUID) -> tuple[ToolRun, Action] | None:
    """The newest tool run of the actions of one agent run, with its action: the step a
    plan run finished. None when that run has started no tool run."""
    query = (
        select(ToolRun, Action)
        .join(Action, Action.action_id == ToolRun.action_id)
        .where(Action.agent_run_id == agent_run_id)
        .order_by(ToolRun.started_at.desc(), ToolRun.tool_run_id.desc())
        .limit(1)
    )
    row = db.execute(query).first()
    return (row[0], row[1]) if row is not None else None


def completed_step(db: Db, tool_run_id: UUID) -> tuple[ToolRun, Action] | None:
    """The run with its action, only when the run COMPLETED and its action did: a validation
    judges findings from a step that really succeeded."""
    query = (
        select(ToolRun, Action)
        .join(Action, Action.action_id == ToolRun.action_id)
        .where(
            ToolRun.tool_run_id == tool_run_id,
            ToolRun.tool_run_status == ToolRunStatus.COMPLETED,
            Action.action_status == ActionStatus.COMPLETED,
        )
    )
    row = db.execute(query).first()
    return (row[0], row[1]) if row is not None else None
