"""Database access for actions and tool_runs."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Action, AgentRun, Approval, ToolRun


def add(db: Db, row: Action | ToolRun | AgentRun) -> None:
    db.add(row)
    db.flush()


def get(db: Db, action_id: UUID) -> Action | None:
    return db.get(Action, action_id)


def get_for_update(db: Db, action_id: UUID) -> Action | None:
    """Locks the action until commit, so it cannot run twice at once."""
    return db.scalar(select(Action).where(Action.action_id == action_id).with_for_update())


def list_by_assessment(db: Db, assessment_id: UUID) -> list[Action]:
    query = (
        select(Action)
        .where(Action.assessment_id == assessment_id)
        .order_by(Action.created_at.desc())
    )
    return list(db.scalars(query))


def list_by_agent_run(db: Db, agent_run_id: UUID) -> list[Action]:
    query = select(Action).where(Action.agent_run_id == agent_run_id).order_by(Action.created_at)
    return list(db.scalars(query))


def approval_for(db: Db, action_id: UUID) -> Approval | None:
    """The newest approval for an action."""
    query = (
        select(Approval)
        .where(Approval.action_id == action_id)
        .order_by(Approval.requested_at.desc())
        .limit(1)
    )
    return db.scalar(query)


def list_tool_runs(db: Db, action_id: UUID) -> list[ToolRun]:
    query = select(ToolRun).where(ToolRun.action_id == action_id).order_by(ToolRun.attempt_no)
    return list(db.scalars(query))


def next_attempt_no(db: Db, action_id: UUID) -> int:
    latest = db.scalar(select(func.max(ToolRun.attempt_no)).where(ToolRun.action_id == action_id))
    return (latest or 0) + 1


def recent_runs(db: Db, assessment_id: UUID, since: datetime) -> list[tuple[Action, ToolRun]]:
    """Tool runs of this assessment that started after `since`, for the loop check."""
    query = (
        select(Action, ToolRun)
        .join(ToolRun, ToolRun.action_id == Action.action_id)
        .where(Action.assessment_id == assessment_id, ToolRun.started_at >= since)
        .order_by(ToolRun.started_at)
    )
    return [(action, run) for action, run in db.execute(query)]


def count_runs(db: Db, assessment_id: UUID) -> int:
    query = (
        select(func.count(ToolRun.tool_run_id))
        .join(Action, ToolRun.action_id == Action.action_id)
        .where(Action.assessment_id == assessment_id)
    )
    return db.scalar(query) or 0
