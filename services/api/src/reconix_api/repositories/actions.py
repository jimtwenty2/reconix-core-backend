"""Database access for actions and tool_runs."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Row, func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Action, AgentRun, Approval, ToolRun
from reconix_api.models.enums import ActionStatus


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


def tool_runs_in_assessment(db: Db, assessment_id: UUID) -> list[tuple[ToolRun, Action]]:
    """Every tool run of the assessment with its action, oldest first."""
    query = (
        select(ToolRun, Action)
        .join(Action, ToolRun.action_id == Action.action_id)
        .where(Action.assessment_id == assessment_id)
        .order_by(ToolRun.started_at.nulls_last(), ToolRun.tool_run_id)
    )
    return [(run, action) for run, action in db.execute(query)]


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


def count_by_status(db: Db, assessment_id: UUID) -> dict[ActionStatus, int]:
    query = (
        select(Action.action_status, func.count())
        .where(Action.assessment_id == assessment_id)
        .group_by(Action.action_status)
    )
    return {row[0]: row[1] for row in db.execute(query)}


def tool_run_totals(db: Db, assessment_id: UUID) -> Row:
    """One row: tool_run_count, request_count, masked_count, first_started_at, last_finished_at."""
    query = (
        select(
            func.count(ToolRun.tool_run_id).label("tool_run_count"),
            func.coalesce(func.sum(ToolRun.request_count), 0).label("request_count"),
            func.coalesce(func.sum(ToolRun.masked_count), 0).label("masked_count"),
            func.min(ToolRun.started_at).label("first_started_at"),
            func.max(ToolRun.finished_at).label("last_finished_at"),
        )
        .join(Action, ToolRun.action_id == Action.action_id)
        .where(Action.assessment_id == assessment_id)
    )
    return db.execute(query).one()
