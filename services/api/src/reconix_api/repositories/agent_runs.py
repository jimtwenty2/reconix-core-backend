"""Database access for agent_runs and the provider a new run uses.

A plan's run is marked at creation with plan = {"task": "PLAN"}; a run with no plan is
the one a person's own actions share.
"""

from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session as Db

from reconix_api.models import AgentRun, LlmProvider
from reconix_api.models.enums import AgentRunStatus


def add(db: Db, agent_run: AgentRun) -> None:
    db.add(agent_run)
    db.flush()


def get(db: Db, agent_run_id: UUID) -> AgentRun | None:
    return db.get(AgentRun, agent_run_id)


def list_by_session(db: Db, session_id: UUID) -> list[AgentRun]:
    query = (
        select(AgentRun)
        .where(AgentRun.session_id == session_id)
        .order_by(AgentRun.started_at.desc())
    )
    return list(db.scalars(query))


def person_run(db: Db, assessment_id: UUID, session_id: UUID) -> AgentRun | None:
    """The RUNNING run one session's own actions on an assessment share: the newest one
    with no plan. Per session, so an action is never filed under another session's run."""
    query = (
        select(AgentRun)
        .where(
            AgentRun.assessment_id == assessment_id,
            AgentRun.session_id == session_id,
            AgentRun.agent_runs_status == AgentRunStatus.RUNNING,
            AgentRun.plan.is_(None),
        )
        .order_by(AgentRun.started_at.desc())
        .limit(1)
    )
    return db.scalar(query)


def open_plan_runs(db: Db, assessment_id: UUID) -> list[AgentRun]:
    """Plan and next-step runs still asking the agent (RUNNING) or waiting for a person."""
    query = (
        select(AgentRun)
        .where(
            AgentRun.assessment_id == assessment_id,
            AgentRun.plan["task"].astext.in_(["PLAN", "SUGGEST"]),
            AgentRun.agent_runs_status.in_(
                [AgentRunStatus.RUNNING, AgentRunStatus.WAITING_APPROVAL]
            ),
        )
        .order_by(AgentRun.started_at.desc())
    )
    return list(db.scalars(query))


def running_chat(db: Db, session_id: UUID) -> AgentRun | None:
    """A CHAT run of this session still asking the agent."""
    query = select(AgentRun).where(
        AgentRun.session_id == session_id,
        AgentRun.plan["task"].astext == "CHAT",
        AgentRun.agent_runs_status == AgentRunStatus.RUNNING,
    )
    return db.scalar(query.limit(1))


def latest_plan(db: Db, assessment_id: UUID) -> AgentRun | None:
    """The newest PLAN run that has its plan saved, whatever its status, except a draft
    that was cancelled before it was sent. Analysis runs keep their answer in `plan` too
    ({"task": "ANALYZE"}), so the task is checked."""
    dropped_draft = (AgentRun.agent_runs_status == AgentRunStatus.CANCELLED) & func.coalesce(
        AgentRun.plan["draft"].as_boolean(), False
    )
    query = (
        select(AgentRun)
        .where(
            AgentRun.assessment_id == assessment_id,
            AgentRun.plan["task"].astext == "PLAN",
            AgentRun.plan.has_key("steps"),
            ~dropped_draft,
        )
        .order_by(AgentRun.started_at.desc())
        .limit(1)
    )
    return db.scalar(query)


def get_for_update(db: Db, agent_run_id: UUID) -> AgentRun | None:
    query = select(AgentRun).where(AgentRun.agent_run_id == agent_run_id).with_for_update()
    return db.scalar(query.execution_options(populate_existing=True))


def claim_waiting(db: Db, agent_run_id: UUID) -> bool:
    """WAITING_APPROVAL -> RUNNING in one statement. Only one caller gets True, so a
    decision is handed to the agent exactly once."""
    result = db.execute(
        update(AgentRun)
        .where(
            AgentRun.agent_run_id == agent_run_id,
            AgentRun.agent_runs_status == AgentRunStatus.WAITING_APPROVAL,
        )
        .values(agent_runs_status=AgentRunStatus.RUNNING)
        .execution_options(synchronize_session="fetch")
    )
    db.commit()
    return result.rowcount == 1


def active_provider(db: Db) -> LlmProvider | None:
    return db.scalar(select(LlmProvider).where(LlmProvider.is_active))
