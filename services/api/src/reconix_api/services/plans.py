"""Plans: ask the agent for a plan, then put its first step through the API's own path.

A plan asked for as a draft keeps its first step until a person sends it
(send_draft) or discards it (discard_draft); until then the run is
WAITING_APPROVAL with plan["draft"] set, and nothing has been sent or run. A new
plan cancels a draft that was never sent.

The agent only suggests. Its step becomes an action through actions.send_action,
filed under the plan's own run, so the API runs check() again (S2) and keeps its
own approval rules: BLOCKED is refused, LOW runs now, MEDIUM and HIGH wait for a
person. While a person decides, the run is WAITING_APPROVAL; the decision is handed
back to the agent exactly once (claim_waiting), and the run is COMPLETED.

One plan per assessment is open at a time. A run ends COMPLETED, FAILED or
CANCELLED, and each end writes one audit line.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentTask,
    ApprovedScope,
    BlockedStep,
    ChatMessage,
    Interfaces,
    Operator,
    PlanStep,
    ResumeInput,
)
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Action as ActionRow
from reconix_api.models import AgentRun, Approval
from reconix_api.models.enums import AgentRunStatus, ApprovalStatus
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import messages as message_repo
from reconix_api.schemas.actions import ActionIn, ActionOut
from reconix_api.schemas.agent_runs import PlanOut
from reconix_api.services import actions, agent_runs
from reconix_api.services.approvals import expires_at
from reconix_api.services.audit import audit

Decision = Literal["APPROVED", "REJECTED"]
STALE_MINUTES = 10  # a plan still RUNNING after this was cut off (e.g. the API stopped)


async def start_plan(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    assessment_id: UUID,
    draft: bool = False,
) -> PlanOut:
    actions.ensure_can_act(db, assessment_id)
    await settle_waiting_run(db, interfaces, operator, assessment_id, settings)
    scope = approved_scope(interfaces, assessment_id)
    run = open_plan_run(db, interfaces, operator, assessment_id)
    try:
        return await plan_and_send(db, interfaces, mask, settings, operator, run, scope, draft)
    except Exception as error:
        agent_runs.fail(db, interfaces, operator, run, error)
        raise


async def plan_and_send(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    run: AgentRun,
    scope: ApprovedScope,
    draft: bool = False,
) -> PlanOut:
    provider, model = agent_runs.agent_provider(db, run)
    request = AgentRequest(
        task=AgentTask.PLAN,
        assessment_id=run.assessment_id,
        agent_run_id=run.agent_run_id,
        provider=provider,
        model=model,
        scope=scope,
        messages=chat(db, operator.session_id),
    )
    response = await agent_runs.ask_agent(db, interfaces, request)
    text = mask(response.text)[0]
    plan = [masked_step(mask, step) for step in response.plan]
    step = response.proposed_action
    keep = draft and step is not None  # a draft with nothing to send has nothing to keep
    run.plan = {
        "task": "PLAN",
        "text": text,
        "steps": [step.model_dump(mode="json") for step in plan],
        "blocked": [step.model_dump(mode="json") for step in response.blocked],
        "draft": keep,
        "proposed_action": step.model_dump(mode="json") if keep else None,
    }
    run.checkpoint_id = response.checkpoint_id
    if keep:
        run.agent_runs_status = AgentRunStatus.WAITING_APPROVAL
    db.commit()
    audit(
        interfaces.write_audit,
        "PLAN_CREATED",
        operator,
        run.assessment_id,
        {"agent_run_id": str(run.agent_run_id), "steps": len(plan), "draft": keep},
    )
    if keep:
        return PlanOut(
            agent_run=agent_runs.agent_run_out(run),
            text=text,
            plan=plan,
            blocked=response.blocked,
            draft=True,
        )
    action = None
    if step is not None:
        action = await send_suggested_step(db, interfaces, mask, settings, operator, run, step)
    return finish_send(db, interfaces, operator, run, plan, response.blocked, action)


def finish_send(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    run: AgentRun,
    plan: list[PlanStep],
    blocked: list[BlockedStep],
    action: ActionOut | None,
) -> PlanOut:
    """After the first step was sent: wait for its approval, or end the run."""
    if action is not None and action.approval_id is not None:
        run.agent_runs_status = AgentRunStatus.WAITING_APPROVAL
        db.commit()
    else:
        # Nothing to decide: no step, the API blocked it, or it was LOW and ran.
        agent_runs.end(
            db, interfaces, operator, run, AgentRunStatus.COMPLETED, {"step": step_note(action)}
        )
    return PlanOut(
        agent_run=agent_runs.agent_run_out(run),
        text=run.plan["text"],
        plan=plan,
        blocked=blocked,
        action=action,
    )


def masked_step(mask: MaskSecrets, step: PlanStep) -> PlanStep:
    return step.model_copy(update={"title": mask(step.title)[0], "reason": mask(step.reason)[0]})


async def send_draft(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    agent_run_id: UUID,
) -> PlanOut:
    """A person sends a drafted plan's first step. It goes through send_action like any
    step: the API's own check(), then BLOCKED, run now (LOW) or wait for an approval."""
    run = draft_run(db, agent_run_id)
    actions.ensure_can_act(db, run.assessment_id)
    if not agent_run_repo.claim_waiting(db, run.agent_run_id):
        raise ApiError(409, "PLAN_NOT_DRAFT", "This plan was already sent or discarded.")
    step = Action(**run.plan["proposed_action"])
    run.plan = {**run.plan, "draft": False}
    db.commit()
    audit(
        interfaces.write_audit,
        "PLAN_SENT",
        operator,
        run.assessment_id,
        {"agent_run_id": str(run.agent_run_id)},
    )
    try:
        action = await send_suggested_step(db, interfaces, mask, settings, operator, run, step)
        plan = [PlanStep(**row) for row in run.plan["steps"]]
        blocked = [BlockedStep(**row) for row in run.plan["blocked"]]
        return finish_send(db, interfaces, operator, run, plan, blocked, action)
    except Exception as error:
        agent_runs.fail(db, interfaces, operator, run, error)
        raise


def discard_draft(db: Db, interfaces: Interfaces, operator: Operator, agent_run_id: UUID) -> None:
    """A person drops a drafted plan. Nothing was sent, so nothing else changes."""
    run = draft_run(db, agent_run_id)
    if not agent_run_repo.claim_waiting(db, run.agent_run_id):
        raise ApiError(409, "PLAN_NOT_DRAFT", "This plan was already sent or discarded.")
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.CANCELLED, {"reason": "DISCARDED"})


def draft_run(db: Db, agent_run_id: UUID) -> AgentRun:
    run = agent_run_repo.get(db, agent_run_id)
    if run is None:
        raise ApiError(404, "RUN_NOT_FOUND", "No agent run with this id.")
    plan = run.plan or {}
    waiting = run.agent_runs_status == AgentRunStatus.WAITING_APPROVAL
    if plan.get("task") != "PLAN" or not plan.get("draft") or not waiting:
        raise ApiError(409, "PLAN_NOT_DRAFT", "This run is not a plan waiting to be sent.")
    return run


async def send_suggested_step(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    run: AgentRun,
    step: Action,
) -> ActionOut:
    body = ActionIn(
        tool=step.tool,
        target=step.target,
        arguments=step.arguments,
        purpose="validation" if step.is_validation else "scan",
    )
    try:
        return await actions.send_action(
            db,
            interfaces,
            mask,
            settings,
            operator,
            run.assessment_id,
            body,
            source="agent",
            agent_run_id=run.agent_run_id,
        )
    except ApiError as error:
        if error.code == "ACTION_BLOCKED":  # the API's own check refused it: keep the record
            return actions.read_action(db, UUID(error.details["action_id"]))
        raise


def open_plan_run(
    db: Db, interfaces: Interfaces, operator: Operator, assessment_id: UUID
) -> AgentRun:
    """The new plan's run. The assessment row stays locked while the open plans are
    checked and the run is saved, so two plans can never both start."""
    assessment_repo.get_for_update(db, assessment_id)
    cutoff = datetime.now(UTC) - timedelta(minutes=STALE_MINUTES)
    for run in agent_run_repo.open_plan_runs(db, assessment_id):
        if run.agent_runs_status == AgentRunStatus.RUNNING and run.started_at < cutoff:
            agent_runs.fail(
                db, interfaces, operator, run, ApiError(500, "RUN_CUT_OFF", "The run stopped.")
            )
            assessment_repo.get_for_update(db, assessment_id)  # fail() committed: lock again
            continue
        waiting = run.agent_runs_status == AgentRunStatus.WAITING_APPROVAL
        db.rollback()
        raise ApiError(
            409,
            "RUN_IS_WAITING" if waiting else "PLAN_IN_PROGRESS",
            "Another plan for this assessment is still open.",
            {"agent_run_id": str(run.agent_run_id)},
        )
    run = agent_runs.new_agent_run(db, operator, assessment_id, task="PLAN")
    db.commit()
    return run


async def settle_waiting_run(
    db: Db, interfaces: Interfaces, operator: Operator, assessment_id: UUID, settings: Settings
) -> None:
    """A waiting plan whose approval is already decided or has expired (no request ever
    came to hand that back) is resumed now, so a new plan can start. One whose
    approval is still pending stays, and open_plan_run() answers 409."""
    for run in agent_run_repo.open_plan_runs(db, assessment_id):
        if run.agent_runs_status != AgentRunStatus.WAITING_APPROVAL:
            continue
        found = waiting_step(db, run)
        if found is None:
            if agent_run_repo.claim_waiting(db, run.agent_run_id):
                agent_runs.end(
                    db, interfaces, operator, run, AgentRunStatus.CANCELLED, {"reason": "NO_STEP"}
                )
            continue
        row, approval = found
        pending = approval.approval_status == ApprovalStatus.PENDING
        ttl = settings.approval_ttl_minutes
        if pending and datetime.now(UTC) < expires_at(approval.requested_at, ttl):
            continue
        if not agent_run_repo.claim_waiting(db, run.agent_run_id):
            continue  # another request is handing the decision back
        if pending:
            approval.approval_status = ApprovalStatus.EXPIRED  # as _get_pending would save it
            db.commit()
            audit(
                interfaces.write_audit,
                "APPROVAL_EXPIRED",
                operator,
                assessment_id,
                {"action_id": str(row.action_id), "approval_id": str(approval.approval_id)},
            )
        decided = "APPROVED" if approval.approval_status == ApprovalStatus.APPROVED else "REJECTED"
        await resume_claimed(db, interfaces, operator, run, row, approval, decided)


async def resume_after_decision(
    db: Db, interfaces: Interfaces, operator: Operator, approval: Approval, decision: Decision
) -> None:
    """Hand a person's decision on an action back to the plan that suggested it."""
    row = action_repo.get(db, approval.action_id) if approval.action_id else None
    if row is None or row.source != "agent":
        return
    if not agent_run_repo.claim_waiting(db, row.agent_run_id):
        return  # not a waiting plan, or another request already handed the decision back
    run = agent_run_repo.get(db, row.agent_run_id)
    await resume_claimed(db, interfaces, operator, run, row, approval, decision)


async def resume_claimed(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    run: AgentRun,
    row: ActionRow,
    approval: Approval,
    decision: Decision,
) -> None:
    """The run is claimed (RUNNING again). The decision is already saved and an approved
    action has run, so a failure here marks the run FAILED and audits it, and is not
    raised: the person's request did what it asked."""
    try:
        provider, model = agent_runs.agent_provider(db, run)
        request = AgentRequest(
            task=AgentTask.PLAN,
            assessment_id=run.assessment_id,
            agent_run_id=run.agent_run_id,
            provider=provider,
            model=model,
            scope=approved_scope(interfaces, run.assessment_id),
            resume=ResumeInput(
                agent_run_id=run.agent_run_id,
                assessment_id=run.assessment_id,
                approval_id=approval.approval_id,
                action=actions.to_action(row),
                decision=decision,
            ),
        )
        response = await agent_runs.ask_agent(db, interfaces, request)
    except Exception as error:
        agent_runs.fail(db, interfaces, operator, run, error)
        return
    run.checkpoint_id = response.checkpoint_id
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.COMPLETED, {"decision": decision})


def waiting_step(db: Db, run: AgentRun) -> tuple[ActionRow, Approval] | None:
    """The plan's own step that waits, and its approval."""
    for row in action_repo.list_by_agent_run(db, run.agent_run_id):
        approval = action_repo.approval_for(db, row.action_id)
        if row.source == "agent" and approval is not None:
            return row, approval
    return None


def step_note(action: ActionOut | None) -> str:
    return "NONE" if action is None else str(action.action_status)


def approved_scope(interfaces: Interfaces, assessment_id: UUID) -> ApprovedScope:
    try:
        return interfaces.get_approved_scope(assessment_id)
    except LookupError:
        raise ApiError(
            409, "SCOPE_NOT_APPROVED", "This assessment has no approved scope."
        ) from None


def chat(db: Db, session_id: UUID) -> list[ChatMessage]:
    """The session's chat, already masked when it was saved. core/agent.py passes on
    only the person's own words."""
    return [
        ChatMessage(role=row.role, content_masked=row.content_masked)
        for row in message_repo.list_by_session(db, session_id)
        if row.role in ("user", "assistant", "system")
    ]
