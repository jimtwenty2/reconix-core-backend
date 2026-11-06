"""Plans: ask the agent for a plan, then put its first step through the API's own path.

A plan asked for as a draft keeps its first step until a person sends it
(send_draft) or cancels the run (cancel_run); until then the run is
WAITING_APPROVAL with plan["draft"] set, and nothing has been sent or run. A new
plan cancels a draft that was never sent.

The agent only suggests. Its step becomes an action through actions.send_action,
filed under the plan's own run, so the API runs check() again (S2) and keeps its
own approval rules: BLOCKED is refused, LOW runs now, MEDIUM and HIGH wait for a
person. While a person decides, the run is WAITING_APPROVAL; the decision is handed
back to the agent exactly once (claim_waiting), and the run is COMPLETED.

One plan per assessment is open at a time. A run ends COMPLETED, FAILED or
CANCELLED, and each end writes one audit line.

The next step (SUGGEST) goes the same way, with the newest masked tool outputs: the
agent reflects on them (ReflAct) and suggests what to run next.
"""

from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

from pydantic import ValidationError
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
from reconix_api.models.enums import ActionStatus, AgentRunStatus, ApprovalStatus
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.repositories import messages as message_repo
from reconix_api.schemas.actions import ActionIn, ActionOut
from reconix_api.schemas.agent_runs import AgentRunOut, PlanOut
from reconix_api.services import actions, agent_runs
from reconix_api.services.approvals import expires_at
from reconix_api.services.audit import audit

Decision = Literal["APPROVED", "REJECTED"]
# A plan still RUNNING after this was cut off (e.g. the API stopped). Longer than one
# plan's model calls usually take; one that answers later saves nothing (see
# ensure_still_running).
STALE_MINUTES = 30
TOOL_OUTPUTS = 3  # the next step reads the newest 3 tool outputs, masked when saved
RUN_LINES = 40  # the list of every finished tool run the next step reads, newest kept
TARGET_CHARS = 60  # a target in that list or an output's header line, cut to this length


async def start_plan(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    assessment_id: UUID,
    task: AgentTask = AgentTask.PLAN,
    draft: bool = False,
) -> PlanOut:
    """PLAN: a plan and its first step. SUGGEST: the next step, from the newest tool
    outputs. Only a PLAN can be a draft."""
    actions.ensure_can_act(db, assessment_id)
    tool_results = recent_outputs(db, assessment_id, mask) if task == AgentTask.SUGGEST else []
    if task == AgentTask.SUGGEST and not tool_results:
        raise ApiError(
            409, "NO_TOOL_RESULTS", "No tool has run yet. Ask for a plan, or run a step first."
        )
    await settle_waiting_run(db, interfaces, operator, assessment_id, settings)
    scope = approved_scope(interfaces, assessment_id)
    run = open_plan_run(db, interfaces, operator, assessment_id, task)
    try:
        return await plan_and_send(
            db, interfaces, mask, settings, operator, run, scope, task, tool_results, draft
        )
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
    task: AgentTask = AgentTask.PLAN,
    tool_results: list[str] | None = None,
    draft: bool = False,
) -> PlanOut:
    provider, model = agent_runs.agent_provider(db, run)
    request = AgentRequest(
        task=task,
        assessment_id=run.assessment_id,
        agent_run_id=run.agent_run_id,
        provider=provider,
        model=model,
        scope=scope,
        messages=chat(db, operator.session_id),
        tool_results=tool_results or [],
    )
    response = await agent_runs.ask_agent(db, interfaces, request)
    ensure_still_running(db, run)
    text = mask(response.text)[0]
    plan = [masked_step(mask, step) for step in response.plan]
    step = response.proposed_action
    # A draft with nothing to send has nothing to keep; only a PLAN is drafted.
    keep = draft and task == AgentTask.PLAN and step is not None
    run.plan = {
        "task": task.value,
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
        "PLAN_CREATED" if task == AgentTask.PLAN else "STEP_SUGGESTED",
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


def ensure_still_running(db: Db, run: AgentRun) -> None:
    """The answer may come after open_plan_run() cut the run off and a newer plan started.
    Then nothing from it is saved or sent. The row stays locked until the plan is saved,
    so the cut-off can't happen in between."""
    row = agent_run_repo.get_for_update(db, run.agent_run_id)
    if row is None or row.agent_runs_status != AgentRunStatus.RUNNING:
        raise ApiError(409, "RUN_CUT_OFF", "This run was stopped while the agent answered.")


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


def draft_run(db: Db, agent_run_id: UUID) -> AgentRun:
    run = agent_run_repo.get(db, agent_run_id)
    if run is None:
        raise ApiError(404, "AGENT_RUN_NOT_FOUND", "No agent run with this id.")
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
    try:
        body = ActionIn(
            tool=step.tool,
            target=step.target,
            arguments=step.arguments,
            purpose="validation" if step.is_validation else "scan",
        )
    except ValidationError as error:  # the agent's Action has none of ActionIn's limits
        raise ApiError(
            422, "INVALID_STEP", "The agent suggested a step that is not valid."
        ) from error
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
            return actions.read_action(db, UUID(error.details["action_id"]), mask)
        raise


def open_plan_run(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    assessment_id: UUID,
    task: AgentTask = AgentTask.PLAN,
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
    run = agent_runs.new_agent_run(db, operator, assessment_id, task=task.value)
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
        if step_still_running(row, approval):
            continue  # its approve request hands the tool's result back
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


def step_still_running(row: ActionRow, approval: Approval) -> bool:
    """Approved, but its tool has not finished: resuming now would hand the plan "approved"
    with no output. One approved more than STALE_MINUTES ago was cut off (e.g. the API
    stopped), so it no longer holds the plan."""
    if approval.approval_status != ApprovalStatus.APPROVED:
        return False
    if row.action_status != ActionStatus.APPROVED:
        return False  # it ran (COMPLETED or FAILED) or was refused
    decided_at = approval.decided_at or approval.requested_at
    return decided_at > datetime.now(UTC) - timedelta(minutes=STALE_MINUTES)


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
            task=AgentTask((run.plan or {}).get("task", AgentTask.PLAN)),
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


def cancel_run(
    db: Db, interfaces: Interfaces, operator: Operator, agent_run_id: UUID
) -> AgentRunOut:
    """Stop a plan or next-step run that waits for a person, or drop a draft plan. Its
    waiting step is CANCELLED and the approval EXPIRED, so the step can never run later. A run still
    asking the agent cannot be stopped half way: 409."""
    run = agent_run_repo.get(db, agent_run_id)
    if run is None or (run.plan or {}).get("task") not in ("PLAN", "SUGGEST"):
        raise ApiError(404, "AGENT_RUN_NOT_FOUND", "No plan or next-step run with this id.")
    if run.agent_runs_status == AgentRunStatus.RUNNING:
        raise ApiError(409, "RUN_IN_PROGRESS", "The agent is still answering. Try again soon.")
    if not agent_run_repo.claim_waiting(db, agent_run_id):
        raise ApiError(409, "RUN_FINISHED", "This run has already ended.")
    details = {"reason": "CANCELLED_BY_PERSON"}
    if (run.plan or {}).get("draft"):
        details["draft"] = "true"  # nothing was sent, so nothing else changes
    found = waiting_step(db, run)
    if found is not None:
        # The same locks as approving, in the same order: a decision made at this moment
        # either finishes first (and the step stands) or waits and finds it cancelled.
        approval = approval_repo.get_for_update(db, found[1].approval_id)
        row = action_repo.get_for_update(db, found[0].action_id)
        details["action_id"] = str(row.action_id)
        if (
            approval.approval_status == ApprovalStatus.PENDING
            and row.action_status == ActionStatus.PENDING
        ):
            approval.approval_status = ApprovalStatus.EXPIRED
            approval.reason = "RUN_CANCELLED"
            row.action_status = ActionStatus.CANCELLED
        else:
            details["step"] = "ALREADY_DECIDED"
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.CANCELLED, details)
    return agent_runs.agent_run_out(run)


def waiting_step(db: Db, run: AgentRun) -> tuple[ActionRow, Approval] | None:
    """The plan's own step that waits, and its approval."""
    for row in action_repo.list_by_agent_run(db, run.agent_run_id):
        approval = action_repo.approval_for(db, row.action_id)
        if row.source == "agent" and approval is not None:
            return row, approval
    return None


def recent_outputs(db: Db, assessment_id: UUID, mask: MaskSecrets) -> list[str]:
    """What the next step reads about the tools that ran, all masked:

    the newest tool outputs, each headed "TOOL target STATUS", then one list of every
    finished tool run (tool, target, status, findings), so the agent knows which checks
    already ran and does not repeat them. The list comes last: the agent keeps only its
    newest few texts, so it drops an old output before it drops the list. Empty when no
    tool run has finished.
    """
    runs = [
        (run, action)
        for run, action in action_repo.tool_runs_in_assessment(db, assessment_id)
        if run.finished_at is not None
    ]
    if not runs:
        return []
    counts = finding_repo.finding_counts(db, [run.tool_run_id for run, _ in runs])
    rows = [
        (action.tool, action.target, str(run.tool_run_status), counts.get(run.tool_run_id, 0))
        for run, action in runs
    ]
    outputs = [
        f"{output_header(action.tool, action.target, str(run.tool_run_status))}\n"
        f"{run.output_masked}"
        for run, action in runs
        if run.output_masked
    ]
    return [mask(text)[0] for text in [*outputs[-TOOL_OUTPUTS:], runs_summary(rows)]]


def output_header(tool: str, target: str, status: str) -> str:
    """One line naming the tool run an output came from, e.g. "NMAP 10.0.0.5 COMPLETED"."""
    return f"{tool} {short(target)} {status}"


def runs_summary(rows: list[tuple[str, str, str, int]]) -> str:
    """Every finished tool run (rows oldest first), one line each, newest first so a cut
    end loses the oldest. Past RUN_LINES the older runs are counted, not listed."""
    lines = [
        f"- {tool} {short(target)} {status}, {found} findings"
        for tool, target, status, found in reversed(rows)
    ]
    if len(lines) > RUN_LINES:
        lines = [*lines[:RUN_LINES], f"- ({len(lines) - RUN_LINES} older runs not shown)"]
    return "Tool runs so far, newest first (tool, target, status, findings):\n" + "\n".join(lines)


def short(target: str) -> str:
    """A target cut to TARGET_CHARS, so one long URL cannot crowd out the list."""
    return target if len(target) <= TARGET_CHARS else target[: TARGET_CHARS - 1] + "…"


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
