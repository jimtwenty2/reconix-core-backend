"""Actions: send -> safety checks -> run now, or wait for a person to approve -> run.

The pure rules (hash, next step, unchanged) sit at the top so they are easy to test.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, NoReturn
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_ai.harness.catalog import canonical
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    RISK_ORDER,
    Action,
    CheckContext,
    CheckName,
    CheckResult,
    Decision,
    Interfaces,
    Operator,
    RecentRun,
    RiskLevel,
    ToolName,
    WriteAudit,
)
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Action as ActionRow
from reconix_api.models import AgentRun, Approval, ScopeManifest
from reconix_api.models.enums import (
    ActionStatus,
    ApprovalStatus,
    AssessmentStatus,
)
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.schemas.actions import ActionIn, ActionOut, ToolRunOut
from reconix_api.schemas.agent_runs import AgentRunDetailOut
from reconix_api.services import agent_runs, limit_settings, scopes, tool_runs
from reconix_api.services.approvals import expires_at
from reconix_api.services.audit import audit

RECENT_MINUTES = 10  # the loop check looks at least this far back


class NextStep(StrEnum):
    RUN_NOW = "RUN_NOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


def action_hash(action: Action) -> str:
    """SHA-256 of the action in a fixed form. Any change to tool, target or arguments changes it."""
    canonical = json.dumps(action.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def blocked_error(result: CheckResult) -> ApiError:
    return ApiError(
        422,
        "ACTION_BLOCKED",
        "The safety checks blocked this action.",
        {"blocked_by": result.blocked_by, "reason": result.reason, "risk": result.risk},
    )


def next_step(result: CheckResult) -> NextStep:
    """BLOCKED -> 422. LOW runs now. MEDIUM and HIGH wait for a person."""
    if result.decision == Decision.BLOCKED:
        raise blocked_error(result)
    if result.risk == RiskLevel.LOW:
        return NextStep.RUN_NOW
    return NextStep.NEEDS_APPROVAL


def ensure_unchanged(approved_hash: str, action: Action) -> None:
    """Right before running: refuse if the action is not exactly what was approved."""
    if action_hash(action) != approved_hash:
        raise ApiError(409, "ACTION_CHANGED", "The action changed after it was approved.")


def to_action(row: ActionRow) -> Action:
    """The shared Action for a saved row, exactly as it will run."""
    return Action(
        tool=row.tool,
        target=row.target,
        arguments=row.args,
        is_validation=row.purpose == "validation",
    )


def masked_snapshot(action: Action, mask: MaskSecrets) -> dict[str, Any]:
    """The masked copy a person sees when approving. The hash is of the real action."""
    snapshot = action.model_dump(mode="json")
    snapshot["target"], _ = mask(action.target)
    snapshot["arguments"] = [mask(argument)[0] for argument in action.arguments]
    return snapshot


# ---------------------------------------------------------------------------
# Send an action: check -> BLOCKED (422) | LOW (run now) | MEDIUM/HIGH (approval)
# ---------------------------------------------------------------------------


async def send_action(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    assessment_id: UUID,
    body: ActionIn,
    source: str = "operator",
    agent_run_id: UUID | None = None,
) -> ActionOut:
    """source is who asked: "operator", or "agent" for the step a plan suggested, which
    passes its own agent_run_id so the action is filed under that plan's run.

    The assessment row is locked from the loop check until a LOW action's tool run is
    saved, so actions sent at once are checked one at a time and each sees the runs
    before it: the loop limits hold under parallel requests."""
    assessment_repo.get_for_update(db, assessment_id)
    manifest = ensure_can_act(db, assessment_id)
    action = Action(
        tool=body.tool,
        target=body.target,
        arguments=body.arguments,
        is_validation=body.purpose == "validation",
    )
    result = interfaces.check(action, _check_context(db, interfaces, operator, assessment_id))
    if result.decision != Decision.BLOCKED and not _fits_auto_scope(
        db, manifest, body, agent_run_id
    ):
        result = CheckResult(
            decision=Decision.BLOCKED,
            risk=result.risk,
            blocked_by=CheckName.SCOPE,
            reason="CODE_SCAN_ONLY",
        )
    row = ActionRow(
        tool=action.tool,
        args=action.arguments,
        target=action.target,
        purpose=body.purpose,
        risk_level=result.risk,
        guardrail_report=result.model_dump(mode="json"),
        source=source,
        assessment_id=assessment_id,
        manifest_id=manifest.manifest_id,
        agent_run_id=agent_run_id or _agent_run(db, operator, assessment_id).agent_run_id,
    )
    if result.decision == Decision.BLOCKED:
        # A blocked action never runs, so it keeps only the masked copy: what got it
        # blocked may be a secret pasted into the target or the arguments.
        snapshot = masked_snapshot(action, mask)
        row.target, row.args = snapshot["target"], snapshot["arguments"]
        row.action_status = ActionStatus.BLOCKED
    action_repo.add(db, row)
    runs_now = result.decision != Decision.BLOCKED and next_step(result) == NextStep.RUN_NOW
    if not runs_now:
        db.commit()  # a LOW action is committed with its tool run (run_action), under the lock

    details = {"action_id": str(row.action_id), "tool": row.tool, "risk": result.risk}
    if result.decision == Decision.BLOCKED:
        audit(
            interfaces.write_audit,
            "ACTION_BLOCKED",
            operator,
            assessment_id,
            {**details, "blocked_by": result.blocked_by, "reason": result.reason},
        )
    try:
        step = next_step(result)
    except ApiError as error:
        error.details["action_id"] = str(row.action_id)
        raise

    if step == NextStep.RUN_NOW:
        audit(interfaces.write_audit, "ACTION_ACCEPTED", operator, assessment_id, details)
        await tool_runs.run_action(
            db, interfaces, mask, settings, operator, row, action, action_hash(action), None
        )
        return read_action(db, row.action_id, mask)

    snapshot = masked_snapshot(action, mask)
    approval = approval_repo.add(
        db,
        Approval(
            kind="action",
            subject_snapshot=snapshot,
            subject_hash=action_hash(action),
            risk_level=result.risk,
            action_id=row.action_id,
        ),
    )
    db.commit()
    audit(
        interfaces.write_audit,
        "APPROVAL_REQUESTED",
        operator,
        assessment_id,
        {**details, "approval_id": str(approval.approval_id)},
    )
    return read_action(db, row.action_id, mask)


def _fits_auto_scope(
    db: Db, manifest: ScopeManifest, body: ActionIn, agent_run_id: UUID | None
) -> bool:
    """A scope the server approved on its own (only the session's code folder) takes only
    a code scan's own tool calls, and a code fix's SEMGREP rechecks, with no options: no
    person looked at anything else, and an option such as -Dsonar.host.url could send the
    code away. The target is still held to the scope by the checks."""
    approval = approval_repo.latest_for_manifest(db, manifest.manifest_id)
    if approval is None or approval.reason != scopes.CODE_SESSION_FOLDER:
        return True
    run = agent_run_repo.get(db, agent_run_id) if agent_run_id else None
    task = (run.plan or {}).get("task") if run is not None else None
    is_code_scan = task == "CODE_SCAN"
    is_fix_check = task == "CODE_FIX" and canonical(body.tool) == canonical(ToolName.SEMGREP)
    return (is_code_scan or is_fix_check) and not body.arguments


def ensure_can_act(db: Db, assessment_id: UUID) -> ScopeManifest:
    """The assessment exists and is ACTIVE with an approved scope; returns that scope."""
    assessment = assessment_repo.get(db, assessment_id)
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    if assessment.assessment_status != AssessmentStatus.ACTIVE:
        message = (
            "Approve the scope before sending actions."
            if assessment.assessment_status == AssessmentStatus.DRAFT
            else f"This assessment is {assessment.assessment_status} and takes no more actions."
        )
        raise ApiError(
            409,
            "ASSESSMENT_NOT_ACTIVE",
            message,
            {"assessment_status": assessment.assessment_status},
        )
    manifest = scope_repo.get_approved(db, assessment_id)
    if manifest is None:
        raise ApiError(409, "SCOPE_NOT_APPROVED", "This assessment has no approved scope.")
    return manifest


# ---------------------------------------------------------------------------
# Approve and reject (called from services/decisions.py)
# ---------------------------------------------------------------------------


async def approve_action(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    approval: Approval,
) -> None:
    """Runs the safety checks again (S2), then marks the approval and the action APPROVED
    and runs the action.

    Up to 30 minutes pass between sending and approving: the assessment may be cancelled,
    the scope window over, or the risk rules changed. If the checks now refuse the action,
    nothing runs and the approval can no longer be used (see _refuse_at_approval).
    """
    # Everything that can refuse runs before anything is saved: a refusal after the
    # approval is committed would leave it APPROVED, unused, and the action stuck.
    if not settings.job_token_secret.get_secret_value():
        raise ApiError(503, "NOT_READY", "RECONIX_JOB_TOKEN_SECRET is not set.")
    now = datetime.now(UTC)  # one time for the expiry check here and in run_action
    row = _get(db, approval.action_id, lock=True)
    if row.action_status != ActionStatus.PENDING:
        raise ApiError(
            409,
            "ACTION_NOT_PENDING",
            "This action is no longer waiting for approval.",
            {"action_status": row.action_status},
        )
    action = to_action(row)
    write_audit = interfaces.write_audit
    if now >= expires_at(approval.requested_at, settings.approval_ttl_minutes):
        error = ApiError(409, "APPROVAL_EXPIRED", "This approval expired. Send the action again.")
        _refuse_at_approval(db, write_audit, operator, row, approval, ActionStatus.CANCELLED, error)
    try:
        ensure_unchanged(approval.subject_hash, action)
    except ApiError as error:
        # Not what the person was shown: it never runs, and this approval is spent.
        _refuse_at_approval(db, write_audit, operator, row, approval, ActionStatus.BLOCKED, error)
    try:
        ensure_can_act(db, row.assessment_id)
    except ApiError as error:
        _refuse_at_approval(db, write_audit, operator, row, approval, ActionStatus.CANCELLED, error)
    result = interfaces.check(action, _check_context(db, interfaces, operator, row.assessment_id))
    if (
        result.decision != Decision.BLOCKED
        and RISK_ORDER[result.risk] > RISK_ORDER[approval.risk_level]
    ):
        # The approval covered a lower risk (a HIGH one needs the typed target): send it again.
        result = CheckResult(
            decision=Decision.BLOCKED,
            risk=result.risk,
            blocked_by=CheckName.RISK,
            reason="RISK_CHANGED",
        )
    row.guardrail_report = result.model_dump(mode="json")  # the check this decision rests on
    if result.decision == Decision.BLOCKED:
        error = blocked_error(result)
        _refuse_at_approval(db, write_audit, operator, row, approval, ActionStatus.BLOCKED, error)
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = now
    approval.confirmation_verified = approval.risk_level == RiskLevel.HIGH
    row.action_status = ActionStatus.APPROVED
    db.commit()
    audit(
        interfaces.write_audit,
        "APPROVAL_GRANTED",
        operator,
        row.assessment_id,
        {"action_id": str(row.action_id), "approval_id": str(approval.approval_id)},
    )
    await tool_runs.run_action(
        db, interfaces, mask, settings, operator, row, action, approval.subject_hash, approval, now
    )


def _refuse_at_approval(
    db: Db,
    write_audit: WriteAudit,
    operator: Operator,
    row: ActionRow,
    approval: Approval,
    status: ActionStatus,
    error: ApiError,
) -> NoReturn:
    """The second check refused an action as it was approved, so nothing runs. The action
    ends (BLOCKED, or CANCELLED with its assessment) and the approval can no longer be used
    (EXPIRED, with the reason), so a plan waiting on it is freed on the next plan request.
    Writes one audit line, then raises the error."""
    reason = error.details.get("reason") or error.code
    row.action_status = status
    approval.approval_status = ApprovalStatus.EXPIRED
    approval.reason = reason
    db.commit()
    audit(
        write_audit,
        "ACTION_BLOCKED",
        operator,
        row.assessment_id,
        {
            "action_id": str(row.action_id),
            "approval_id": str(approval.approval_id),
            "tool": row.tool,
            "blocked_by": error.details.get("blocked_by"),
            "reason": reason,
        },
    )
    error.details["action_id"] = str(row.action_id)
    raise error


def reject_action(
    db: Db, write_audit: WriteAudit, operator: Operator, approval: Approval, reason: str | None
) -> None:
    row = _get(db, approval.action_id, lock=True)
    approval.approval_status = ApprovalStatus.REJECTED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
    approval.reason = reason
    row.action_status = ActionStatus.REJECTED
    db.commit()
    audit(
        write_audit,
        "APPROVAL_REJECTED",
        operator,
        row.assessment_id,
        {"action_id": str(row.action_id), "approval_id": str(approval.approval_id)},
    )


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------


def read_action(db: Db, action_id: UUID, mask: MaskSecrets) -> ActionOut:
    return _action_out(db, _get(db, action_id), mask)


def list_actions(db: Db, assessment_id: UUID, mask: MaskSecrets) -> list[ActionOut]:
    if assessment_repo.get(db, assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    rows = action_repo.list_by_assessment(db, assessment_id)
    return [_action_out(db, row, mask) for row in rows]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get(db: Db, action_id: UUID, lock: bool = False) -> ActionRow:
    row = action_repo.get_for_update(db, action_id) if lock else action_repo.get(db, action_id)
    if row is None:
        raise ApiError(404, "ACTION_NOT_FOUND", "No action with this id.")
    return row


def _check_context(
    db: Db, interfaces: Interfaces, operator: Operator, assessment_id: UUID
) -> CheckContext:
    try:
        scope = interfaces.get_approved_scope(assessment_id)
    except LookupError as error:
        raise ApiError(
            409, "SCOPE_NOT_APPROVED", "This assessment has no approved scope."
        ) from error
    now = datetime.now(UTC)
    limits = limit_settings.current_limits(db)
    # At least as far back as the same-command window, or a longer window counts too few runs.
    minutes = max(RECENT_MINUTES, limits.same_command_window_minutes)
    recent = action_repo.recent_runs(db, assessment_id, now - timedelta(minutes=minutes))
    return CheckContext(
        operator=operator,
        scope=scope,
        now=now,
        recent_runs=[
            RecentRun(
                tool=action.tool,
                target=action.target,
                arguments=action.args,
                started_at=run.started_at,
            )
            for action, run in recent
        ],
        runs_in_assessment=action_repo.count_runs(db, assessment_id),
        loop_limits=limits,
    )


def _agent_run(db: Db, operator: Operator, assessment_id: UUID) -> AgentRun:
    """Every action belongs to an agent run. A person's action joins the run that their
    session's actions on this assessment share, never a plan's run."""
    running = agent_run_repo.person_run(db, assessment_id, operator.session_id)
    return running or agent_runs.new_agent_run(db, operator, assessment_id)


def _action_out(db: Db, row: ActionRow, mask: MaskSecrets) -> ActionOut:
    """The action as shown: target and arguments masked (S8). The row keeps the real
    values, because the action is hashed and checked again with them before it runs."""
    approval = action_repo.approval_for(db, row.action_id)
    return ActionOut(
        action_id=row.action_id,
        tool=row.tool,
        args=[mask(argument)[0] for argument in row.args],
        target=mask(row.target)[0],
        purpose=row.purpose,
        risk_level=row.risk_level,
        action_status=row.action_status,
        guardrail_report=row.guardrail_report,
        source=row.source,
        created_at=row.created_at,
        assessment_id=row.assessment_id,
        manifest_id=row.manifest_id,
        approval_id=approval.approval_id if approval else None,
        tool_runs=[
            ToolRunOut.model_validate(run, from_attributes=True)
            for run in action_repo.list_tool_runs(db, row.action_id)
        ],
    )


def read_agent_run(db: Db, agent_run_id: UUID, mask: MaskSecrets) -> AgentRunDetailOut:
    """A run and the actions filed under it, e.g. a plan's suggested step and its status."""
    agent_run = agent_run_repo.get(db, agent_run_id)
    if agent_run is None:
        raise ApiError(404, "AGENT_RUN_NOT_FOUND", "No agent run with this id.")
    rows = action_repo.list_by_agent_run(db, agent_run_id)
    return AgentRunDetailOut(
        **agent_runs.agent_run_out(agent_run).model_dump(),
        actions=[_action_out(db, row, mask) for row in rows],
    )
