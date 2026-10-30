"""Actions: send -> safety checks -> run now, or wait for a person to approve -> run.

The pure rules (hash, next step, unchanged) sit at the top so they are easy to test.
"""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    CheckContext,
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
from reconix_api.services import agent_runs, tool_runs
from reconix_api.services.audit import audit

RECENT_MINUTES = 10  # the loop check looks at least this far back


class NextStep(StrEnum):
    RUN_NOW = "RUN_NOW"
    NEEDS_APPROVAL = "NEEDS_APPROVAL"


def action_hash(action: Action) -> str:
    """SHA-256 of the action in a fixed form. Any change to tool, target or arguments changes it."""
    canonical = json.dumps(action.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def next_step(result: CheckResult) -> NextStep:
    """BLOCKED -> 422. LOW runs now. MEDIUM and HIGH wait for a person."""
    if result.decision == Decision.BLOCKED:
        raise ApiError(
            422,
            "ACTION_BLOCKED",
            "The safety checks blocked this action.",
            {"blocked_by": result.blocked_by, "reason": result.reason, "risk": result.risk},
        )
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
        tool=ToolName(row.tool),
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
    passes its own agent_run_id so the action is filed under that plan's run."""
    manifest = ensure_can_act(db, assessment_id)
    action = Action(
        tool=body.tool,
        target=body.target,
        arguments=body.arguments,
        is_validation=body.purpose == "validation",
    )
    result = interfaces.check(action, _check_context(db, interfaces, operator, assessment_id))
    row = ActionRow(
        tool=action.tool.value,
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
        row.action_status = ActionStatus.BLOCKED
    action_repo.add(db, row)
    db.commit()

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
        return read_action(db, row.action_id)

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
    return read_action(db, row.action_id)


def ensure_can_act(db: Db, assessment_id: UUID) -> ScopeManifest:
    """The assessment exists and is ACTIVE with an approved scope; returns that scope."""
    assessment = assessment_repo.get(db, assessment_id)
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    if assessment.assessment_status != AssessmentStatus.ACTIVE:
        raise ApiError(
            409,
            "ASSESSMENT_NOT_ACTIVE",
            "Approve the scope before sending actions.",
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
    the scope window over or the scope changed. Then nothing runs and the approval is not
    used: an inactive assessment is a 409, and an action the checks now block is saved as
    BLOCKED and answered with 422 ACTION_BLOCKED, as when it is sent.
    """
    row = _get(db, approval.action_id, lock=True)
    action = to_action(row)
    ensure_unchanged(approval.subject_hash, action)
    ensure_can_act(db, row.assessment_id)
    result = interfaces.check(action, _check_context(db, interfaces, operator, row.assessment_id))
    if result.decision == Decision.BLOCKED:
        _block_at_approval(db, interfaces.write_audit, operator, row, approval, result)
    approval.approval_status = ApprovalStatus.APPROVED
    approval.decided_by = operator.actor
    approval.decided_at = datetime.now(UTC)
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
        db, interfaces, mask, settings, operator, row, action, approval.subject_hash, approval
    )


def _block_at_approval(
    db: Db,
    write_audit: WriteAudit,
    operator: Operator,
    row: ActionRow,
    approval: Approval,
    result: CheckResult,
) -> None:
    """The checks blocked an action as it was approved: save it as BLOCKED, write one audit
    line and raise 422. The approval stays PENDING and unused, so it can still be rejected."""
    row.action_status = ActionStatus.BLOCKED
    row.guardrail_report = result.model_dump(mode="json")
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
            "risk": result.risk,
            "blocked_by": result.blocked_by,
            "reason": result.reason,
        },
    )
    try:
        next_step(result)
    except ApiError as error:
        error.details["action_id"] = str(row.action_id)
        raise


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


def read_action(db: Db, action_id: UUID) -> ActionOut:
    return _action_out(db, _get(db, action_id))


def list_actions(db: Db, assessment_id: UUID) -> list[ActionOut]:
    if assessment_repo.get(db, assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    return [_action_out(db, row) for row in action_repo.list_by_assessment(db, assessment_id)]


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
    recent = action_repo.recent_runs(db, assessment_id, now - timedelta(minutes=RECENT_MINUTES))
    return CheckContext(
        operator=operator,
        scope=scope,
        now=now,
        recent_runs=[
            RecentRun(
                tool=ToolName(action.tool),
                target=action.target,
                arguments=action.args,
                started_at=run.started_at,
            )
            for action, run in recent
        ],
        runs_in_assessment=action_repo.count_runs(db, assessment_id),
    )


def _agent_run(db: Db, operator: Operator, assessment_id: UUID) -> AgentRun:
    """Every action belongs to an agent run. A person's action joins the run a person's
    actions share, never a plan's run."""
    running = agent_run_repo.person_run(db, assessment_id)
    return running or agent_runs.new_agent_run(db, operator, assessment_id)


def _action_out(db: Db, row: ActionRow) -> ActionOut:
    approval = action_repo.approval_for(db, row.action_id)
    return ActionOut(
        action_id=row.action_id,
        tool=row.tool,
        args=row.args,
        target=row.target,
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
