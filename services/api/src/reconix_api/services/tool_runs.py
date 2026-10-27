"""Running one action: new tool run -> one-time job token -> call_tool (MCP) -> masked result."""

from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import Session as Db

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Action, Interfaces, Operator, ToolJob, ToolResult
from reconix_api.core.job_token import sign_job_token
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Action as ActionRow
from reconix_api.models import Approval, ToolRun
from reconix_api.models.enums import ActionStatus, ToolRunStatus
from reconix_api.repositories import actions as action_repo
from reconix_api.services.approvals import approval_state, ensure_can_use
from reconix_api.services.audit import audit


async def run_action(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    row: ActionRow,
    action: Action,
    action_hash: str,
    approval: Approval | None,
) -> ToolRun:
    """`action` and `action_hash` must already be checked against the approval.

    A LOW action has no approval. Any other action needs an approval that is APPROVED,
    not expired and not used; running it uses it up.
    """
    secret = settings.job_token_secret.get_secret_value()
    if not secret:
        raise ApiError(503, "NOT_READY", "RECONIX_JOB_TOKEN_SECRET is not set.")
    now = datetime.now(UTC)
    if approval is not None:
        ensure_can_use(approval_state(approval, settings.approval_ttl_minutes), now)
        approval.consumed_at = now

    run = ToolRun(
        attempt_no=action_repo.next_attempt_no(db, row.action_id),
        tool_run_status=ToolRunStatus.RUNNING,
        job_token_id=uuid4(),
        started_at=now,
        action_id=row.action_id,
        approval_id=approval.approval_id if approval else None,
    )
    action_repo.add(db, run)
    db.commit()
    details = {"action_id": str(row.action_id), "tool_run_id": str(run.tool_run_id)}
    audit(interfaces.write_audit, "TOOL_RUN_STARTED", operator, row.assessment_id, details)

    token = sign_job_token(
        run.tool_run_id,
        action_hash,
        secret,
        now,
        settings.job_token_ttl_seconds,
        jti=str(run.job_token_id),
    )
    job = ToolJob(
        tool_run_id=run.tool_run_id,
        tool=action.tool,
        target=action.target,
        arguments=action.arguments,
        job_token=token,
    )
    try:
        result = await interfaces.call_tool(job)
    except Exception as error:  # noqa: BLE001 - any failure is saved on the run, never raised
        _save_failure(run, row, mask, error)
    else:
        _save_result(run, row, mask, result)
    db.commit()

    audit(
        interfaces.write_audit,
        "TOOL_RUN_FINISHED",
        operator,
        row.assessment_id,
        {**details, "status": run.tool_run_status, "masked_count": run.masked_count},
    )
    return run


def _save_result(run: ToolRun, row: ActionRow, mask: MaskSecrets, result: ToolResult) -> None:
    # The tool's own result file is what the parsers read; stdout is the fallback.
    output, hidden = mask(result.output_file or result.stdout)
    stderr, hidden_in_stderr = mask(result.stderr)
    run.output_masked = output
    run.masked_count = hidden + hidden_in_stderr
    run.exit_code = result.exit_code
    run.error = stderr or None
    run.tool_run_status = ToolRunStatus(result.status)
    run.finished_at = datetime.now(UTC)
    if run.tool_run_status == ToolRunStatus.COMPLETED:
        row.action_status = ActionStatus.COMPLETED
    else:
        row.action_status = ActionStatus.FAILED


def _save_failure(run: ToolRun, row: ActionRow, mask: MaskSecrets, error: Exception) -> None:
    message = error.message if isinstance(error, ApiError) else str(error)
    run.error, run.masked_count = mask(f"{type(error).__name__}: {message}")
    run.tool_run_status = ToolRunStatus.FAILED
    run.finished_at = datetime.now(UTC)
    row.action_status = ActionStatus.FAILED
