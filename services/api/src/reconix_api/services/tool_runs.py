"""Running one action: new tool run -> one-time job token -> call_tool (MCP) -> masked result."""

import logging
import re
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy.orm import Session as Db

from reconix_ai.harness.catalog import canonical
from reconix_api.core import code_files
from reconix_api.core.config import Settings
from reconix_api.core.disclosure import DisclosureVault, vault_for_tool_runs
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Action, Interfaces, Operator, ToolJob, ToolResult
from reconix_api.core.job_token import sign_job_token
from reconix_api.core.masking import MaskSecrets, mask_output
from reconix_api.findings.shape import NewFinding, OutputUnreadable
from reconix_api.models import Action as ActionRow
from reconix_api.models import Approval, ToolRun
from reconix_api.models.enums import ActionStatus, ToolRunStatus
from reconix_api.repositories import actions as action_repo
from reconix_api.services.approvals import approval_state, ensure_can_use
from reconix_api.services.audit import audit
from reconix_api.services.findings import CONTROL, KeptValues, parse_run, save_findings

# Terminal colour and cursor codes, e.g. gitleaks's "\x1b[90m2:45AM\x1b[0m". Cut out
# whole, before the control characters, so no "[90m" is left behind.
logger = logging.getLogger(__name__)

TERMINAL_CODES = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")

# Tools that EXIT NON-ZERO precisely when they find issues (not a crash): schemathesis
# (exit 1 = test failures found), sqlmap and dalfox. The Kali wrapper reports these as
# failed, but their output holds real findings, so a FAILED/TIMED_OUT run with output is
# still parsed. Catalog (canonical) names.
FINDINGS_ON_NONZERO_EXIT = {"schemathesis", "sqlmap", "dalfox"}


def _should_parse(run: ToolRun, action: Action) -> bool:
    """True when the run's output should be parsed for findings: a COMPLETED run, or a
    find-on-nonzero-exit tool that came back FAILED/TIMED_OUT but left output to read."""
    if run.tool_run_status == ToolRunStatus.COMPLETED:
        return True
    return (
        canonical(str(action.tool)) in FINDINGS_ON_NONZERO_EXIT
        and run.tool_run_status in (ToolRunStatus.FAILED, ToolRunStatus.TIMED_OUT)
        and bool(run.output_masked)
    )


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
    now: datetime | None = None,
) -> ToolRun:
    """`action` and `action_hash` must already be checked against the approval.

    A LOW action has no approval. Any other action needs an approval that is APPROVED,
    not expired and not used; running it uses it up. `now` is the time the approval was
    checked at, so a just-approved action is never refused here as expired.
    """
    secret = settings.job_token_secret.get_secret_value()
    if not secret:
        db.commit()  # the action is kept as sent; it just cannot run yet
        raise ApiError(503, "NOT_READY", "RECONIX_JOB_TOKEN_SECRET is not set.")
    now = now or datetime.now(UTC)
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
    result: ToolResult | None = None
    try:
        result = await interfaces.call_tool(job)
    except Exception as error:  # noqa: BLE001 - any failure is saved on the run, never raised
        _save_failure(run, row, mask, error)
    else:
        _save_result(run, row, mask, result)
    finding_count = 0
    if result is not None and _should_parse(run, action):
        vault = vault_for_tool_runs(settings)
        finding_count = _save_findings(db, mask, vault, run, row, action, result)
        # A find-on-nonzero-exit tool (schemathesis, sqlmap, dalfox) comes back FAILED
        # though its output is valid; when it yielded findings the run really succeeded,
        # so record it COMPLETED for coverage and the UI. No findings: leave it FAILED.
        if finding_count and run.tool_run_status != ToolRunStatus.COMPLETED:
            run.tool_run_status = ToolRunStatus.COMPLETED
            row.action_status = ActionStatus.COMPLETED
    db.commit()

    audit(
        interfaces.write_audit,
        "TOOL_RUN_FINISHED",
        operator,
        row.assessment_id,
        {
            **details,
            "status": run.tool_run_status,
            "masked_count": run.masked_count,
            "finding_count": finding_count,
        },
    )
    return run


def _save_result(run: ToolRun, row: ActionRow, mask: MaskSecrets, result: ToolResult) -> None:
    # The tool's own result file is what the parsers read; stdout is the fallback. Paths in
    # a code scan's copy folder become the code folder's before any finding is deduped.
    raw = code_files.canonical_paths(result.output_file or result.stdout)
    output, hidden = mask_output(mask, raw)
    # stderr is shown in the TUI and the web: no terminal codes from the tool reach them.
    stderr, hidden_in_stderr = mask(CONTROL.sub("", TERMINAL_CODES.sub("", result.stderr)))
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


def _save_findings(
    db: Db,
    mask: MaskSecrets,
    vault: DisclosureVault | None,
    run: ToolRun,
    row: ActionRow,
    action: Action,
    result: ToolResult,
) -> int:
    """Parse the masked output and save its findings. The run is kept whatever happens here.

    The raw output is parsed too, in memory only, so the real values behind the saved
    evidence's labels can be kept in the vault for a `disclosure` approval.
    """
    try:
        new, run.request_count = parse_run(action.tool, run.output_masked or "")
        with db.begin_nested():  # a savepoint: a failure drops the findings, not the run
            raw = _parse_raw(action, result) if vault is not None else None
            saved, kept = save_findings(db, mask, row.assessment_id, run, new, raw)
    except OutputUnreadable as error:
        note, _ = mask(f"OUTPUT_UNREADABLE: {error}")  # parser messages quote the output
        run.error = _append(run.error, note)
        return 0
    except Exception as error:  # noqa: BLE001 - a parser bug must not lose the run
        run.error = _append(run.error, f"FINDINGS_NOT_SAVED: {type(error).__name__}")
        return 0
    if vault is not None:
        _keep_values(vault, kept)
    return len(saved)


def _parse_raw(action: Action, result: ToolResult) -> list[NewFinding] | None:
    """The raw output's findings, only to find the values behind labels. Unreadable: None."""
    try:
        raw, _ = parse_run(action.tool, result.output_file or result.stdout)
    except Exception:  # noqa: BLE001 - the masked findings are saved either way
        return None
    return raw


def _keep_values(vault: DisclosureVault, kept: list[KeptValues]) -> None:
    """After the findings are saved. A vault that cannot be written only means these
    values cannot be shown later; the findings stay."""
    for evidence_id, hidden in kept:
        try:
            vault.keep(evidence_id, hidden)
        except Exception as error:  # noqa: BLE001 - never lose findings over the vault
            logger.warning("Evidence values not kept: %s", type(error).__name__)


def _append(error: str | None, note: str) -> str:
    return f"{error}\n{note}" if error else note


def _save_failure(run: ToolRun, row: ActionRow, mask: MaskSecrets, error: Exception) -> None:
    message = error.message if isinstance(error, ApiError) else str(error)
    run.error, run.masked_count = mask(f"{type(error).__name__}: {message}")
    run.tool_run_status = ToolRunStatus.FAILED
    run.finished_at = datetime.now(UTC)
    row.action_status = ActionStatus.FAILED
