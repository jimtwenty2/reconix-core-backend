"""Code scans for VS Code: semgrep, then gitleaks, then the agent's analysis.

A scan is an agent run with plan = {"task": "CODE_SCAN", "stage", "progress", "notes",
"error", "analysis_run_id"}. The route answers at once, and the scan goes on in the
background with its own database session. Each tool runs through actions.send_action,
so it gets the 5 checks, the second check and its audit lines like any other action.

Cancelling marks the run CANCELLED at once. The scan sees it before its next step and
stops; a tool that is already running finishes, and its findings are kept.
"""

import asyncio
import json
import logging
import re
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session as Db
from sqlalchemy.orm import sessionmaker

from reconix_api.core import code_files
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import ApprovedScope, Interfaces, Operator, ToolName, WriteAudit
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import AgentRun, Finding
from reconix_api.models.enums import ActionStatus, AgentRunStatus, SeverityStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.schemas.actions import ActionIn
from reconix_api.schemas.code import CodeFindingOut, CodeScanIn, CodeScanOut
from reconix_api.services import actions, agent_runs, analysis, findings, plans
from reconix_api.services.audit import audit

logger = logging.getLogger(__name__)

TASK = "CODE_SCAN"
TOOLS = (ToolName.SEMGREP, ToolName.GITLEAKS)
MAX_SNIPPET = 500
SECRET_CWES = {"CWE-259", "CWE-321", "CWE-798"}  # hard-coded password, key, credentials
SECRET_WORDS = re.compile(r"secret|passw|token|credential|api.?key|private.?key|jwt", re.I)
_running: set[asyncio.Task[None]] = set()  # keeps each scan alive until it ends


async def start_scan(
    db: Db,
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    assessment_id: UUID,
    body: CodeScanIn,
) -> CodeScanOut:
    """Scans the code sent to the assessment's session. Files in the scope's excluded
    folders are deleted from the stored code first, so the tools never read them.
    409 SCAN_RUNNING while another scan of it runs; 422 NO_CODE when no code is left
    to scan; 422 CODE_EXCLUDED when the scope excludes the whole code folder."""
    actions.ensure_can_act(db, assessment_id)
    session_id = assessment_repo.get(db, assessment_id).session_id
    target = code_files.container_path(session_id)
    skip = excluded_folders(plans.approved_scope(interfaces, assessment_id), target)
    assessment_repo.lock(db, assessment_id)  # two starts at once: the second one waits
    if agent_run_repo.running_code_scan(db, assessment_id) is not None:
        raise ApiError(409, "SCAN_RUNNING", "A code scan of this assessment is still running.")
    folder = code_files.session_folder(settings.code_dir, session_id)
    removed = code_files.remove_excluded(folder, skip)
    if not code_files.stored_files(folder):
        raise ApiError(422, "NO_CODE", "Send the code first with /sessions/{id}/code.")

    run = agent_runs.new_agent_run(db, operator, assessment_id, task=TASK)
    run.plan = {"task": TASK, "stage": "SCANNING", "progress": 0, "notes": []}
    db.commit()
    details = {
        "agent_run_id": str(run.agent_run_id),
        "analyze": str(body.analyze),
        "excluded_files_removed": str(removed),
    }
    audit(interfaces.write_audit, "CODE_SCAN_STARTED", operator, assessment_id, details)

    scan = run_scan(
        session_factory, interfaces, mask, settings, operator, run.agent_run_id, target, body
    )
    task = asyncio.create_task(scan)
    _running.add(task)
    task.add_done_callback(_running.discard)
    return scan_out(db, run)


async def run_scan(
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    agent_run_id: UUID,
    target: str,
    body: CodeScanIn,
) -> None:
    """The scan itself. Any error ends the run FAILED with its code; nothing is raised."""
    with session_factory() as db:
        try:
            await _scan(db, interfaces, mask, settings, operator, agent_run_id, target, body)
        except Exception as error:
            if not isinstance(error, ApiError):
                logger.error("Code scan %s failed: %s", agent_run_id, type(error).__name__)
            _fail(db, interfaces, operator, agent_run_id, error)


def excluded_folders(scope: ApprovedScope, target: str) -> list[str]:
    """The scope's excluded paths inside the code folder, relative to it. The tools get
    no exclude list, so the scan removes these from the stored code instead. A scope
    that excludes the whole code folder leaves nothing to scan."""
    for entry in scope.excluded_targets:
        if target == entry.rstrip("/") or target.startswith(entry.rstrip("/") + "/"):
            raise ApiError(422, "CODE_EXCLUDED", "The scope excludes the whole code folder.")
    return code_files.excluded_inside(scope.excluded_targets, target)


def cancel_for_session(
    db: Db, write_audit: WriteAudit, operator: Operator, session_id: UUID
) -> None:
    """When a session closes, its running code scan ends CANCELLED (one audit line). The
    row is locked and checked again, so a scan that finished meanwhile keeps its end."""
    assessment = assessment_repo.get_by_session(db, session_id)
    found = assessment and agent_run_repo.running_code_scan(db, assessment.assessment_id)
    if not found:
        return
    run = agent_run_repo.get_for_update(db, found.agent_run_id)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        return
    _update_plan(run, stage="DONE")
    agent_runs.finish(run, AgentRunStatus.CANCELLED)
    db.commit()
    details = {"agent_run_id": str(run.agent_run_id), "task": TASK}
    audit(write_audit, "AGENT_RUN_CANCELLED", operator, run.assessment_id, details)


def read_scan(db: Db, agent_run_id: UUID) -> CodeScanOut:
    return scan_out(db, _get_scan(db, agent_run_id))


def cancel_scan(
    db: Db, interfaces: Interfaces, operator: Operator, agent_run_id: UUID
) -> CodeScanOut:
    """409 SCAN_ENDED when the scan has already ended."""
    run = _get_scan(db, agent_run_id, lock=True)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        raise ApiError(409, "SCAN_ENDED", "This code scan has already ended.")
    _update_plan(run, stage="DONE")
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.CANCELLED, {"task": TASK})
    return scan_out(db, run)


def list_scan_findings(
    db: Db, settings: Settings, mask: MaskSecrets, agent_run_id: UUID
) -> list[CodeFindingOut]:
    """The findings this scan's tools found, with their place in the code."""
    run = _get_scan(db, agent_run_id)
    session_id = assessment_repo.get(db, run.assessment_id).session_id
    folder = code_files.session_folder(settings.code_dir, session_id)
    prefix = code_files.container_path(session_id) + "/"
    return [
        code_finding_out(db, mask, folder, prefix, row)
        for row in finding_repo.list_by_agent_run(db, agent_run_id)
    ]


def scan_out(db: Db, run: AgentRun) -> CodeScanOut:
    plan = run.plan or {}
    counts = {severity: 0 for severity in SeverityStatus}
    for row in finding_repo.list_by_agent_run(db, run.agent_run_id):
        counts[row.severity_status] += 1
    return CodeScanOut(
        agent_run_id=run.agent_run_id,
        agent_runs_status=run.agent_runs_status,
        stage=plan.get("stage", "SCANNING"),
        progress=plan.get("progress", 0),
        started_at=run.started_at,
        finished_at=run.finished_at,
        session_id=run.session_id,
        assessment_id=run.assessment_id,
        counts=counts,
        notes=plan.get("notes", []),
        error=plan.get("error"),
        analysis_run_id=plan.get("analysis_run_id"),
    )


def code_finding_out(
    db: Db, mask: MaskSecrets, folder: Path, prefix: str, row: Finding
) -> CodeFindingOut:
    """Path and line come from the finding's newest evidence, the rest from the stored
    file. A gitleaks finding never gets a snippet: its line is the secret."""
    out = findings.read_finding(db, row.finding_id)
    path = relative_path(row.target, prefix)
    proof = _proof(out.evidence[-1].content) if out.evidence else {}
    line = _int(proof, ("start", "line"), ("StartLine",))
    end_line = _int(proof, ("end", "line"), ("EndLine",))
    file = folder / path if path else None
    has_file = file is not None and file.is_file() and not file.is_symlink()
    rule_id = proof.get("check_id") or proof.get("RuleID")
    snippet = None
    if has_file and line and not may_hold_secret(out.tools, rule_id, out.cwe_ids):
        snippet = mask(_line(file, line)[:MAX_SNIPPET])[0]
    return CodeFindingOut(
        **out.model_dump(),
        path=path,
        line=line,
        end_line=end_line,
        rule_id=rule_id,
        snippet=snippet,
        file_sha256=code_files.file_sha256(file) if has_file else None,
    )


def may_hold_secret(tools: list[str], rule_id: str | None, cwe_ids: list[str]) -> bool:
    """A finding whose line may be the secret itself gets no snippet: every gitleaks
    finding, and semgrep's hard-coded secret rules. The masker cannot know a secret it
    has no pattern for, e.g. jwt.sign(payload, "acme-prod-2024")."""
    if ToolName.GITLEAKS in tools or SECRET_CWES & set(cwe_ids):
        return True
    return bool(rule_id and SECRET_WORDS.search(rule_id))


def relative_path(target: str, prefix: str) -> str | None:
    """'/workspace/code/<session>/src/app.js' -> 'src/app.js'; None for anything else."""
    path = target.removeprefix(prefix) if target.startswith(prefix) else target
    try:
        return code_files.check_rel_path(path)
    except code_files.CodeFileError:
        return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _scan(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    agent_run_id: UUID,
    target: str,
    body: CodeScanIn,
) -> None:
    assessment_id = agent_run_repo.get(db, agent_run_id).assessment_id
    completed = 0
    for index, tool in enumerate(TOOLS):
        if not _next_step(db, agent_run_id, "SCANNING", 10 + 40 * index):
            return
        action = await actions.send_action(
            db,
            interfaces,
            mask,
            settings,
            operator,
            assessment_id,
            ActionIn(tool=tool, target=target),
            agent_run_id=agent_run_id,
        )
        if action.action_status == ActionStatus.COMPLETED:
            completed += 1
        else:
            _add_note(db, agent_run_id, f"{tool} {action.action_status}")
    if completed == 0:
        raise ApiError(502, "TOOLS_FAILED", "No scanner finished.")
    if body.analyze and _next_step(db, agent_run_id, "ANALYZING", 85):
        await _analyze(db, interfaces, mask, operator, agent_run_id, assessment_id)
    _finish(db, interfaces, operator, agent_run_id)


async def _analyze(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    agent_run_id: UUID,
    assessment_id: UUID,
) -> None:
    """The scan's findings stay useful without the agent, so its failure is only a note.
    analysis.analyze ends its own ANALYZE run FAILED before it raises."""
    try:
        result = await analysis.analyze(db, interfaces, mask, operator, assessment_id)
    except Exception as error:
        db.rollback()
        code = error.code if isinstance(error, ApiError) else "UNEXPECTED_ERROR"
        if code != "NO_FINDINGS":
            _add_note(db, agent_run_id, f"ANALYZE {code}")
        return
    run = agent_run_repo.get_for_update(db, agent_run_id)
    _update_plan(run, analysis_run_id=str(result.agent_run.agent_run_id))
    db.commit()


def _next_step(db: Db, agent_run_id: UUID, stage: str, progress: int) -> bool:
    """Records the step; False when the scan was cancelled and must stop."""
    run = agent_run_repo.get_for_update(db, agent_run_id)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        db.commit()
        return False
    _update_plan(run, stage=stage, progress=progress)
    db.commit()
    return True


def _add_note(db: Db, agent_run_id: UUID, note: str) -> None:
    run = agent_run_repo.get_for_update(db, agent_run_id)
    _update_plan(run, notes=[*run.plan.get("notes", []), note])
    db.commit()


def _finish(db: Db, interfaces: Interfaces, operator: Operator, agent_run_id: UUID) -> None:
    run = agent_run_repo.get_for_update(db, agent_run_id)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        db.commit()  # cancelled meanwhile: it keeps that end
        return
    _update_plan(run, stage="DONE", progress=100)
    found = len(finding_repo.list_by_agent_run(db, agent_run_id))
    details = {"task": TASK, "findings": str(found)}
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.COMPLETED, details)


def _fail(
    db: Db, interfaces: Interfaces, operator: Operator, agent_run_id: UUID, error: Exception
) -> None:
    db.rollback()
    run = agent_run_repo.get_for_update(db, agent_run_id)
    if run is None or run.agent_runs_status != AgentRunStatus.RUNNING:
        db.commit()
        return
    code = error.code if isinstance(error, ApiError) else "UNEXPECTED_ERROR"
    reason = error.details.get("reason") if isinstance(error, ApiError) else None
    _update_plan(run, stage="DONE", error=f"{code}: {reason}" if reason else code)
    details = {"task": TASK, "code": code}
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.FAILED, details)


def _update_plan(run: AgentRun, **changes: Any) -> None:
    """A new dict, so the JSONB column is saved (changing it in place is not seen)."""
    run.plan = {**(run.plan or {}), **changes}


def _get_scan(db: Db, agent_run_id: UUID, lock: bool = False) -> AgentRun:
    get = agent_run_repo.get_for_update if lock else agent_run_repo.get
    run = get(db, agent_run_id)
    if run is None or (run.plan or {}).get("task") != TASK:
        raise ApiError(404, "CODE_SCAN_NOT_FOUND", "No code scan with this id.")
    return run


def _proof(content: str | None) -> dict[str, Any]:
    try:
        proof = json.loads(content or "{}")
    except json.JSONDecodeError:
        return {}
    return proof if isinstance(proof, dict) else {}


def _int(proof: dict[str, Any], *paths: tuple[str, ...]) -> int | None:
    """The first whole number found at one of the paths, e.g. ("start", "line")."""
    for path in paths:
        value: Any = proof
        for key in path:
            value = value.get(key) if isinstance(value, dict) else None
        if isinstance(value, int) and value > 0:
            return value
    return None


def _line(file: Path, number: int) -> str:
    with file.open(encoding="utf-8", errors="replace") as text:
        for index, line in enumerate(text, start=1):
            if index == number:
                return line.strip()
    return ""
