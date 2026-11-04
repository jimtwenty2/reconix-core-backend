"""Code scans: the 7 source code tools on the session's code, then an AI review of each
finding (services/code_review.py).

A scan is an agent run with plan = {"task": "CODE_SCAN", "stage", "progress", "notes",
"error", "paths", "tools", "tool_versions", "scanned", "full", "carried", "reviews"}.
The route answers at once, and the scan goes on in the background with its own database
session. Each tool runs through actions.send_action, so it gets the 5 checks, the second
check and its audit lines like any other action.

A rescan reads only what changed since the last COMPLETED scan (plan.scanned holds each
file's sha256): semgrep and gitleaks read the changed files, the dependency tools run when
a manifest or lockfile changed, sonar_scan when anything changed. Earlier findings on
unchanged files are kept (plan.carried). The first scan, a new tool or new tool versions
in Kali make a full scan.

The tools read a copy made for this run, <session>/_reconix_scan_<run8>/, every file in
reconix-<session hex>/ and the changed ones in changed/, so every tool call has its own
target and the loop check never sees a repeat. tool_runs turns
the copy's paths back into the code folder's before the findings are saved.

Cancelling marks the run CANCELLED at once. The scan sees it before its next step and
stops; a tool that is already running finishes, and its findings are kept.
"""

import asyncio
import hashlib
import json
import logging
import re
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy.orm import Session as Db
from sqlalchemy.orm import sessionmaker

from reconix_ai.harness.catalog import canonical
from reconix_api.core import code_files
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    ApprovedScope,
    Interfaces,
    Operator,
    RiskLevel,
    ToolJob,
    ToolName,
    ToolRunStatus,
    WriteAudit,
)
from reconix_api.core.job_token import sign_job_token
from reconix_api.core.masking import MaskSecrets
from reconix_api.findings import code_notes
from reconix_api.models import AgentRun, Finding
from reconix_api.models.enums import (
    ActionStatus,
    AgentRunStatus,
    AssessmentStatus,
    FindingStatus,
    SeverityStatus,
)
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.actions import ActionIn
from reconix_api.schemas.code import CODE_TOOLS, CodeFindingOut, CodeScanIn, CodeScanOut, Verdict
from reconix_api.schemas.scopes import ScopeDraft, ScopeSubmit, ScopeTargetIn
from reconix_api.services import actions, agent_runs, code, code_review, findings, plans, scopes
from reconix_api.services.audit import audit

logger = logging.getLogger(__name__)

TASK = "CODE_SCAN"
CHANGED = "changed"  # the copy folder of the files that changed
ALL = "all"  # the copy folder of every file in the scan (named by code_files.all_copy_name)
CHANGED_TOOLS = {ToolName.SEMGREP, ToolName.GITLEAKS}
DEPENDENCY_TOOLS = {ToolName.TRIVY, ToolName.GRYPE, ToolName.OSV_SCANNER, ToolName.SYFT}
MANIFEST = re.compile(
    r"requirements[^/]*\.txt|pyproject\.toml|poetry\.lock|uv\.lock|Pipfile|Pipfile\.lock"
    r"|package\.json|package-lock\.json|yarn\.lock|pnpm-lock\.yaml|go\.mod|go\.sum|Cargo\.lock"
    r"|pom\.xml|build\.gradle|build\.gradle\.kts|gradle\.lockfile|Gemfile\.lock|composer\.lock"
    r"|packages\.lock\.json|pubspec\.lock|mix\.lock"
)
TOOLS_INFO_TIMEOUT_SECONDS = 60
ANALYZE_PROGRESS = 85  # progress when the AI review starts; it moves to 99 as reviews finish
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
    to scan; 422 CODE_EXCLUDED when the scope excludes the whole code folder; 422
    PATH_NOT_FOUND when a path holds no stored file; 422 NO_CODE_TOOLS when the scope
    allows none of the code scan tools."""
    actions.ensure_can_act(db, assessment_id)
    session_id = assessment_repo.get(db, assessment_id).session_id
    target = code_files.container_path(session_id)
    scope = plans.approved_scope(interfaces, assessment_id)
    skip = excluded_folders(scope, target)
    tools = scan_tools(scope, body.tools)
    # Two starts at once: the second one waits. The session row too: code being cloned or
    # copied holds it (code.ensure_not_scanning), also before the first scan's assessment.
    session_repo.get_for_update(db, session_id)
    assessment_repo.lock(db, assessment_id)
    if agent_run_repo.running_code_scan(db, assessment_id) is not None:
        raise ApiError(409, "SCAN_RUNNING", "A code scan of this assessment is still running.")
    folder = code_files.session_folder(settings.code_dir, session_id)
    removed = code_files.remove_excluded(folder, skip)
    stored = code_files.scan_files(folder, [])
    if not stored:
        raise ApiError(422, "NO_CODE", "Send the code first with /sessions/{id}/code.")
    missing = [path for path in body.paths if not any(_under(file, [path]) for file in stored)]
    if missing:
        message = "No stored file is at or under these paths."
        raise ApiError(422, "PATH_NOT_FOUND", message, {"paths": missing})

    run = agent_runs.new_agent_run(db, operator, assessment_id, task=TASK)
    run.plan = {
        "task": TASK,
        "stage": "SCANNING",
        "progress": 0,
        "notes": [],
        "paths": body.paths,
        "tools": tools,
    }
    db.commit()
    details = {
        "agent_run_id": str(run.agent_run_id),
        "analyze": str(body.analyze),
        "excluded_files_removed": str(removed),
        "tools": ",".join(tools),
        "paths": str(len(body.paths)),  # a count: the audit never holds file names
    }
    audit(interfaces.write_audit, "CODE_SCAN_STARTED", operator, assessment_id, details)

    scan = run_scan(
        session_factory, interfaces, mask, settings, operator, run.agent_run_id, target, body
    )
    task = asyncio.create_task(scan)
    _running.add(task)
    task.add_done_callback(_running.discard)
    return scan_out(db, run)


def session_assessment(
    db: Db,
    interfaces: Interfaces,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    tools: list[ToolName] | None,
) -> UUID:
    """The assessment a scan of this session's own code runs in. A scope that is only the
    session's code folder needs no person to approve it: the code is theirs, and the code
    tools only read it. Reuses the session's ACTIVE assessment when its scope is exactly
    that folder and allows the tools; otherwise drafts, submits and approves that scope
    (one SCOPE_APPROVED line, reason CODE_SESSION_FOLDER).

    409 CODE_SCOPE_MISMATCH when the session's assessment has another scope, 409
    ASSESSMENT_NOT_ACTIVE when it has ended, 409 SCOPE_PENDING while one waits."""
    code.ensure_own_open_session(db, operator, session_id)
    target = code_files.container_path(session_id)
    code_files.check_code_path(target)  # built here from the id, never from the request
    assessment = assessment_repo.get_by_session(db, session_id)
    if assessment is not None and assessment.assessment_status == AssessmentStatus.ACTIVE:
        scope = plans.approved_scope(interfaces, assessment.assessment_id)
        if is_code_folder_scope(scope, target, tools or list(CODE_TOOLS)):
            return assessment.assessment_id
        raise ApiError(
            409,
            "CODE_SCOPE_MISMATCH",
            "This session's assessment has another scope. "
            "Scan it with /assessments/{id}/code-scans.",
            {"assessment_id": str(assessment.assessment_id)},
        )
    if assessment is not None and assessment.assessment_status != AssessmentStatus.DRAFT:
        raise ApiError(
            409,
            "ASSESSMENT_NOT_ACTIVE",
            f"This session's assessment is {assessment.assessment_status}.",
            {"assessment_status": assessment.assessment_status},
        )
    draft = ScopeDraft(
        max_risk=RiskLevel.LOW,
        allowed_tools=list(CODE_TOOLS),
        targets=[ScopeTargetIn(type="path", value=target)],
    )
    write_audit = interfaces.write_audit
    scope_out = scopes.create_draft(db, write_audit, operator, session_id, draft)
    submitted = scopes.submit(
        db,
        write_audit,
        operator,
        scope_out.manifest_id,
        ScopeSubmit(name=f"Code of session {str(session_id)[:8]}", type="source_code"),
        settings.approval_ttl_minutes,
    )
    approval = approval_repo.get_for_update(db, submitted.approval_id)
    scopes.approve_scope(db, write_audit, operator, approval, reason=scopes.CODE_SESSION_FOLDER)
    return submitted.assessment.assessment_id


def is_code_folder_scope(scope: ApprovedScope, target: str, tools: list[ToolName]) -> bool:
    """True when the scope is exactly the code folder, with nothing excluded, and allows
    every one of the tools."""
    others = scope.ip_ranges or scope.domains or scope.url_prefixes or scope.excluded_targets
    return scope.repo_paths == [target] and not others and set(tools) <= set(scope.allowed_tools)


def scan_tools(scope: ApprovedScope, tools: list[ToolName] | None) -> list[str]:
    """The tools asked for, or every code scan tool the scope allows, in CODE_TOOLS order.
    A tool asked for that the scope does not allow is BLOCKED by the checks: a note."""
    wanted = set(tools) if tools is not None else set(scope.allowed_tools)
    chosen = [str(tool) for tool in CODE_TOOLS if tool in wanted]
    if not chosen:
        raise ApiError(422, "NO_CODE_TOOLS", "The scope allows none of the code scan tools.")
    return chosen


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
            await _scan(
                db,
                session_factory,
                interfaces,
                mask,
                settings,
                operator,
                agent_run_id,
                target,
                body,
            )
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
    """When a session closes, its running code scan ends CANCELLED (one audit line)."""
    assessment = assessment_repo.get_by_session(db, session_id)
    run = assessment and agent_run_repo.running_code_scan(db, assessment.assessment_id)
    if not run:
        return
    _update_plan(run, stage="DONE")
    agent_runs.finish(run, AgentRunStatus.CANCELLED)
    db.commit()
    details = {"agent_run_id": str(run.agent_run_id), "task": TASK}
    audit(write_audit, "AGENT_RUN_CANCELLED", operator, run.assessment_id, details)


def read_scan(db: Db, agent_run_id: UUID) -> CodeScanOut:
    return scan_out(db, _get_scan(db, agent_run_id))


def ensure_own_scan(db: Db, operator: Operator, agent_run_id: UUID) -> None:
    """The scan must be of the caller's own session's code. 404 CODE_SCAN_NOT_FOUND,
    403 NOT_YOUR_SCAN."""
    run = _get_scan(db, agent_run_id)
    if assessment_repo.get(db, run.assessment_id).session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SCAN", "This code scan is of another session's code.")


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
    db: Db,
    settings: Settings,
    mask: MaskSecrets,
    agent_run_id: UUID,
    include_false_positives: bool = True,
) -> list[CodeFindingOut]:
    """The findings of this scan, with the ones kept from earlier scans, with their place
    in the code and their AI review. Without include_false_positives, the LIKELY_FALSE_POSITIVE
    ones are left out, except a leak or a HIGH or CRITICAL finding only the AI calls false:
    text in the scanned code can sway the AI, never a person's decision."""
    run = _get_scan(db, agent_run_id)
    session_id = assessment_repo.get(db, run.assessment_id).session_id
    folder = code_files.session_folder(settings.code_dir, session_id)
    prefix = code_files.container_path(session_id) + "/"
    reviews = (run.plan or {}).get("reviews", {})
    found = [
        code_finding_out(db, mask, folder, prefix, row, reviews.get(str(row.finding_id)))
        for row in scan_rows(db, run)
    ]
    if include_false_positives:
        return found
    return [finding for finding in found if not _hidden_as_false(finding)]


def _hidden_as_false(finding: CodeFindingOut) -> bool:
    if finding.verdict != Verdict.LIKELY_FALSE_POSITIVE:
        return False
    if finding.finding_status == FindingStatus.FALSE_POSITIVE:
        return True  # a person decided
    serious = finding.severity_status in (SeverityStatus.HIGH, SeverityStatus.CRITICAL)
    return not serious and ToolName.GITLEAKS not in finding.tools


def scan_log(db: Db, agent_run_id: UUID, tool: str) -> str:
    """The masked output of the tool's run in this scan, e.g. sonar_scan's text log.
    404 TOOL_LOG_NOT_FOUND when the tool left no output in it."""
    _get_scan(db, agent_run_id)
    name = canonical(tool)
    outputs = [
        tool_run.output_masked
        for action in action_repo.list_by_agent_run(db, agent_run_id)
        if canonical(action.tool) == name
        for tool_run in action_repo.list_tool_runs(db, action.action_id)
        if tool_run.output_masked
    ]
    if not outputs:
        raise ApiError(404, "TOOL_LOG_NOT_FOUND", "This tool left no output in this scan.")
    return outputs[-1]


def scan_rows(db: Db, run: AgentRun) -> list[Finding]:
    """The scan's own findings, then the ones it carried over, at or under its paths."""
    rows = _own_and_carried(db, run)
    paths = (run.plan or {}).get("paths") or []
    if not paths:
        return rows
    session_id = assessment_repo.get(db, run.assessment_id).session_id
    prefix = code_files.container_path(session_id) + "/"
    return [row for row in rows if _under(relative_path(row.target, prefix), paths)]


def _own_and_carried(db: Db, run: AgentRun) -> list[Finding]:
    """Also the carried findings outside the scan's paths: a later scan carries them on."""
    own = finding_repo.list_by_agent_run(db, run.agent_run_id)
    seen = {row.finding_id for row in own}
    ids = (run.plan or {}).get("carried", [])
    carried = [finding_repo.get(db, UUID(finding_id)) for finding_id in ids]
    return own + [row for row in carried if row is not None and row.finding_id not in seen]


def scan_out(db: Db, run: AgentRun) -> CodeScanOut:
    plan = run.plan or {}
    counts = {severity: 0 for severity in SeverityStatus}
    for row in scan_rows(db, run):
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
    )


def code_finding_out(
    db: Db,
    mask: MaskSecrets,
    folder: Path,
    prefix: str,
    row: Finding,
    review: dict[str, Any] | None = None,
) -> CodeFindingOut:
    """Path and line come from the finding's newest evidence, the rest from the stored
    file, the verdict from the review (plan.reviews). A gitleaks finding never gets a
    snippet: its line is the secret."""
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
        verdict=code_review.verdict_of(out, review),
        explanation=review.get("explanation") if review else None,
        fix_recommendation=review.get("fix_recommendation") if review else None,
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
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    agent_run_id: UUID,
    target: str,
    body: CodeScanIn,
) -> None:
    run = agent_run_repo.get(db, agent_run_id)
    assessment_id = run.assessment_id
    tools = run.plan["tools"]
    session_id = assessment_repo.get(db, assessment_id).session_id
    folder = code_files.session_folder(settings.code_dir, session_id)
    files = code_files.scan_files(folder, body.paths)
    scanned = await asyncio.to_thread(_hashes, files)  # up to max_upload_mb of code
    previous = agent_run_repo.latest_completed_code_scan(db, assessment_id)
    before = (previous.plan or {}) if previous else {}
    full = previous is None or not set(tools) <= set(before.get("tools", []))
    known = before.get("scanned", {})
    inside = {path: sha256 for path, sha256 in known.items() if _in_scan(path, body.paths)}
    changed, deleted = changes(scanned, inside)  # files outside the paths are not deleted
    versions = before.get("tool_versions")
    if full or changed or deleted:  # nothing changed: no call to Kali at all
        versions = await kali_versions(db, interfaces, settings, agent_run_id)
        full = full or versions is None or versions != before.get("tool_versions")
    if full:
        changed, deleted = set(scanned), set()
    due = due_tools(tools, changed, deleted, full)
    if not _next_step(db, agent_run_id, "SCANNING", 5):
        return  # cancelled while Kali answered: the code may be gone already
    _set_plan(db, agent_run_id, tool_versions=versions, full=full)

    copy = folder / f"{code_files.SCAN_FOLDER_PREFIX}{agent_run_id.hex[:8]}"
    names = {ALL: code_files.all_copy_name(session_id), CHANGED: CHANGED}
    try:
        await asyncio.to_thread(_make_copy, copy, names, files, changed, due)
        targets = {tool: f"{target}/{copy.name}/{names[kind]}" for tool, kind in due.items()}
        completed = await _run_tools(
            db, interfaces, mask, settings, operator, agent_run_id, targets
        )
    finally:
        shutil.rmtree(copy, ignore_errors=True)
    if completed is None:
        return  # cancelled
    if due and not completed:
        raise ApiError(502, "TOOLS_FAILED", "No scanner finished.")
    carried = []
    if not full:
        ran = Ran(due, completed, changed, body.paths)
        own = {row.finding_id for row in finding_repo.list_by_agent_run(db, agent_run_id)}
        carried = carry_over(db, previous, tools, scanned, ran, own)
    kept = baseline(scanned, changed, due, completed)
    if not full:  # files outside the paths keep what the last scan knew of them
        kept |= {path: sha256 for path, sha256 in known.items() if path not in inside}
    _set_plan(db, agent_run_id, scanned=kept, carried=carried)
    # Also when nothing ran: the carried findings get their earlier reviews back.
    if body.analyze and _next_step(db, agent_run_id, "ANALYZING", ANALYZE_PROGRESS):
        unread = unread_by_gitleaks(tools, scanned, changed, due, completed)
        await _analyze(db, session_factory, settings, mask, agent_run_id, unread)
    _finish(db, interfaces, operator, agent_run_id)


async def _run_tools(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    agent_run_id: UUID,
    targets: dict[str, str],
) -> set[str] | None:
    """One action per due tool, on its copy folder. Returns the tools that COMPLETED, or
    None when the scan was cancelled. A tool that is BLOCKED or does not finish is a note."""
    assessment_id = agent_run_repo.get(db, agent_run_id).assessment_id
    completed = set()
    for index, (tool, folder) in enumerate(targets.items()):
        if not _next_step(db, agent_run_id, "SCANNING", 10 + 70 * index // len(targets)):
            return None
        try:
            action = await actions.send_action(
                db,
                interfaces,
                mask,
                settings,
                operator,
                assessment_id,
                ActionIn(tool=tool, target=folder),
                agent_run_id=agent_run_id,
            )
        except ApiError as error:
            if error.code != "ACTION_BLOCKED":
                raise
            reason = error.details.get("reason")  # e.g. TOO_MANY_ACTIONS, RUN_LIMIT_REACHED
            _add_note(db, agent_run_id, f"{tool} {ActionStatus.BLOCKED} {reason or ''}".strip())
            continue
        if action.action_status != ActionStatus.COMPLETED:
            _add_note(db, agent_run_id, f"{tool} {action.action_status}")
            continue
        completed.add(tool)
        note = code_notes.tool_note(tool, action.tool_runs[-1].output_masked or "")
        if note:
            _add_note(db, agent_run_id, note)
    return completed


async def kali_versions(
    db: Db, interfaces: Interfaces, settings: Settings, agent_run_id: UUID
) -> dict[str, str] | None:
    """The code tools' versions from Kali's tools_info; None, and a note, when it gives
    none. Called directly, not as an action: tools_info reads no target and changes
    nothing. Its job token names a tool run that is never saved."""
    tool_run_id = uuid4()
    try:
        token = sign_job_token(
            tool_run_id,
            hashlib.sha256(b"tools_info").hexdigest(),
            settings.job_token_secret.get_secret_value(),
            datetime.now(UTC),
            settings.job_token_ttl_seconds,
        )
        job = ToolJob(
            tool_run_id=tool_run_id,
            tool="tools_info",
            target="",
            arguments=[],
            job_token=token,
            timeout_seconds=TOOLS_INFO_TIMEOUT_SECONDS,
        )
        result = await interfaces.call_tool(job)
        if result.status == ToolRunStatus.COMPLETED:
            versions = code_notes.tool_versions(result.stdout)
            if versions:
                return versions
    except Exception as error:  # noqa: BLE001 - without versions the scan is a full one
        logger.warning("tools_info failed: %s", type(error).__name__)
    _add_note(db, agent_run_id, "TOOLS_INFO FAILED")
    return None


def changes(scanned: dict[str, str], before: dict[str, str]) -> tuple[set[str], set[str]]:
    """(changed, deleted): files that are new or whose sha256 differs, and files gone."""
    changed = {path for path, sha256 in scanned.items() if before.get(path) != sha256}
    return changed, set(before) - set(scanned)


def due_tools(tools: list[str], changed: set[str], deleted: set[str], full: bool) -> dict[str, str]:
    """Tool -> the copy folder it reads, for each selected tool this scan must run.
    semgrep and gitleaks read the changed files; the dependency tools read every file when
    a manifest or lockfile changed (or on a full scan); sonar_scan when anything changed."""
    touched = changed | deleted
    manifests = full or any(is_manifest(path) for path in touched)
    due = {}
    for tool in tools:
        if tool in CHANGED_TOOLS and changed:
            due[tool] = CHANGED
        elif (tool in DEPENDENCY_TOOLS and manifests) or (tool == ToolName.SONAR_SCAN and touched):
            due[tool] = ALL
    return due


def is_manifest(path: str) -> bool:
    return bool(MANIFEST.fullmatch(path.rsplit("/", 1)[-1]))


@dataclass(frozen=True)
class Ran:
    """What this scan's tools did: due (tool -> copy folder), the ones that COMPLETED, the
    changed files and the scan's paths."""

    due: dict[str, str]
    completed: set[str]
    changed: set[str]
    paths: list[str]


def carry_over(
    db: Db,
    previous: AgentRun | None,
    tools: list[str],
    scanned: dict[str, str],
    ran: Ran,
    own: set[UUID],
) -> list[str]:
    """The ids of the previous scan's findings that still hold without a new run, from one
    of the selected tools:
    - outside this scan's paths: nothing read their file;
    - on an unchanged file: the tool did not read it again (semgrep and gitleaks read only
      changed files; a dependency tool that ran read them all);
    - on a changed file: every tool that found it was due and did not finish, so nothing
      read the file yet (the next scan does).
    A deleted file's findings are dropped."""
    if previous is None:
        return []
    session_id = assessment_repo.get(db, previous.assessment_id).session_id
    prefix = code_files.container_path(session_id) + "/"
    reread = {tool for tool in ran.completed if ran.due[tool] == ALL}
    failed = set(ran.due) - ran.completed
    carried = []
    for row in _own_and_carried(db, previous):
        path = relative_path(row.target, prefix)
        found_by = {tool for _, tool in finding_repo.sources(db, row.finding_id)} & set(tools)
        if row.finding_id in own or not found_by:
            continue
        if path is not None and not _in_scan(path, ran.paths):
            keep = True
        elif path not in scanned:
            keep = False
        elif path in ran.changed:
            keep = found_by <= failed
        else:
            keep = bool(found_by - reread)
        if keep:
            carried.append(str(row.finding_id))
    return carried


def unread_by_gitleaks(
    tools: list[str],
    scanned: dict[str, str],
    changed: set[str],
    due: dict[str, str],
    completed: set[str],
) -> set[str]:
    """The files no gitleaks run read as they are now. The AI review gets none of their
    code: a secret on them would not be found, so not [MASKED]. An unchanged file was read
    by an earlier scan (a file a failed gitleaks missed counts as changed, see baseline)."""
    if ToolName.GITLEAKS not in tools:
        return set(scanned)
    if ToolName.GITLEAKS in due and ToolName.GITLEAKS not in completed:
        return set(changed)
    return set()


def baseline(
    scanned: dict[str, str], changed: set[str], due: dict[str, str], completed: set[str]
) -> dict[str, str]:
    """The file hashes the next scan compares with. A file a due tool could not read counts
    as changed next time, so that tool reads it then. sonar_scan gives no findings."""
    failed = {due[tool] for tool in due if tool not in completed and tool != ToolName.SONAR_SCAN}
    return {
        path: sha256
        for path, sha256 in scanned.items()
        if not (CHANGED in failed and path in changed) and not (ALL in failed and is_manifest(path))
    }


def recover_interrupted(db: Db, code_dir: str) -> None:
    """At startup: a scan cut off by a restart ends FAILED with INTERRUPTED, and the copy
    folders scans left behind are deleted."""
    for run in agent_run_repo.running_code_scans(db):
        _update_plan(run, stage="DONE", error="INTERRUPTED")
        agent_runs.finish(run, AgentRunStatus.FAILED)
    db.commit()
    for copy in Path(code_dir).resolve().glob(f"*/{code_files.SCAN_FOLDER_PREFIX}*"):
        shutil.rmtree(copy, ignore_errors=True)


def _hashes(files: dict[str, Path]) -> dict[str, str]:
    return {path: code_files.file_sha256(file) for path, file in files.items()}


def _make_copy(
    copy: Path,
    names: dict[str, str],
    files: dict[str, Path],
    changed: set[str],
    due: dict[str, str],
) -> None:
    if ALL in due.values():
        code_files.link_files(copy / names[ALL], files)
    if CHANGED in due.values():
        code_files.link_files(copy / names[CHANGED], {path: files[path] for path in changed})


def _under(path: str | None, paths: list[str]) -> bool:
    """True when the relative path is one of the paths or inside one."""
    return path is not None and code_files.is_excluded(path, paths)


def _in_scan(path: str, paths: list[str]) -> bool:
    """True when a scan with these paths reads the file (no paths: every file)."""
    return not paths or _under(path, paths)


async def _analyze(
    db: Db,
    session_factory: sessionmaker[Db],
    settings: Settings,
    mask: MaskSecrets,
    agent_run_id: UUID,
    unread: set[str],
) -> None:
    """The AI review of the scan's findings, kept in plan.reviews. The findings stay useful
    without it, so a failure is only a note. The files in unread send no code."""
    try:
        provider = agent_runs.make_provider_for_run(session_factory, settings)(agent_run_id)
        run = agent_run_repo.get(db, agent_run_id)
        session_id = assessment_repo.get(db, run.assessment_id).session_id
        folder = code_files.session_folder(settings.code_dir, session_id)
        prefix = code_files.container_path(session_id) + "/"
        found = [code_finding_out(db, mask, folder, prefix, row) for row in scan_rows(db, run)]
        earlier = agent_run_repo.code_scan_reviews(db, run.assessment_id)
        carried = set(run.plan.get("carried", []))
        db.commit()  # no transaction stays open while the model answers
        hidden = code_review.Hidden(secret_lines(found), unread)

        def reviewed(done: int, total: int) -> None:
            # A slow model would otherwise look stuck at ANALYZE_PROGRESS. Best effort:
            # a failed update must not stop the reviews or leave the row locked.
            try:
                _set_plan(db, agent_run_id, progress=ANALYZE_PROGRESS + 14 * done // total)
            except Exception:  # noqa: BLE001
                db.rollback()

        reviews, note = await code_review.review_scan(
            found, carried, earlier, folder, mask, hidden, provider, reviewed
        )
    except Exception as error:
        db.rollback()
        if not isinstance(error, ApiError):
            logger.warning("Code review of scan %s failed: %s", agent_run_id, type(error).__name__)
        code = error.code if isinstance(error, ApiError) else "UNEXPECTED_ERROR"
        _add_note(db, agent_run_id, f"ANALYZE {code}")
        return
    _set_plan(db, agent_run_id, reviews=reviews)
    if note:
        _add_note(db, agent_run_id, note)


def secret_lines(found: list[CodeFindingOut]) -> dict[str, set[int]]:
    """Path -> the lines of the findings whose line may be a secret. The AI review shows
    them as [MASKED]: the masker cannot know every secret."""
    hidden: dict[str, set[int]] = {}
    for finding in found:
        if (
            finding.path
            and finding.line
            and may_hold_secret(finding.tools, finding.rule_id, finding.cwe_ids)
        ):
            end = finding.end_line or finding.line
            hidden.setdefault(finding.path, set()).update(range(finding.line, end + 1))
    return hidden


def _next_step(db: Db, agent_run_id: UUID, stage: str, progress: int) -> bool:
    """Records the step; False when the scan was cancelled and must stop."""
    run = agent_run_repo.get_for_update(db, agent_run_id)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        db.commit()
        return False
    _update_plan(run, stage=stage, progress=progress)
    db.commit()
    return True


def _set_plan(db: Db, agent_run_id: UUID, **changes: Any) -> None:
    run = agent_run_repo.get_for_update(db, agent_run_id)
    _update_plan(run, **changes)
    db.commit()


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
    found = len(scan_rows(db, run))
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
