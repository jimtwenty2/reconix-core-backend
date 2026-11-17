"""Code fixes: an AI agent per file proposes line edits for code scan findings (VS Code).

A fix run is an agent run with plan = {"task": "CODE_FIX", "stage", "scan_id",
"finding_ids", "error", "result", "tokens"}. The route answers at once; the fix goes on
in the background with its own database session, like a code scan. The agents
(reconix_ai.agent.code_fix) work on an in-memory copy of each file: nothing is written to
the stored code or to the person's files. The result is line edits VS Code shows as a
diff and applies only when the person says so.

Rechecks run SEMGREP on the edited files, copied for each check into
<session>/_reconix_scan_<random8>/changed/, through actions.send_action: the 5 checks,
the second check and the audit lines like any other action. Their output is kept on the
tool run but saves no findings (tool_runs), since the edited code is only a proposal.

What the model sees is masked: secrets as [MASKED:<kind>], and every line of a finding
that may be a secret (code_scans.secret_lines) as [MASKED]. A file the last scan did not
read as it is now sends no code: its line numbers and its gitleaks check would be stale.

The live transcript is in memory (core/fix_events.py), masked, never logged. The audit
log has CODE_FIX_STARTED and the run's end (AGENT_RUN_COMPLETED / FAILED / CANCELLED),
with ids and counts only.
"""

import asyncio
import difflib
import hashlib
import logging
import re
import secrets
import shutil
from collections import Counter
from collections.abc import AsyncIterator, Awaitable, Callable, Coroutine
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session as Db
from sqlalchemy.orm import sessionmaker

from reconix_ai import providers
from reconix_ai.agent import code_fix
from reconix_ai.agent.code_fix import Budget, FileCopy, FixStopped, FixTarget
from reconix_ai.providers import ProviderError, ToolReply
from reconix_api.core import code_files
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.fix_events import FIX_EVENTS
from reconix_api.core.interfaces import GetOperator, Interfaces, Operator, ToolName, WriteAudit
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import AgentRun
from reconix_api.models.enums import ActionStatus, AgentRunStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.actions import ActionIn
from reconix_api.schemas.code import CodeFindingOut
from reconix_api.schemas.code_fixes import CodeFixIn, CodeFixOut, CodeFixResult, CodeFixStarted
from reconix_api.services import actions, agent_runs, code, code_scans
from reconix_api.services.audit import audit
from reconix_api.services.chat_functions import newest_scan
from reconix_api.services.findings import parse_run
from reconix_api.services.stream import sse

logger = logging.getLogger(__name__)

# A module attribute, so tests can swap in a fake model.
complete_with_tools = providers.complete_with_tools

TASK = "CODE_FIX"
TOKEN_BUDGET = 400_000  # tokens all agents of one fix may spend together
MAX_PARALLEL = 3  # files fixed at once
FIX_TIMEOUT_SECONDS = 30 * 60  # the whole fix
MAX_FILE_BYTES = 1_000_000  # a larger file is not sent to the model
CHECK_TOOL = ToolName.SEMGREP  # the scanner a fix is rechecked with
DEPENDENCY_TOOLS = {ToolName.TRIVY, ToolName.GRYPE, ToolName.OSV_SCANNER, ToolName.SYFT}
HIDDEN_LINE = "[MASKED]"

LEAK_NOTE = (
    "A leaked secret is not fixed by changing code: rotate it, then remove it from the "
    "code and its history."
)
DEPENDENCY_NOTE = (
    "Upgrade the package to a fixed version in its manifest and reinstall; the fix agent "
    "does not change dependencies."
)
NO_PLACE_NOTE = "This finding has no line in the code to change."
CHANGED_NOTE = "The file changed since the last scan. Rescan it, then fix."
NOT_TEXT_NOTE = "The file is not a UTF-8 text file, so it is not changed."
TOO_LARGE_NOTE = "The file is too large to send to the model. Fix it by hand."
GONE_NOTE = "The file is no longer in the stored code. Send the code again and rescan."
UNREAD_NOTE = (
    "The last scan did not check this code for secrets with GITLEAKS, so it is not sent to "
    "the model. Rescan with GITLEAKS, then fix."
)
REFUSED_NOTE = "The change holds text that looks like a secret. Fix it by hand."
MAX_AGENT_RECHECKS = 15  # agents' own rechecks per fix; the last recheck always runs
_running: set[asyncio.Task[None]] = set()  # keeps each fix alive until it ends


async def start_fix(
    db: Db,
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    body: CodeFixIn,
) -> CodeFixStarted:
    """403 NOT_YOUR_SESSION, 409 SESSION_CLOSED, 409 NO_FINISHED_SCAN when the session has
    no COMPLETED code scan, 409 SCAN_RUNNING or FIX_RUNNING while one runs in the session,
    422 FINDING_NOT_IN_SCAN for an id that is not in its latest finished scan, 503
    NO_ACTIVE_PROVIDER."""
    code.ensure_own_open_session(db, operator, session_id)
    assessment = assessment_repo.get_by_session(db, session_id)
    if assessment is None:
        raise ApiError(409, "NO_FINISHED_SCAN", "Scan the code before asking for a fix.")
    # Two starts at once: the second one waits, then sees the first one's run.
    session_repo.get_for_update(db, session_id)
    assessment_repo.lock(db, assessment.assessment_id)
    if agent_run_repo.running_code_scan(db, assessment.assessment_id) is not None:
        raise ApiError(409, "SCAN_RUNNING", "Wait for the code scan to end, or cancel it.")
    if agent_run_repo.running_code_fix(db, assessment.assessment_id) is not None:
        raise ApiError(409, "FIX_RUNNING", "A fix is already running in this session.")
    scan = newest_scan(db, session_id, finished=True)
    if scan is None:
        raise ApiError(409, "NO_FINISHED_SCAN", "Scan the code before asking for a fix.")
    wanted = list(dict.fromkeys(body.finding_ids))
    known = {row.finding_id for row in code_scans.scan_rows(db, scan)}
    unknown = [str(finding_id) for finding_id in wanted if finding_id not in known]
    if unknown:
        message = "These findings are not in the session's latest finished code scan."
        raise ApiError(422, "FINDING_NOT_IN_SCAN", message, {"finding_ids": unknown})

    run = agent_runs.new_agent_run(db, operator, scan.assessment_id, task=TASK)
    run.plan = {
        "task": TASK,
        "stage": "FIXING",
        "scan_id": str(scan.agent_run_id),
        "finding_ids": [str(finding_id) for finding_id in wanted],
    }
    db.commit()
    details = {
        "agent_run_id": str(run.agent_run_id),
        "scan_id": str(scan.agent_run_id),
        "findings": str(len(wanted)),
    }
    audit(interfaces.write_audit, "CODE_FIX_STARTED", operator, scan.assessment_id, details)

    FIX_EVENTS.open(run.agent_run_id)
    fix = run_fix(session_factory, interfaces, mask, settings, operator, run.agent_run_id)
    task = asyncio.create_task(fix)
    _running.add(task)
    task.add_done_callback(_running.discard)
    return CodeFixStarted(agent_run_id=run.agent_run_id)


async def run_fix(
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    run_id: UUID,
) -> None:
    """The fix itself. Any error ends the run FAILED with its code; nothing is raised."""
    with session_factory() as db:
        try:
            coroutine = _fix(db, session_factory, interfaces, mask, settings, operator, run_id)
            await asyncio.wait_for(coroutine, FIX_TIMEOUT_SECONDS)
        except FixStopped:
            db.rollback()  # cancelled: the cancel already ended the run
        except Exception as error:
            if not isinstance(error, (ApiError, ProviderError, TimeoutError)):
                logger.error("Code fix %s failed: %s", run_id, type(error).__name__)
            _fail(db, interfaces, operator, run_id, error)
        finally:
            FIX_EVENTS.end(run_id)


def read_fix(db: Db, operator: Operator, run_id: UUID) -> CodeFixOut:
    return fix_out(_get_own_fix(db, operator, run_id))


def cancel_fix(db: Db, interfaces: Interfaces, operator: Operator, run_id: UUID) -> CodeFixOut:
    """Ends the run CANCELLED at once (one AGENT_RUN_CANCELLED line) and stops its agents.
    409 FIX_ENDED when it has already ended."""
    run = _get_own_fix(db, operator, run_id, lock=True)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        raise ApiError(409, "FIX_ENDED", "This fix has already ended.")
    _update_plan(run, stage="DONE")
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.CANCELLED, {"task": TASK})
    FIX_EVENTS.stop(run_id)
    return fix_out(run)


def cancel_for_session(
    db: Db, write_audit: WriteAudit, operator: Operator, session_id: UUID
) -> None:
    """When a session closes, its running fix ends CANCELLED (one audit line)."""
    assessment = assessment_repo.get_by_session(db, session_id)
    found = assessment and agent_run_repo.running_code_fix(db, assessment.assessment_id)
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
    FIX_EVENTS.stop(run.agent_run_id)


def recover_interrupted(db: Db) -> None:
    """At startup: a fix cut off by a restart ends FAILED with INTERRUPTED. Its recheck
    copies are removed with the code scans' (code_scans.recover_interrupted)."""
    for run in agent_run_repo.running_code_fixes(db):
        _update_plan(run, stage="DONE", error="INTERRUPTED")
        agent_runs.finish(run, AgentRunStatus.FAILED)
    db.commit()


def ensure_own_fix(db: Db, operator: Operator, run_id: UUID) -> None:
    _get_own_fix(db, operator, run_id)


async def event_frames(
    session_factory: sessionmaker[Db],
    run_id: UUID,
    after: int,
    get_operator: GetOperator,
    token: str,
    heartbeat_seconds: float,
    is_disconnected: Callable[[], Awaitable[bool]],
) -> AsyncIterator[str]:
    """FIX_EVENT messages after seq `after`, live, with a heartbeat event when nothing
    happens; then one FIX_ENDED {agent_run_id, agent_runs_status} and the stream ends. It also ends
    when the client leaves or the session is closed."""
    seq = after
    while True:
        events = await FIX_EVENTS.wait(run_id, seq, heartbeat_seconds)
        if not _still_signed_in(get_operator, token):
            return
        for event in events:
            seq = event["seq"]
            yield sse("FIX_EVENT", event)
        state = FIX_EVENTS.get(run_id)
        if state is None or (state.ended and seq >= len(state.events)):
            with session_factory() as db:
                run = agent_run_repo.get(db, run_id)
                status = run.agent_runs_status if run else AgentRunStatus.FAILED
            yield sse("FIX_ENDED", {"agent_run_id": str(run_id), "agent_runs_status": str(status)})
            return
        if not events:
            if await is_disconnected():
                return
            heartbeat = {"agent_run_id": str(run_id), "seq": seq, "file": None}
            yield sse("FIX_EVENT", {**heartbeat, "kind": "HEARTBEAT", "text": ""})


def fix_out(run: AgentRun) -> CodeFixOut:
    plan = run.plan or {}
    result = plan.get("result")
    return CodeFixOut(
        agent_run_id=run.agent_run_id,
        agent_runs_status=run.agent_runs_status,
        started_at=run.started_at,
        finished_at=run.finished_at,
        session_id=run.session_id,
        assessment_id=run.assessment_id,
        finding_count=len(plan.get("finding_ids", [])),
        error=plan.get("error"),
        result=CodeFixResult.model_validate(result) if result else None,
    )


# ---------------------------------------------------------------------------
# Building the agents' input
# ---------------------------------------------------------------------------


def fix_target(finding: CodeFindingOut, note: str | None = None) -> FixTarget:
    """One finding as the agent gets it. note: why no agent may try it."""
    line = finding.line or 1
    return FixTarget(
        finding_id=str(finding.finding_id),
        path=finding.path or "",
        title=finding.title,
        severity=str(finding.severity_status),
        tools=list(finding.tools),
        start_line=line,
        end_line=max(finding.end_line or line, line),
        rule_id=finding.rule_id,
        cwe_ids=list(finding.cwe_ids),
        message=finding.description,
        advice=finding.fix_recommendation,
        not_fixable=note,
    )


def not_fixable(finding: CodeFindingOut) -> str | None:
    """Why no agent should try this finding, or None."""
    if ToolName.GITLEAKS in finding.tools:
        return LEAK_NOTE
    if (
        finding.tools
        and set(finding.tools) <= DEPENDENCY_TOOLS
        and code_scans.is_manifest(finding.path or "")
    ):
        return DEPENDENCY_NOTE
    if not finding.path or not finding.line:
        return NO_PLACE_NOTE
    return None


def file_copy(
    folder: Any,
    path: str,
    scanned_sha256: str | None,
    hidden: set[int],
    mask: MaskSecrets,
) -> FileCopy | str:
    """The file as its agent sees it, or the note why it is not sent: it is gone, not
    text, too large, or not the file the last scan read."""
    try:
        file = folder / code_files.check_rel_path(path)
    except code_files.CodeFileError:
        return GONE_NOTE
    if not file.is_file() or file.is_symlink():
        return GONE_NOTE
    data = file.read_bytes()
    if len(data) > MAX_FILE_BYTES:
        return TOO_LARGE_NOTE
    sha256 = hashlib.sha256(data).hexdigest()
    if sha256 != scanned_sha256:
        return CHANGED_NOTE
    if b"\x00" in data[:8192]:
        return NOT_TEXT_NOTE
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return NOT_TEXT_NOTE
    real = code_fix.split_lines(text)
    masked = masked_lines(real, mask)
    for number in hidden:
        if 0 < number <= len(masked):
            masked[number - 1] = HIDDEN_LINE
    return FileCopy(path, real, masked, sha256)


def masked_lines(real: list[str], mask: MaskSecrets) -> list[str]:
    """The masked view of each line. The whole text is masked at once, as the AI review
    does, so a secret over several lines (a private key) is found; a line whose masked
    text no longer lines up with one real line is hidden whole."""
    whole = mask("\n".join(real))[0].split("\n")
    view = [HIDDEN_LINE] * len(real)
    matcher = difflib.SequenceMatcher(None, real, whole, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal" or (tag == "replace" and i2 - i1 == j2 - j1):
            view[i1:i2] = whole[j1:j2]
    return view


def gitleaks_read(scan_plan: dict[str, Any]) -> bool:
    """True when GITLEAKS ran in the scan and did not fail or get blocked. Otherwise a
    secret the masker has no pattern for may be in the code, so none is sent (the AI
    review follows the same rule)."""
    if ToolName.GITLEAKS not in scan_plan.get("tools", []):
        return False
    return not any(str(note).startswith("GITLEAKS ") for note in scan_plan.get("notes", []))


def rule_key(rule_id: str | None, path: str | None) -> tuple[str, str]:
    return (rule_id or "", path or "")


# ---------------------------------------------------------------------------
# The fix
# ---------------------------------------------------------------------------


async def _fix(
    db: Db,
    session_factory: sessionmaker[Db],
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    run_id: UUID,
) -> None:
    run = agent_run_repo.get(db, run_id)
    plan = run.plan or {}
    scan = agent_run_repo.get(db, UUID(plan["scan_id"]))
    session_id = assessment_repo.get(db, run.assessment_id).session_id
    folder = code_files.session_folder(settings.code_dir, session_id)
    found = code_scans.list_scan_findings(db, settings, mask, scan.agent_run_id)
    by_id = {str(finding.finding_id): finding for finding in found}
    scanned = (scan.plan or {}).get("scanned", {})
    hidden = code_scans.secret_lines(found)
    secrets_checked = gitleaks_read(scan.plan or {})

    targets: list[FixTarget] = []
    copies: dict[str, FileCopy] = {}
    for finding_id in plan["finding_ids"]:
        finding = by_id[finding_id]
        note = not_fixable(finding)
        path = finding.path or ""
        if note is None and not secrets_checked:
            note = UNREAD_NOTE
        if note is None and path not in copies:
            made = file_copy(folder, path, scanned.get(path), hidden.get(path, set()), mask)
            if isinstance(made, str):
                note = made
            else:
                copies[path] = made
        targets.append(fix_target(finding, note))
    # Before: how often each SEMGREP rule fires in each file, to tell a fix from a move.
    before = Counter(
        rule_key(finding.rule_id, finding.path) for finding in found if CHECK_TOOL in finding.tools
    )
    provider = agent_runs.make_provider_for_run(session_factory, settings)(run_id)
    db.commit()  # no transaction stays open while the model answers

    state = FIX_EVENTS.get(run_id)
    stop = state.stop if state else asyncio.Event()
    recheck_lock = asyncio.Lock()  # one database session: one recheck at a time
    rechecks = {"agents": 0}  # each is a tool run: the session's run cap must last

    async def say(file: str | None, kind: str, text: str) -> None:
        FIX_EVENTS.add(run_id, file, kind, mask(text)[0])

    async def model(
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        on_text: Callable[[str], Awaitable[None]],
        on_thinking: Callable[[str], Awaitable[None]],
    ) -> ToolReply:
        call = complete_with_tools(messages, tools, provider, on_text, on_thinking)
        return await _until_stopped(call, stop)

    async def recheck(
        changed: dict[str, FileCopy], group: list[FixTarget], final: bool
    ) -> tuple[set[str], set[str]]:
        async with recheck_lock:
            if stop.is_set():
                raise FixStopped
            if not final:  # an agent's own check; the last one always runs
                rechecks["agents"] += 1
                if rechecks["agents"] > MAX_AGENT_RECHECKS:
                    ids = {target.finding_id for target in group if target.path in changed}
                    return set(), ids
            return await _recheck(
                db, interfaces, mask, settings, operator, run_id, changed, group, before
            )

    output = await code_fix.fix_files(
        model, copies, targets, recheck, say, Budget(TOKEN_BUDGET), MAX_PARALLEL
    )
    if stop.is_set():
        raise FixStopped
    output = refuse_unsafe_files(output, targets, mask)
    result = _masked_result(output, mask)
    _finish(db, interfaces, operator, run_id, result, output.tokens)


async def _until_stopped[T](call: Coroutine[Any, Any, T], stop: asyncio.Event) -> T:
    """The call's answer, or FixStopped as soon as the run is stopped."""
    task = asyncio.ensure_future(call)
    stopper = asyncio.ensure_future(stop.wait())
    try:
        await asyncio.wait({task, stopper}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        stopper.cancel()
    if not task.done():
        task.cancel()
        raise FixStopped
    return task.result()


async def _recheck(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    run_id: UUID,
    changed: dict[str, FileCopy],
    group: list[FixTarget],
    before: Counter[tuple[str, str]],
) -> tuple[set[str], set[str]]:
    """(ids SEMGREP still reports, ids that could not be checked) for the targets in the
    changed files. A target SEMGREP did not find, or a check that is BLOCKED or fails,
    is unchecked: NOT_VERIFIED."""
    inside = [target for target in group if target.path in changed]
    checkable = [target for target in inside if CHECK_TOOL in target.tools]
    unchecked = {target.finding_id for target in inside if target not in checkable}
    if not checkable:
        return set(), unchecked
    run = agent_run_repo.get(db, run_id)
    session_id = assessment_repo.get(db, run.assessment_id).session_id
    folder = code_files.session_folder(settings.code_dir, session_id)
    # A new 8-hex name per check: each call has its own target, so the loop check never
    # sees a repeat, and tool_runs turns the copy's paths back into the code folder's.
    name = f"{code_files.SCAN_FOLDER_PREFIX}{secrets.token_hex(4)}"
    copy = folder / name
    try:
        await asyncio.to_thread(_write_copy, copy / code_scans.CHANGED, changed)
        target = f"{code_files.container_path(session_id)}/{name}/{code_scans.CHANGED}"
        output = await _run_check(db, interfaces, mask, settings, operator, run, target)
    finally:
        shutil.rmtree(copy, ignore_errors=True)
    if output is None:
        return set(), unchecked | {target.finding_id for target in checkable}
    prefix = code_files.container_path(session_id) + "/"
    new, _ = parse_run(CHECK_TOOL, output)
    after = Counter(
        rule_key(item.title, code_scans.relative_path(item.target, prefix)) for item in new
    )
    still = set()
    for target in checkable:
        key = rule_key(target.rule_id, target.path)
        # The same rule firing as often in the file as before: the change did not fix it
        # (counted per rule and file, not by line, since the lines moved).
        if after[key] >= max(before[key], 1):
            still.add(target.finding_id)
    return still, unchecked


async def _run_check(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    run: AgentRun,
    target: str,
) -> str | None:
    """SEMGREP on the copy, as an action of this fix run; its masked output, or None."""
    try:
        action, _ = await actions.send_action(
            db,
            interfaces,
            mask,
            settings,
            operator,
            run.assessment_id,
            ActionIn(tool=CHECK_TOOL, target=target),
            agent_run_id=run.agent_run_id,
        )
    except ApiError as error:
        if error.code != "ACTION_BLOCKED":
            raise
        db.rollback()
        return None
    if action.action_status != ActionStatus.COMPLETED or not action.tool_runs:
        return None
    return action.tool_runs[-1].output_masked or ""


def _write_copy(folder: Any, changed: dict[str, FileCopy]) -> None:
    folder.mkdir(parents=True, exist_ok=True)
    for path, copy in changed.items():
        file = folder / code_files.check_rel_path(path)
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("\n".join(copy.real) + "\n", encoding="utf-8")
    (folder / ".semgrepignore").write_bytes(b"")  # semgrep skips tests/ etc. without one


def refuse_unsafe_files(
    output: code_fix.FixOutput, targets: list[FixTarget], mask: MaskSecrets
) -> code_fix.FixOutput:
    """A file whose edits masking would change is dropped, and its findings end
    NOT_FIXED: the edits are kept unmasked, so they must hold nothing a mask hides."""
    unsafe = {
        fix.path
        for fix in output.files
        if any(mask(edit["replacement"])[0] != edit["replacement"] for edit in fix.edits)
    }
    if not unsafe:
        return output
    path_of = {target.finding_id: target.path for target in targets}
    results = [
        code_fix.FixOutcome(item.finding_id, code_fix.NOT_FIXED, REFUSED_NOTE)
        if path_of.get(item.finding_id) in unsafe
        else item
        for item in output.results
    ]
    files = [fix for fix in output.files if fix.path not in unsafe]
    return code_fix.FixOutput(files, output.summary, results, output.tokens)


MARKDOWN_IMAGE = re.compile(r"!\[[^\]]*\]\([^)]*\)")
MARKDOWN_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
HTML_TAG = re.compile(r"<[^>\n]+>")


def plain(text: str) -> str:
    """Model text with no image, link or HTML tag: a screen that renders the Markdown
    must not fetch an address the scanned code asked the model to write."""
    text = MARKDOWN_IMAGE.sub("", text)
    text = MARKDOWN_LINK.sub(r"\1", text)
    return HTML_TAG.sub("", text)


def _masked_result(output: code_fix.FixOutput, mask: MaskSecrets) -> dict[str, Any]:
    """The result as saved and shown. The summary and the notes are masked. The edits are
    not masked again: they are the model's masked text and lines no mask changed
    (FileCopy.proposal refuses any other), and masking code would break it."""
    return {
        "files": [
            {"path": fix.path, "file_sha256": fix.file_sha256, "edits": fix.edits}
            for fix in output.files
        ],
        "summary": plain(mask(output.summary)[0]),
        "results": [
            {
                "finding_id": item.finding_id,
                "status": item.status,
                "note": plain(mask(item.note)[0]),
            }
            for item in output.results
        ],
    }


def _finish(
    db: Db,
    interfaces: Interfaces,
    operator: Operator,
    run_id: UUID,
    result: dict[str, Any],
    tokens: int,
) -> None:
    run = agent_run_repo.get_for_update(db, run_id)
    if run.agent_runs_status != AgentRunStatus.RUNNING:
        db.commit()  # cancelled meanwhile: it keeps that end
        return
    _update_plan(run, stage="DONE", result=result, tokens=tokens)
    statuses = Counter(item["status"] for item in result["results"])
    details = {
        "task": TASK,
        "files": str(len(result["files"])),
        "tokens": str(tokens),
        **{status.lower(): str(count) for status, count in statuses.items()},
    }
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.COMPLETED, details)


def _fail(
    db: Db, interfaces: Interfaces, operator: Operator, run_id: UUID, error: Exception
) -> None:
    db.rollback()
    run = agent_run_repo.get_for_update(db, run_id)
    if run is None or run.agent_runs_status != AgentRunStatus.RUNNING:
        db.commit()
        return
    if isinstance(error, ApiError | ProviderError):
        error_code = error.code
    elif isinstance(error, TimeoutError):
        error_code = "TIMED_OUT"
    else:
        error_code = "UNEXPECTED_ERROR"
    _update_plan(run, stage="DONE", error=error_code)
    details = {"task": TASK, "code": error_code}
    agent_runs.end(db, interfaces, operator, run, AgentRunStatus.FAILED, details)


def _update_plan(run: AgentRun, **changes: Any) -> None:
    """A new dict, so the JSONB column is saved (changing it in place is not seen)."""
    run.plan = {**(run.plan or {}), **changes}


def _get_own_fix(db: Db, operator: Operator, run_id: UUID, lock: bool = False) -> AgentRun:
    """404 CODE_FIX_NOT_FOUND, 403 NOT_YOUR_SESSION for another session's fix."""
    get = agent_run_repo.get_for_update if lock else agent_run_repo.get
    run = get(db, run_id)
    if run is None or (run.plan or {}).get("task") != TASK:
        raise ApiError(404, "CODE_FIX_NOT_FOUND", "No code fix with this id.")
    if run.session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "This fix belongs to another session.")
    return run


def _still_signed_in(get_operator: GetOperator, token: str) -> bool:
    try:
        get_operator(token)
    except PermissionError:
        return False
    return True
