"""The VS Code chat functions: what each one does, its arguments, where it runs, and how.

Whatever chooses a function (the keyword rules today, a model later), the call goes
through the same checks here: the arguments must fit the function's model, and every id
must belong to the person's own session (a scan this session started, on an assessment
of this session). A call that does not fit raises FunctionError and the message is
treated as a question.

SERVER functions only read. Anything that changes something is a CLIENT function, so
nothing has happened when the person's message cannot be saved, and a model choosing a
function can never change anything without the person saying yes in VS Code.
"""

from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core import code_files
from reconix_api.core.config import Settings
from reconix_api.core.interfaces import Interfaces, Operator
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import AgentRun
from reconix_api.models.enums import AgentRunStatus, FindingStatus, SeverityStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.schemas.code import CodeFindingOut
from reconix_api.schemas.vscode_chat import (
    Arguments,
    CancelScanArgs,
    ExplainFindingArgs,
    FileCount,
    FindingResult,
    FindingsResult,
    FunctionName,
    FunctionResult,
    FunctionSpec,
    ListFindingsArgs,
    NoArgs,
    ProposeFixArgs,
    RunsOn,
    ScanResult,
    StartScanArgs,
    SummaryResult,
    SwitchModelArgs,
)
from reconix_api.services import code_scans

SEVERITY_ORDER = list(SeverityStatus)  # CRITICAL first, NONE last
TOP = 3  # most affected files and fix-first findings in a summary


class FunctionError(Exception):
    """The call does not fit this session (an unknown id, a bad path)."""


@dataclass(frozen=True)
class FunctionContext:
    db: Db
    interfaces: Interfaces
    mask: MaskSecrets
    settings: Settings
    operator: Operator
    session_id: UUID
    # The findings of the newest finished code scan, none before one. Loaded only when a
    # function needs them: each one reads and hashes its file.
    load_findings: Callable[[], list[CodeFindingOut]]

    def findings(self) -> list[CodeFindingOut]:
        return self.load_findings()


@dataclass(frozen=True)
class Outcome:
    text: str  # the answer saved in the chat
    arguments: Arguments | None  # the checked call; None: nothing to run, text says why
    result: FunctionResult | None = None


@dataclass(frozen=True)
class ChatFunction:
    name: FunctionName
    description: str  # for a model choosing a function; keep it one plain sentence
    arguments: type[Arguments]
    runs_on: RunsOn
    confirm: bool
    run: Callable[[FunctionContext, Any], Outcome]


def spec(function: ChatFunction) -> FunctionSpec:
    return FunctionSpec(
        name=function.name,
        description=function.description,
        runs_on=function.runs_on,
        confirm=function.confirm,
        parameters=function.arguments.model_json_schema(),
    )


# ---------------------------------------------------------------------------
# SERVER functions: they only read
# ---------------------------------------------------------------------------


def list_findings(context: FunctionContext, args: ListFindingsArgs) -> Outcome:
    if args.path is not None:
        check_path(args.path)
    findings = context.findings()
    if not findings:
        return Outcome(NO_SCAN_TEXT, args, FindingsResult(findings=[]))
    picked = [
        finding
        for finding in findings
        if (args.severity is None or finding.severity_status == args.severity)
        and (args.path is None or finding.path == args.path)
    ]
    return Outcome(f"{counted(len(picked), 'finding')}.", args, FindingsResult(findings=picked))


def explain_finding(context: FunctionContext, args: ExplainFindingArgs) -> Outcome:
    finding = next((f for f in context.findings() if f.finding_id == args.finding_id), None)
    if finding is None:
        raise FunctionError("the finding is not in this session's latest code scan")
    return Outcome(f"{finding.code}: {finding.title}", args, FindingResult(finding=finding))


def summarize_findings(context: FunctionContext, args: NoArgs) -> Outcome:
    findings = context.findings()
    open_findings = [f for f in findings if f.finding_status == FindingStatus.OPEN]
    counts = {severity: 0 for severity in SeverityStatus}
    for finding in open_findings:
        counts[finding.severity_status] += 1
    per_file = Counter(f.path for f in open_findings if f.path)
    worst = sorted(open_findings, key=lambda f: (SEVERITY_ORDER.index(f.severity_status), f.code))
    summary = SummaryResult(
        total=len(open_findings),
        counts=counts,
        files=[FileCount(path=path, count=n) for path, n in per_file.most_common(TOP)],
        fix_first=[finding.finding_id for finding in worst[:TOP]],
    )
    if not findings:
        text = NO_SCAN_TEXT
    elif not open_findings:
        text = "There are no open findings."
    else:
        parts = [f"{n} {s.lower()}" for s, n in counts.items() if n]
        text = f"{counted(len(open_findings), 'open finding')}: {', '.join(parts)}."
    return Outcome(text, args, summary)


def scan_status(context: FunctionContext, args: NoArgs) -> Outcome:
    run = newest_scan(context.db, context.session_id)
    if run is None:
        return Outcome("There is no code scan in this session yet.", args, ScanResult(scan=None))
    scan = code_scans.scan_out(context.db, run)
    text = f"The latest code scan is {scan.agent_runs_status.lower()}"
    if scan.agent_runs_status == AgentRunStatus.RUNNING:
        text += f" ({scan.progress}%)"
    return Outcome(f"{text}.", args, ScanResult(scan=scan))


# ---------------------------------------------------------------------------
# CLIENT functions: checked here; VS Code asks the person, then runs them (through an
# existing endpoint where there is one)
# ---------------------------------------------------------------------------


def cancel_scan(context: FunctionContext, args: CancelScanArgs) -> Outcome:
    """VS Code stops it with POST /code-scans/{agent_run_id}/cancel."""
    run = newest_scan(context.db, context.session_id)
    if run is None or run.agent_runs_status != AgentRunStatus.RUNNING:
        return Outcome("No code scan is running.", None)
    if args.agent_run_id not in (None, run.agent_run_id):
        raise FunctionError("not this session's running code scan")
    scan = code_scans.scan_out(context.db, run)
    return Outcome(
        "Stop the running code scan?",
        CancelScanArgs(agent_run_id=run.agent_run_id),
        ScanResult(scan=scan),
    )


def start_scan(context: FunctionContext, args: StartScanArgs) -> Outcome:
    """VS Code syncs and uploads, then calls POST /assessments/{id}/code-scans. full and
    paths are hints for that upload: the scan itself runs on the scope's stored code."""
    for path in args.paths:
        check_path(path)
    what = ", ".join(args.paths) if args.paths else "the workspace"
    return Outcome(f"Starting a scan of {what}.", args)


def propose_fix(context: FunctionContext, args: ProposeFixArgs) -> Outcome:
    """There is no fix endpoint yet: VS Code prepares the fix itself and shows the diff."""
    findings = context.findings()
    if not findings:
        return Outcome("There are no findings to fix yet. Scan the project first.", None)
    known = {finding.finding_id for finding in findings}
    ids = [finding_id for finding_id in dict.fromkeys(args.finding_ids) if finding_id in known]
    if not ids:
        return Outcome(
            "Which findings should I fix? Name a severity, a file or a finding code.", None
        )
    return Outcome(
        f"Preparing a fix for {counted(len(ids), 'finding')}.", ProposeFixArgs(finding_ids=ids)
    )


def switch_model(context: FunctionContext, args: SwitchModelArgs) -> Outcome:
    provider = provider_repo.get(context.db, args.llm_provider_id)
    if provider is None:
        raise FunctionError("no provider with this id")
    if provider.is_active:
        return Outcome(f"{provider.display_name} is already the active model.", None)
    return Outcome(f"Switching to {provider.display_name}.", args)


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

FUNCTIONS: dict[FunctionName, ChatFunction] = {
    function.name: function
    for function in (
        ChatFunction(
            FunctionName.LIST_FINDINGS,
            "List the findings of the latest code scan, optionally of one severity or file.",
            ListFindingsArgs,
            RunsOn.SERVER,
            False,
            list_findings,
        ),
        ChatFunction(
            FunctionName.EXPLAIN_FINDING,
            "Show one finding of the latest code scan in full.",
            ExplainFindingArgs,
            RunsOn.SERVER,
            False,
            explain_finding,
        ),
        ChatFunction(
            FunctionName.SUMMARIZE_FINDINGS,
            "Count the open findings by severity, with the most affected files.",
            NoArgs,
            RunsOn.SERVER,
            False,
            summarize_findings,
        ),
        ChatFunction(
            FunctionName.SCAN_STATUS,
            "Tell whether the latest code scan is running, finished or failed.",
            NoArgs,
            RunsOn.SERVER,
            False,
            scan_status,
        ),
        ChatFunction(
            FunctionName.CANCEL_SCAN,
            "Stop the code scan that is running.",
            CancelScanArgs,
            RunsOn.CLIENT,
            True,
            cancel_scan,
        ),
        ChatFunction(
            FunctionName.START_SCAN,
            "Scan the workspace code; full and paths only change what VS Code uploads.",
            StartScanArgs,
            RunsOn.CLIENT,
            True,
            start_scan,
        ),
        ChatFunction(
            FunctionName.PROPOSE_FIX,
            "Prepare fixes in VS Code for the given findings; the person reviews the changes.",
            ProposeFixArgs,
            RunsOn.CLIENT,
            True,
            propose_fix,
        ),
        ChatFunction(
            FunctionName.SWITCH_MODEL,
            "Use another configured model provider for the chat and fixes.",
            SwitchModelArgs,
            RunsOn.CLIENT,
            True,
            switch_model,
        ),
    )
}

NO_SCAN_TEXT = "There is no finished code scan in this session yet."


def newest_scan(db: Db, session_id: UUID, finished: bool = False) -> AgentRun | None:
    """The session's newest code scan, or its newest COMPLETED one: started by this
    session, on an assessment of this session, so it scanned this session's code."""
    for run in agent_run_repo.list_by_session(db, session_id):  # newest first
        if (run.plan or {}).get("task") != code_scans.TASK:
            continue
        if finished and run.agent_runs_status != AgentRunStatus.COMPLETED:
            continue
        assessment = assessment_repo.get(db, run.assessment_id) if run.assessment_id else None
        if assessment is not None and assessment.session_id == session_id:
            return run
    return None


def check_path(path: str) -> None:
    try:
        code_files.check_rel_path(path)
    except code_files.CodeFileError as error:
        raise FunctionError(str(error)) from error


def counted(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"
