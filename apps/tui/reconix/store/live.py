"""The assessment run on the Core API: what to ask it next, and what its answers show.

After you run the plan, the API runs it: it sends the agent's first step through check()
(S1/S2), runs a LOW step in Kali at once and holds a MEDIUM or HIGH one for you. Then the
app asks for the next step, until the agent has none, and for the analysis. This module
never runs anything and never makes data up: each answer becomes the run's next steps
(lines in the activity log, a card with the tool's masked output, an approval gate, the
findings), and the controller plays them like any other step.

One call at a time, split so the network stays off the UI thread:

    job = next_job()           # UI thread: what to ask, or None (waiting for you, or done)
    result = job.fetch()       # a worker: the API call (core_api/run_api.py)
    job.apply(result)          # UI thread: record the answer as run steps
    job.fail(error)            # UI thread, instead of apply: show why it failed

A decision you make at a gate is recorded at once (the gate opens) and sent to the API by
the next job. If the API refuses it (the typed target doesn't match, the approval expired),
the decision is taken back and the gate asks again with the API's reason.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..core_api import adapt, code_scan, run_api, sync
from ..core_api.client import CoreApiError
from ..core_api.scope_map import api_tools
from ..models import GATE_APPROVAL_PREFIX, Assessment, LiveRun, RunStep
from . import lists
from .activity import log_event
from .scenario import banner, gate
from .transcript import add_activity

MAX_STEPS = 24  # the run asks the agent for at most this many steps (the API caps it too)


@dataclass
class Job:
    """One call to the API for `assessment`'s run."""

    name: str  # send | decide | next | analyze
    assessment: Assessment
    fetch: Callable[[], Any]
    on_result: Callable[[Assessment, Any], None]
    # A slow job (the code scan) reports what it is doing: the host sets this to hand the
    # line to the UI thread (`progress` there), and the worker calls `report`.
    on_progress: Optional[Callable[[str], None]] = None

    def report(self, text: str) -> None:
        """From the worker: a progress line, handed to the UI thread when the host listens."""
        if self.on_progress is not None:
            self.on_progress(text)

    def progress(self, text: str) -> None:
        """UI thread: show one progress line of the job in the run's log."""
        _append(self.assessment, [_log("SYS", text)])

    def apply(self, result: Any) -> None:
        live = self.assessment.live
        live.busy = False
        if self.assessment is not lists.current() and not _still_listed(self.assessment):
            return  # the assessment is gone
        live.failed = ""
        self.on_result(self.assessment, result)

    def fail(self, error: Exception) -> None:
        live = self.assessment.live
        live.busy = False
        _failed(self.assessment, self.name, error)


def _still_listed(assessment: Assessment) -> bool:
    return any(a is assessment for a in lists.ASSESSMENTS)


def _say(text: str, tone: str = "default") -> RunStep:
    return RunStep("say", speaker="reconix", text=text, tone=tone, pause=0.3, literal=True)


def _log(source: str, text: str, tone: str = "default") -> RunStep:
    return RunStep("log", source=source, text=text, tone=tone, pause=0.2, literal=True)


def _append(assessment: Assessment, steps: List[RunStep]) -> None:
    assessment.script.extend(steps)


# --- what to ask next ------------------------------------------------------------------------
def next_job(assessment: Optional[Assessment] = None) -> Optional[Job]:
    """The next call the run needs, or None: nothing to ask (not started, waiting for your
    decision, a call already in flight, stopped, or finished)."""
    assessment = assessment or lists.current()
    live, run = assessment.live, assessment.run
    if (live.busy or live.failed or not run.plan_started or run.stopped or run.completed
            or not (live.assessment_id or _is_source(assessment))):
        return None  # (after a failure the run waits for you: retry())
    from .scope import time_limit_pending

    if time_limit_pending():
        return None  # the run waits at the time-limit prompt (Execution: Continue or Stop)
    if run.cursor < len(assessment.script):
        return None  # steps still to play first
    job = _job_for(assessment, live)
    if job is not None:
        live.busy = True
    return job


def _is_source(assessment: Assessment) -> bool:
    """A source-code scope: its run is a code scan (upload, scan, findings), no plan."""
    return assessment.scope is not None and assessment.scope.kind == "source"


def _job_for(assessment: Assessment, live: LiveRun) -> Optional[Job]:
    if _is_source(assessment):
        return None if live.code_scan_done else _code_scan_job(assessment)
    aid = live.assessment_id
    if not live.sent:
        if not live.agent_run_id:
            return None
        run_id = live.agent_run_id
        return Job("send", assessment, lambda: run_api.send_plan(run_id, aid), _on_plan_out)
    if live.waiting_approval:
        decision = _unsent_decision(assessment, live.waiting_approval)
        if decision is None:
            return None  # the gate waits for you
        approval_id, approve, typed = (
            live.waiting_approval,
            decision.decision == "APPROVED",
            decision.typed_target,
        )
        return Job(
            "decide",
            assessment,
            lambda: run_api.decide(approval_id, approve, aid, typed or None),
            _on_decided,
        )
    if live.to_analyze:
        ids = list(live.to_analyze)
        # Analyze this step's findings before moving on, so each one gets its analysis now.
        return Job("analyze", assessment, lambda: run_api.analyze(aid, ids), _on_step_analysis)
    if not live.agent_done and live.steps_done < MAX_STEPS:
        return Job("next", assessment, lambda: run_api.next_step(aid), _on_plan_out)
    if not live.analyzed:
        # Every step's findings were analyzed as they came in; close the run.
        return Job("finish", assessment, lambda: None, _on_finish)
    return None


def _code_scan_job(assessment: Assessment) -> Job:
    """Upload the local code (or have the API clone a repo), scan it, read the findings."""
    scope = assessment.scope
    tools = list(api_tools(scope))
    add_activity("SYS", "Code scan: uploading the code to the Core API…")

    def fetch() -> Any:
        return code_scan.run_scan(
            scope.target_url, scope.excluded_paths, tools,
            lambda: sync.session_for(assessment), job.report,
        )

    job = Job("code_scan", assessment, fetch, _on_code_scan)
    return job


def _on_code_scan(assessment: Assessment, out: Dict[str, Any]) -> None:
    """The finished code scan and its findings: shown, then the run is complete."""
    live = assessment.live
    scan = out.get("scan") or {}
    live.code_scan_done = True
    live.code_scan_id = str(scan.get("agent_run_id", ""))
    steps = [_log("SYS", f"Code scan {scan.get('stage', 'DONE').title()}", "ok")]
    for note in scan.get("notes") or []:
        bad = any(word in str(note) for word in ("FAILED", "BLOCKED"))
        steps.append(_log("SYS", str(note), "warn" if bad else "default"))
    steps += _new_code_findings(assessment, out.get("findings") or [])
    steps += [RunStep("progress", name=bar, value=100, pause=0.0)
              for bar in ("discovery", "scanning", "validation", "analysis")]
    steps += _completion_steps(assessment)
    _append(assessment, steps)
    log_event("run.finished", live.code_scan_id)


def _new_code_findings(assessment: Assessment, rows: List[dict]) -> List[RunStep]:
    """The scan's findings, added and revealed (the API's own review is on each row)."""
    live = assessment.live
    known = set(live.finding_ids.values())
    steps: List[RunStep] = []
    for row in rows:
        finding_id = str(row.get("finding_id", ""))
        if not finding_id or finding_id in known:
            continue
        fid = f"{len(live.finding_ids) + 1:03d}"
        live.finding_ids[fid] = finding_id
        assessment.findings.append(adapt.code_finding(row, fid))
        steps.append(RunStep("reveal", name=fid, pause=0.1))
        steps.append(_log("AI", f"Finding {fid} · {adapt.severity(row.get('severity_status'))} "
                                f"· {row.get('title', '')}", "warn"))
    return steps


def failed_reason() -> str:
    """Why the run's last call to the Core API failed ("" when it didn't)."""
    return lists.current().live.failed


def retry() -> bool:
    """Ask the API again after a failed call (you pressed Enter on Execution). False when
    nothing failed."""
    live = lists.current().live
    if not live.failed:
        return False
    live.failed = ""
    add_activity("USER", "Retry the Core API call")
    return True


def _unsent_decision(assessment: Assessment, approval_id: str):
    for decision in reversed(assessment.decisions):
        if decision.request_id == approval_id:
            return None if decision.sent else decision
    return None


# --- the answers -----------------------------------------------------------------------------
def _on_plan_out(assessment: Assessment, out: Dict[str, Any]) -> None:
    """A PlanOut (the first step, or the next one) plus the findings."""
    live = assessment.live
    first = not live.sent
    if not live.sent:
        live.sent = True
        live.agent_run_id = ""
    action = out.get("action")
    if action is None:
        live.agent_done = True
        text = (out.get("text") or "").strip()
        steps = [_log("AI", "The AI has no further step for this scope.", "ok")]
        if text:
            steps.insert(0, _say(text[:600]))
        _append(assessment, steps)
        return
    reasoning = (out.get("text") or "").strip()
    if reasoning and not first:  # the first step's reasoning is on the plan card already
        _append(assessment, [_say(reasoning[:500])])
    _append(assessment, _action_steps(assessment, action, out.get("approval")))
    _append(assessment, _new_findings(assessment, out.get("findings") or []))


def _on_decided(assessment: Assessment, out: Dict[str, Any]) -> None:
    """Your decision reached the API: what the tool did (approved) or that it was skipped."""
    live = assessment.live
    approval = out.get("approval") or {}
    approval_id = str(approval.get("approval_id") or live.waiting_approval)
    for decision in assessment.decisions:
        if decision.request_id == approval_id:
            decision.sent = True
    live.waiting_approval = ""
    action = out.get("action")
    if approval.get("approval_status") == "REJECTED" or action is None:
        _append(
            assessment, [_log("POLICY", "Skipped: you rejected this step. Nothing ran.", "block")]
        )
        return
    _append(assessment, _ran_steps(assessment, action))
    _append(assessment, _new_findings(assessment, out.get("findings") or []))


def _on_step_analysis(assessment: Assessment, out: Dict[str, Any]) -> None:
    """A per-step analysis came back: write it onto the findings this step found and show the
    AI's read of each one. The run is not ended here; more steps may follow."""
    live = assessment.live
    live.to_analyze = []  # these were just analyzed
    _refresh_findings(assessment, out.get("findings") or [])
    steps: List[RunStep] = []
    for row in out.get("analysis") or []:
        code = str(row.get("code") or "")
        meaning = str(row.get("impact") or "").strip() or str(row.get("explanation") or "").strip()
        if meaning:
            steps.append(_log("AI", f"Analysis {code}: {meaning[:400]}", "default"))
        if row.get("unsure"):
            steps.append(
                _log(
                    "AI",
                    f"{code}: unsure, a person decides ({str(row['unsure'])[:200]})",
                    "warn",
                )
            )
    _append(assessment, steps)
    log_event("run.analyzed", live.assessment_id)


def _on_finish(assessment: Assessment, _result: object) -> None:
    """The agent is done and nothing was found: close the phases and complete the run,
    with no analysis call (there are no findings to analyze)."""
    live = assessment.live
    live.analyzed = True
    steps = [RunStep("progress", name=bar, value=100, pause=0.0)
             for bar in ("discovery", "scanning", "validation", "analysis")]
    steps += _completion_steps(assessment)
    _append(assessment, steps)
    log_event("run.finished", live.assessment_id)


def _completion_steps(assessment: Assessment) -> List[RunStep]:
    """The lines that end a run: the status, how many findings, and how to open the report."""
    count = len(assessment.findings)
    none = " No findings were recorded." if count == 0 else ""
    return [
        _log("SYS", "Assessment status: Completed", "ok"),
        _say(f"Assessment completed. {count} finding{'s' if count != 1 else ''}.{none}", "ok"),
        _say("Open the report (Alt+8 or /report) to export it.", "muted"),
        RunStep("complete", pause=0.0),
    ]


def _failed(assessment: Assessment, name: str, error: Exception) -> None:
    """A call failed: say why, as the API said it. Nothing is retried around the API."""
    live = assessment.live
    reason = str(error)
    code = getattr(error, "code", "")
    if name == "decide" and isinstance(error, CoreApiError) and error.status in (409, 422):
        _decision_refused(assessment, error)  # the gate asks again: not a stopped run
        return
    if name == "next" and code == "NO_TOOL_RESULTS":
        live.agent_done = True  # nothing ran (all skipped): go to analysis
        return
    if name == "analyze":
        # a per-step analysis failed: skip it and keep the run going (findings stay
        # un-analyzed); the run is not stopped for an analysis hiccup.
        live.to_analyze = []
        _append(assessment, [_log("AI", "Could not analyze this step; continuing.", "warn")])
        return
    live.failed = f"{code}: {reason}" if code else reason
    add_activity("SYS", f"Core API: {live.failed}", tone="block")
    _append(
        assessment,
        [
            RunStep(
                "say",
                speaker="policy",
                text=(f"The run stopped: {reason}. Press Enter on Execution to try again."),
                tone="block",
                entry="banner",
                pause=0.0,
                literal=True,
            )
        ],
    )


def _decision_refused(assessment: Assessment, error: CoreApiError) -> None:
    """The API refused your decision: take it back, and ask again at the same gate."""
    live = assessment.live
    approval_id = live.waiting_approval
    assessment.decisions = [
        d for d in assessment.decisions if not (d.request_id == approval_id and not d.sent)
    ]
    add_activity("POLICY", f"The Core API refused the decision: {error}", tone="block")
    if error.code in ("APPROVAL_EXPIRED", "EXPIRED", "APPROVAL_ALREADY_DECIDED"):
        live.waiting_approval = ""  # the approval is over: ask the agent again
        _append(assessment, [banner(f"{error}. The AI picks the next step.", "warn")])
        return
    _append(
        assessment,
        [
            RunStep(
                "say",
                speaker="policy",
                text=f"Not approved: {error}",
                tone="block",
                entry="banner",
                pause=0.0,
                literal=True,
            ),
            gate(GATE_APPROVAL_PREFIX + approval_id),
        ],
    )


# --- one action as run steps ------------------------------------------------------------------
def _action_steps(assessment: Assessment, action: dict,
                  approval: Optional[dict]) -> List[RunStep]:
    """A step the API gave the run: blocked, waiting for you, or already run (LOW)."""
    live = assessment.live
    live.steps_done += 1
    live.actions.append(str(action.get("action_id", "")))
    plan_step = adapt.plan_step_for(live.plan_steps, action, live.steps_done)
    title = adapt.step_title(plan_step, action)
    risk = str(action.get("risk_level") or "").upper()
    steps: List[RunStep] = [
        RunStep("phase", name="testing", pause=0.0),
        _log("AI", f"Step {live.steps_done}: {title}"),
    ]
    status = str(action.get("action_status") or "")
    if status == "BLOCKED":
        reason = (action.get("guardrail_report") or {}).get("reason") or "refused by a check"
        steps.append(_log("POLICY", f"Blocked: {reason}", "block"))
        return steps
    steps.append(_log("POLICY", f"Checks passed · risk {risk or 'LOW'}", "ok"))
    approval_id = action.get("approval_id")
    if approval_id and status == "PENDING":
        approval = approval or {"approval_id": approval_id, "risk_level": risk}
        request = adapt.approval_request(action, approval, plan_step)
        assessment.approvals = [
            a for a in assessment.approvals if a.request_id != request.request_id
        ] + [request]
        live.waiting_approval = request.request_id
        steps.append(_log("POLICY", f"Risk: {risk} · approval required", "warn"))
        steps.append(gate(GATE_APPROVAL_PREFIX + request.request_id))
        return steps
    return steps + _ran_steps(assessment, action)


def _ran_steps(assessment: Assessment, action: dict) -> List[RunStep]:
    """What a tool run did: its status line, a card with the first lines of its masked
    output, and the progress bar of its purpose."""
    run = adapt.tool_run_line(action)
    tool = str(action.get("tool", "")).lower()
    target = str(action.get("target", ""))
    if not run:
        return [_log("TOOL", f"{tool} on {target}: no tool run recorded", "warn")]
    tone = "ok" if run["status"] == "COMPLETED" else "block"
    if run["status"] == "COMPLETED" and tool not in assessment.live.finished_tools:
        assessment.live.finished_tools.append(tool)   # the report's test coverage
    line = f"{tool} on {target}: {run['status'].lower()}"
    if run["exit"]:
        line += f" · exit {run['exit']}"
    steps = [_log("TOOL", line, tone)]
    if run["error"]:
        steps.append(_log("TOOL", f"{tool}: {run['error'][:300]}", "block"))
    rows = adapt.output_rows(run["output"])
    if rows:
        steps.append(
            RunStep(
                "card",
                speaker="reconix",
                text=f"{tool} · {target}",
                rows=tuple(rows),
                pause=0.3,
                literal=True,
            )
        )
    bar = adapt.bar(action)
    done = assessment.run.progress.get(bar, 0)
    steps.append(RunStep("progress", name=bar, value=min(100, max(done, 50) + 25), pause=0.1))
    return steps


def _new_findings(assessment: Assessment, rows: List[dict]) -> List[RunStep]:
    """Findings the API has that the app hasn't shown yet: added, then revealed."""
    live = assessment.live
    known = set(live.finding_ids.values())
    steps: List[RunStep] = []
    for row in rows:
        finding_id = str(row.get("finding_id", ""))
        if not finding_id or finding_id in known:
            continue
        fid = f"{len(live.finding_ids) + 1:03d}"
        live.finding_ids[fid] = finding_id
        live.to_analyze.append(finding_id)  # analyzed before the next step
        assessment.findings.append(adapt.finding(row, fid))
        steps.append(RunStep("reveal", name=fid, pause=0.1))
        steps.append(
            _log(
                "AI",
                f"Finding {fid} · {adapt.severity(row.get('severity_status'))} "
                f"· {row.get('title', '')}",
                "warn",
            )
        )
    return steps


def _refresh_findings(assessment: Assessment, rows: List[dict]) -> None:
    """Refresh findings already shown with the API's latest copy, so the plain-language
    analysis the ANALYZE step wrote (description, impact, remediation, CVSS) reaches the
    detail view. Local triage (status, note, severity override) is left as it is."""
    live = assessment.live
    local_of = {finding_id: fid for fid, finding_id in live.finding_ids.items()}
    by_fid = {f.fid: f for f in assessment.findings}
    for row in rows:
        finding = by_fid.get(local_of.get(str(row.get("finding_id", "")), ""))
        if finding is None:
            continue
        finding.description = str(row.get("description") or finding.description)
        finding.impact = str(row.get("impact") or "")
        finding.remediation = str(row.get("remediation") or "")
        cvss = row.get("cvss_score")
        if cvss is not None:
            finding.cvss_score = float(cvss)


# --- after the scope and plan -----------------------------------------------------------------
def record_plan(assessment: Assessment, out: Dict[str, Any]) -> None:
    """A drafted plan (PlanOut, draft=True): kept until you run it."""
    live = assessment.live
    # Only a draft has a step to send; with nothing to send, Run plan stays closed.
    run_id = str((out.get("agent_run") or {}).get("agent_run_id", ""))
    live.agent_run_id = run_id if out.get("draft") else ""
    live.model_name = str((out.get("agent_run") or {}).get("model_name", ""))
    live.plan_text = str(out.get("text") or "")
    live.plan_steps = list(out.get("plan") or [])
    live.blocked_steps = list(out.get("blocked") or [])
    live.sent = False
    live.agent_done = not out.get("draft") and out.get("action") is None

