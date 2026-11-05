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

from ..core_api import adapt, run_api
from ..core_api.client import CoreApiError
from ..models import GATE_APPROVAL_PREFIX, Assessment, LiveRun, RunStep
from . import lists
from .activity import log_event
from .scenario import banner, gate
from .transcript import add_activity

MAX_STEPS = 12  # the run asks the agent for at most this many steps (the API caps it too)


@dataclass
class Job:
    """One call to the API for `assessment`'s run."""

    name: str  # send | decide | next | analyze
    assessment: Assessment
    fetch: Callable[[], Any]
    on_result: Callable[[Assessment, Any], None]

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
            or not live.assessment_id):
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


def _job_for(assessment: Assessment, live: LiveRun) -> Optional[Job]:
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
    if not live.agent_done and live.steps_done < MAX_STEPS:
        return Job("next", assessment, lambda: run_api.next_step(aid), _on_plan_out)
    if not live.analyzed and not assessment.findings:
        # Nothing was found (every step failed, or the scan came up clean): there is nothing
        # to analyze, so finish without that call rather than hit NO_FINDINGS.
        return Job("finish", assessment, lambda: None, _on_finish)
    if not live.analyzed:
        return Job("analyze", assessment, lambda: run_api.analyze(aid), _on_analysis)
    return None


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


def _on_analysis(assessment: Assessment, out: Dict[str, Any]) -> None:
    live = assessment.live
    live.analyzed = True
    live.analysis_summary = str(out.get("summary") or "")
    # The agent has nothing left: every testing phase is over (it ran, or you rejected its
    # checks, which the plan shows as skipped). Analysis is done now.
    steps: List[RunStep] = [RunStep("progress", name=bar, value=100, pause=0.0)
                            for bar in ("discovery", "scanning", "validation")]
    steps += [
        RunStep("phase", name="analyzing", pause=0.0),
        RunStep("progress", name="analysis", value=100, pause=0.2),
    ]
    if live.analysis_summary:
        steps.append(_say(live.analysis_summary[:1200]))
    for row in out.get("analysis") or []:
        if row.get("unsure"):
            steps.append(
                _log(
                    "AI",
                    f"{row.get('code', '')}: unsure, a person decides ({str(row['unsure'])[:200]})",
                    "warn",
                )
            )
    steps += _new_findings(assessment, out.get("findings") or [])
    steps += _completion_steps(assessment)
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
    if name == "analyze" and code in ("NO_FINDINGS", "NO_OPEN_FINDINGS"):
        _on_finish(assessment, None)  # nothing to analyze: finish cleanly, not a stopped run
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

