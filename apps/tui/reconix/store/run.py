"""The assessment run: play the next scripted step, stop at gates, and report where it is.

`advance()` is the only way the run moves. At a gate it stays put until the store has
recorded the human decision (template, scope, plan, target login, one-time code,
approval), so no step past a gate can play early, whatever the UI does. Steps marked
`when` play only if the approved tools need them (a login, the code after it).
"""

from dataclasses import replace
from datetime import timedelta
from pathlib import PurePath
from string import Template as TextTemplate
from typing import Callable, Dict, List, Optional

from ..models import (
    ApprovalRequest,
    GATE_ACCOUNT,
    GATE_APPROVAL_PREFIX,
    GATE_CODE,
    GATE_PLAN,
    GATE_SCOPE,
    GATE_TEMPLATE,
    PROGRESS_BARS,
    PlanTask,
    RunState,
    RunStep,
)
from ..models.base import utc_now
from ..models.parser import ParsedTarget
from . import lists, seed
from .activity import log_event
from .approvals import approvals_count, decision_for, get_approval
from .assessment import (
    add_request,
    clean_request,
    get_assessment,
    is_empty_assessment,
    recorded_line,
    shown_line,
)
from .confirm_check import checks_finding, elsewhere_note
from .errors import StoreValidationError
from .findings import finding_exists, findings_line, list_findings
from .parser import parse_request
from .replies import reply_to, template_hint
from .scope import (
    blocked_count,
    check_request,
    get_scope,
    is_scope_approved,
    time_limit_pending,
)
from .scope_view import join_and
from .targets import as_network, check_target
from .templates import apply_template, selected_template, template_name
from .templates.base import build_plan
from .tools import approved_tool
from .transcript import add_activity, add_chat, list_activity
from .vault import code_needed, is_authenticated, is_code_verified, login_kind, login_tools

# The phase shown while the run waits at a gate.
WAITING_PHASES = {
    GATE_TEMPLATE: "planning",
    GATE_SCOPE: "scope_pending",
    GATE_PLAN: "plan_pending",
    GATE_ACCOUNT: "waiting_account",
    GATE_CODE: "waiting_account",
}
# How the login reads in step text ($login_need).
LOGIN_WORDS = {
    "cookie": "a session cookie",
    "password": "a test account",
    "password+otp": "a test account and a one-time code",
}
PIPELINE_SOURCES = {"AI": "ai", "POLICY": "policy", "TOOL": "tool"}


def _client_label(target: str) -> str:
    """A readable client name from the target (staging.example.com -> Example).

    An address or range stays as typed (192.0.2.10), and a local folder gives its own
    name (/home/me/shop-app -> Shop App): neither has a domain to take a name from.
    """
    if as_network(target) is not None:
        return target.strip()
    if target.startswith(("/", "~", ".")) or (len(target) > 2 and target[1:3] in (":\\", ":/")):
        name = PurePath(target.replace("\\", "/").rstrip("/")).name
        return name.replace("-", " ").replace("_", " ").title() or target
    host = target.split("//")[-1].split("/")[0].split(":")[0]
    labels = [part for part in host.split(".") if part]
    core = labels[-2] if len(labels) >= 2 else (labels[0] if labels else target)
    return core.replace("-", " ").title() or target


def get_run() -> RunState:
    return lists.current().run


# --- starting and resetting -------------------------------------------------------------
def submit_prompt(text: str) -> str:
    """A line typed at the prompt. Returns "started" (a run began), "answered", or "ask".

    Before a run, a line that names a target starts the run on it; anything else (a
    greeting, a question, "scan my network" without an address) gets a short answer and
    nothing starts. With a model active (a real provider or the offline mock) that answer is
    the model's, except for a line a template keyword names and that isn't a question, which
    gets the template hint: the masked line is recorded and "ask" tells the app to call
    `llm_answer` off the UI thread. A malformed target (10.0.0.300) raises, so the operator
    can fix it. During a run the line goes to the assistant.
    """

    if get_run().started:
        say_to_assistant(text)
        return "answered"
    text = clean_request(text)
    parsed = parse_request(text)
    if parsed is None:
        line = recorded_line(text)  # masked: chat and model never see a secret
        add_chat("text", "you", line)
        # A line that names a kind of test but no target ("scan my network") gets Reconix's
        # own template hint first, with or without a model: it says what to type next.
        # (a question never gets a template hint)
        if not template_hint(line):
            return "ask"  # the app asks the Core API's AI (llm_answer) in a worker
        add_chat("text", "reconix", reply_to(line), tone="muted")
        return "answered"
    _start(text, parsed, picked=False)
    return "started"


def start_run(text: str, template_id: Optional[str] = None) -> None:
    """Start the assessment on the target in `text`.

    With `template_id` (the operator picked it with /template) the target must be valid
    for that template, and the template applies at once. Without it the target's shape
    picks the template: an unambiguous one (IPv4, URL, repo, path) applies at once; a bare
    hostname waits at the template gate. Text without a target raises with the answer.
    The Scope Manifest gate comes next in every case.
    """
    if get_run().started:
        raise StoreValidationError("An assessment is already running. Type /new to start over.")
    text = clean_request(text)
    if template_id is not None:
        from dataclasses import replace

        from .parser import extract_ports, extract_tools

        found = check_target(template_id, text)
        found = replace(found, ports=extract_ports(text), tools=extract_tools(text))
        _start(text, found, picked=True)
        return
    parsed = parse_request(text)
    if parsed is None:
        raise StoreValidationError(reply_to(text))
    _start(text, parsed, picked=False)


def _start(text: str, parsed: ParsedTarget, *, picked: bool) -> None:
    """Record the request and target and build the plan (and the run, if the template is
    known). `picked`: the operator chose the template; else it is matched or asked for."""
    assessment = lists.current()
    request = add_request(text)  # recorded masked; `parsed` came from the raw line
    assessment.target = parsed.target
    assessment.target_url = parsed.target_url
    assessment.target_kind = parsed.target_kind
    assessment.template_id = parsed.template_id
    assessment.requested_ports = list(parsed.ports)
    assessment.requested_tools = list(parsed.tools)
    assessment.client = _client_label(parsed.target)
    add_chat("text", "you", request.text)
    known = picked or parsed.confident
    assessment.script = build_plan(parsed.target_kind, ask_template=not known)
    assessment.run.started = True
    log_event("run.started", parsed.target)
    if known:
        apply_template(parsed.template_id, auto=not picked)


def login_refusal() -> Optional[str]:
    """Why a typed line must not be taken right now (the run waits for, or stopped at, the
    target login: the line may be the password), or None. Records nothing."""
    if get_run().waiting_gate in (GATE_ACCOUNT, GATE_CODE):
        # Don't record it: an operator may be pasting the login into the wrong place.
        return ("Reconix is waiting for the target login. Press Enter on "
                "the Execution screen to open the secure input; never "
                "paste credentials into the chat.")
    if get_run().stopped_at_gate in (GATE_ACCOUNT, GATE_CODE):
        # Stopped at the login: the next line may still be the password. Never echo, record
        # or send it to a model.
        return ("This run stopped at the target login. Use /new to start "
                "another assessment; never paste credentials into the "
                "chat.")
    return None


def say_operator_line(text: str) -> str:
    """Record the operator's chat line and return it. Raises before any model is called."""
    if not get_run().started:
        raise StoreValidationError("Start an assessment first.")
    refusal = login_refusal()
    if refusal:
        raise StoreValidationError(refusal)
    request = add_request(text)
    add_chat("text", "you", request.text)
    return request.text


def llm_answer(text: str, on_update: Optional[Callable[[], None]] = None) -> None:
    """Add the AI's reply to `text`, from the Core API (it calls the model and keeps the
    history). Blocks on the network: the app builds replies off the UI thread with
    `llm_chat.build_draft` instead (see `shell/actions.py`). When the API can't answer, one
    line says why; no reply is made up in its place."""
    from ..llm import LLMError
    from . import llm_chat

    try:
        llm_chat.core_reply(text, on_update)
    except LLMError as exc:
        add_chat("text", "reconix", llm_chat.couldnt_answer(exc), tone="muted")


def say_to_assistant(text: str) -> None:
    """A message typed while the run is going: record it, then answer (model or built-in)."""
    answer = say_operator_line(text)
    llm_answer(answer)


def new_assessment() -> bool:
    """Load a fresh assessment (earlier ones stay listed); the audit trail and history stay.

    False, and nothing changes, when the current one is still empty: it already is a fresh
    one, so no empty assessment is left behind and the numbering never skips.
    """
    from .persist import autosave  # (imported here: persist depends on this module)

    if is_empty_assessment():
        return False
    autosave()  # keep the one we leave up to date on disk
    seed.load_run_data()
    log_event("assessment.new")
    return True


# --- gates -----------------------------------------------------------------------------------
def gate_state(gate: str) -> str:
    """ "open" once the human decision is recorded, "rejected", or "pending"."""
    if gate == GATE_TEMPLATE:
        return "open" if selected_template() else "pending"
    if gate == GATE_SCOPE:
        return "open" if is_scope_approved() else "pending"
    if gate == GATE_PLAN:
        return "open" if get_run().plan_started else "pending"
    if gate == GATE_ACCOUNT:
        return "open" if not login_kind() or is_authenticated() else "pending"
    if gate == GATE_CODE:
        return "open" if not code_needed() or is_code_verified() else "pending"
    if gate.startswith(GATE_APPROVAL_PREFIX):
        decision = decision_for(gate[len(GATE_APPROVAL_PREFIX) :])
        if decision is None:
            return "pending"
        return "open" if decision.decision == "APPROVED" else "rejected"
    raise StoreValidationError(f"Unknown gate {gate}.")


def waiting_gate() -> str:
    return get_run().waiting_gate


def run_plan() -> None:
    """The operator runs the reviewed plan. Testing starts only after this."""
    run = get_run()
    if run.waiting_gate != GATE_PLAN or not is_scope_approved():
        raise StoreValidationError("The plan can only be run when Reconix asks for it.")
    if run.plan_started:
        raise StoreValidationError("The plan is already running.")
    if get_assessment().plan_drafting:
        raise StoreValidationError("The AI is still drafting the plan. It runs once the "
                                   "draft is in.")
    if not get_assessment().live.agent_run_id:
        raise StoreValidationError("There is no plan from the AI yet. Draft it again with "
                                   "/plan once the Core API and its model answer.")
    run.plan_started = True
    add_activity("USER", "Plan approved · testing starts", tone="ok")
    log_event("plan.run", get_assessment().label)


def is_plan_started() -> bool:
    return get_run().plan_started


def approve_more_time() -> None:
    """Continue past the scope's time limit (you chose Continue): the rest of the run has no
    limit, so it is not asked again."""
    run = get_run()
    if not time_limit_pending():
        raise StoreValidationError("There is no time-limit prompt right now.")
    run.time_approved = True
    get_scope().time_limit_minutes = 0
    add_activity("USER", "Continue past the time limit", tone="warn")
    log_event("time.extended", get_assessment().label)


def stop_for_time() -> None:
    """End the run at the time-limit prompt (you chose Stop)."""
    if not time_limit_pending():
        raise StoreValidationError("There is no time-limit prompt right now.")
    add_activity("USER", "Stop at the time limit", tone="block")
    _stop("you stopped at the time limit", "Stopped at the time limit. Nothing else will run.")


def reject_scope() -> None:
    """The operator rejects the drafted scope: nothing is tested and the assessment stops."""
    run = get_run()
    if run.waiting_gate != GATE_SCOPE or is_scope_approved() or run.stopped:
        raise StoreValidationError("The scope can only be rejected while it waits for approval.")
    add_activity("USER", "Scope rejected", tone="block")
    log_event("scope.rejected")
    _stop("you rejected the scope", "Scope rejected. Nothing was tested.")


def stop_run() -> None:
    """The operator stops the run. Findings so far are kept; nothing else plays."""
    run = get_run()
    if not run.started or is_finished():
        raise StoreValidationError("No assessment is running.")
    add_activity("USER", "Stop requested", tone="block")
    _stop("you stopped it", "You stopped it. Nothing else will run.")


# --- playing steps ---------------------------------------------------------------------------
def _applies(step: RunStep) -> bool:
    """A `when` step plays only if the approved tools need it."""
    if step.when == "login":
        return bool(login_kind())
    if step.when == "code":
        return code_needed()
    return True


def _next_index() -> Optional[int]:
    """Where the next step that applies sits in the script (None when the run can't move)."""
    run = get_run()
    script = lists.current().script
    if not run.started or run.stopped:
        return None
    index = run.cursor
    while index < len(script) and not _applies(script[index]):
        index += 1
    return index if index < len(script) else None


def peek() -> Optional[RunStep]:
    """The next step, without playing it (None when the run can't move)."""
    index = _next_index()
    return None if index is None else lists.current().script[index]


def advance() -> Optional[RunStep]:
    """Play the next step and return it.

    At a gate that is still pending, the run records that it is waiting and returns
    the gate step without moving. Returns None when there is nothing to play.
    """
    index = _next_index()
    if index is None:
        return None
    step = lists.current().script[index]
    run = get_run()
    run.cursor = index  # past the steps this run doesn't need
    if time_limit_pending():
        return None  # the run pauses; Execution offers Continue or Stop (run_host asks you)
    if step.kind == "gate":
        state = gate_state(step.name)
        if state == "pending":
            if run.waiting_gate != step.name and _policy_blocks_gate(step.name):
                return None
            run.waiting_gate = step.name
            return step
        run.waiting_gate = ""
        if state == "rejected":
            _skip_rejected(index, get_approval(step.name[len(GATE_APPROVAL_PREFIX) :]))
    else:
        _apply(step)
    run.cursor += 1
    return step


def _skip_rejected(index: int, request: ApprovalRequest) -> None:
    """The operator rejected the gated action at `script[index]`: it never runs, and the plan
    goes on with its next step (a later gated action still asks for its own approval).

    Every step of the action after its gate is dropped from the script but the progress
    bars: its "approved" banner, the tool line, the requests it would have sent, the
    "Validation completed" lines and the finding's evidence. The candidate finding the
    validation was meant to confirm stays UNCONFIRMED, with no evidence from it.
    """
    if request.api_approval_id:
        return  # the Core API skips it; what comes next is the API's next step
    script = lists.current().script
    end = index + 1
    while end < len(script) and not _ends_action_block(script[end]):
        end += 1
    # Nothing the action would have done or reported plays: only the progress bars move on
    # (no "approved" banner, tool line, request count, "Validation completed" or evidence)
    block = script[index + 1:end]
    for step in block:
        if step.kind == "confirm":
            finding = _finding(step.name)
            finding.evidence = [EVIDENCE_REJECTED]
            add_activity("POLICY", f"{step.name} stays unconfirmed: its validation was "
                         "rejected", tone="warn")
    script[index + 1:end] = [step for step in block if step.kind == "progress"]
    # A later check of the same validation may still run and record its evidence, but
    # without this one it can't confirm the finding (the HIGH check compares against the
    # MEDIUM baseline): its "confirm" keeps the evidence and drops the CONFIRMED
    for i in range(index + 1, len(script)):
        step = script[i]
        if step.kind == "confirm" and step.value:
            script[i] = replace(step, value=0)
            add_activity("POLICY", f"{step.name} stays unconfirmed: part of its validation "
                         "was rejected", tone="warn")
    add_chat(
        "banner",
        "policy",
        f"Rejected: {request.action}. Not executed — the plan goes on with its next step.",
        tone="block",
    )
    add_activity("POLICY", f"Skipped: {request.action} (rejected)", tone="block")


def _confirmed_later(fid: str) -> bool:
    """A step still to play confirms finding `fid` (it is a candidate until then)."""
    run = get_run()
    return any(step.kind == "confirm" and step.name == fid
               for step in lists.current().script[run.cursor + 1:])


def _check_before(index: int) -> Optional[ApprovalRequest]:
    """The gated check whose steps hold `script[index]` (None: no gate before it)."""
    script = lists.current().script
    for step in reversed(script[:index]):
        if step.kind == "gate" and step.name.startswith(GATE_APPROVAL_PREFIX):
            return get_approval(step.name[len(GATE_APPROVAL_PREFIX):])
        if step.kind == "phase":
            return None
    return None


def _ran_elsewhere(finding, request: ApprovalRequest) -> None:
    """The check was moved (Edit params) off the finding's own location: it can't confirm
    the finding, and what it saw is not the finding's evidence."""
    where = shown_line(request.path)
    finding.evidence = [elsewhere_note(request, where)]
    add_activity("POLICY", f"{finding.fid} stays unconfirmed: the check ran on {where}, "
                 "not on the finding's own location", tone="warn")


def _finding(fid: str):
    """The live finding row `fid` (the store's own; getters hand out copies)."""
    for finding in lists.current().findings:
        if finding.fid == fid:
            return finding
    raise StoreValidationError(f"No finding {fid}.")


EVIDENCE_PENDING = "Not collected yet: the validation that tests it waits for your approval."
EVIDENCE_REJECTED = "Not collected: you rejected the validation that would test it."


def _ends_action_block(step: RunStep) -> bool:
    """The next gate's risk line, a gate or a new phase: the rejected action's steps end."""
    return step.kind in ("gate", "phase") or (step.kind == "log" and step.source == "POLICY")


def _fill(text: str, tool: str = "") -> str:
    """Step text with its $names filled in. `tool` is what the step names as `$tool`."""
    assessment = get_assessment()
    tools = _approved_tools()
    return TextTemplate(text).safe_substitute(
        assessment=assessment.assessment_id or assessment.planned_id,
        target=assessment.target,
        template=template_name(assessment.template_id),
        picked="auto-selected" if assessment.template_auto else "selected",
        findings=findings_line(),
        login_need=_login_need(),
        tools=join_and(tools) if tools else "none",
        tool=approved_tool(tool, tools) if tool else "",
    )


def _approved_tools() -> List[str]:
    scope = get_scope()
    return list(scope.tools) if scope else []


def _login_need() -> str:
    """'a test account and a one-time code (for OWASP ZAP)', for the login step's text."""
    return f"{LOGIN_WORDS.get(login_kind(), 'no login')} (for {join_and(login_tools())})"


def _apply(step: RunStep) -> None:
    run = get_run()
    kind = step.kind
    # A literal step came from the Core API (tool output, the AI's words): shown as it is.
    text = step.text if step.literal else _fill(step.text, step.tool)
    if kind == "say":
        add_chat(step.entry, step.speaker, text, step.tone)
    elif kind == "card":
        add_chat("card", step.speaker, text, rows=step.rows)
    elif kind == "log":
        add_activity(step.source, text, step.tone)
    elif kind == "phase":
        run.phase = step.name
    elif kind == "parse":
        run.target_known = True
    elif kind == "progress":
        if step.name not in PROGRESS_BARS:
            raise StoreValidationError(f"Unknown progress bar {step.name}.")
        run.progress[step.name] = max(0, min(100, step.value))
    elif kind == "requests":
        run.requests += max(0, step.value)
    elif kind == "propose":
        _propose(step.method, step.path)
    elif kind == "reveal":
        if not finding_exists(step.name):
            raise StoreValidationError(f"No finding {step.name}.")
        if step.name not in run.revealed:
            run.revealed.append(step.name)
        if _confirmed_later(step.name):                # a candidate until validated
            finding = _finding(step.name)
            finding.validation = "UNCONFIRMED"
            if step.text:
                finding.description = _fill(step.text)
            finding.evidence = [EVIDENCE_PENDING]
    elif kind == "confirm":
        finding = _finding(step.name)
        if step.text:
            finding.description = step.text
        request = _check_before(run.cursor)
        if request is not None and not checks_finding(request, finding):
            _ran_elsewhere(finding, request)  # stays UNCONFIRMED: it tested something else
            return
        finding.evidence = [line for _, line in step.rows]
        if step.value:
            finding.validation = "CONFIRMED"
            add_activity("AI", f"{step.name} confirmed by the validation you approved",
                         tone="ok")
    elif kind == "complete":
        run.completed = True
        run.phase = "completed"
        run.finished_at = utc_now()
        log_event("run.completed")
    else:
        raise StoreValidationError(f"Unknown run step {kind}.")


def _propose(method: str, path: str) -> None:
    """The AI proposes a request; the policy check decides whether it runs."""
    add_activity("AI", f"Proposed request: {method} {path}", tone="warn")
    verdict = check_request(method, path)
    if verdict.allowed:
        get_run().requests += 1
        add_activity("TOOL", f"Executing {method} {path}")
        return
    add_activity("POLICY", f"Blocked: {verdict.reason}", tone="block")
    add_chat(
        "banner",
        "policy",
        f"Blocked: {method} {path} · {verdict.reason}. Not executed.",
        tone="block",
    )


def _policy_blocks_gate(gate: str) -> bool:
    """Before asking a human, the policy engine checks the action; a block stops the run."""
    if not gate.startswith(GATE_APPROVAL_PREFIX):
        return False
    request = get_approval(gate[len(GATE_APPROVAL_PREFIX) :])
    if request.api_approval_id:
        return False  # the Core API checked this action (S1) and checks it again (S2)
    verdict = check_request(request.method, request.path)
    if verdict.allowed:
        return False
    add_activity("POLICY", f"Blocked: {verdict.reason}", tone="block")
    _stop(
        f"policy blocked {request.action}",
        f"Blocked: {request.method} {request.path} · {verdict.reason}. Not executed.",
    )
    return True


def _stop(reason: str, banner: str) -> None:
    """End the run early: nothing else plays, and the chat says why."""
    run = get_run()
    run.stopped = reason
    run.phase = "stopped"
    at_login = run.waiting_gate in (GATE_ACCOUNT, GATE_CODE)
    run.stopped_at_gate = run.waiting_gate if at_login else ""
    run.waiting_gate = ""
    run.finished_at = utc_now()
    add_chat("banner", "policy", banner, tone="block")
    add_chat(
        "text",
        "reconix",
        "Assessment stopped. Nothing else will run. Type /new to start a new assessment.",
        tone="muted",
    )
    add_activity("SYS", "Assessment stopped", tone="block")
    log_event("run.stopped", run.stopped)


# --- what the dashboard shows ------------------------------------------------------------------
def display_phase() -> str:
    """The phase id to show: a waiting state at a gate, else the run's phase."""
    run = get_run()
    if run.stopped:
        return "stopped"
    if run.completed:
        return "completed"
    gate = run.waiting_gate
    if gate.startswith(GATE_APPROVAL_PREFIX):
        return "awaiting_approval"
    return WAITING_PHASES.get(gate, run.phase)


def is_completed() -> bool:
    return get_run().completed


def is_finished() -> bool:
    """Completed or stopped: nothing more will play."""
    run = get_run()
    return run.completed or bool(run.stopped)


def counters() -> Dict[str, int]:
    return {
        "requests": get_run().requests,
        "blocked": blocked_count(),
        "approvals": approvals_count(),
        "findings": len(list_findings()),
    }


def phase_progress() -> Dict[str, int]:
    progress = get_run().progress
    return {bar: progress.get(bar, 0) for bar in PROGRESS_BARS}


def task_status(key: str, run: RunState) -> str:
    """Where a plan task stands, read from the run's progress.

    The report task is special: it has no progress until a report is generated, so it
    reads "active" (ready to generate) once the assessment completes and "done" once a
    report is saved.
    """
    percent = run.progress.get(key, 0)
    if key == "report" and percent < 100:
        return "active" if run.completed else "pending"
    if percent >= 100:
        return "done"
    if percent > 0:
        return "active"
    return "pending"


def plan_tasks() -> List[PlanTask]:
    """The current assessment's plan, each task's status read live from the run.

    Empty until a template is chosen (the plan is template-specific). The dashboard shows
    these as a checklist: pending ·, loading ⠹, done ✓.
    """
    run = get_run()
    tasks = lists.current().plan
    for task in tasks:
        task.status = task_status(task.key, run)
    return list(tasks)


def pipeline_stage() -> str:
    """Which box of AI Assistant → Policy Engine → Tool Service is active ("" before a run)."""
    run = get_run()
    if not run.started or run.completed or run.stopped:
        return ""
    if run.waiting_gate:
        return "policy"
    for entry in reversed(list_activity()):
        stage = PIPELINE_SOURCES.get(entry.source)
        if stage:
            return stage
    return "ai"


def elapsed() -> Optional[timedelta]:
    """Testing time so far (from scope approval to now, or to the end of the run)."""
    run = get_run()
    if run.started_at is None:
        return None
    end = run.finished_at or utc_now()
    return end - run.started_at


def time_limit() -> timedelta:
    scope = get_scope()
    return timedelta(minutes=scope.time_limit_minutes if scope else 30)
