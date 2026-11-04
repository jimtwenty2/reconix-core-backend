"""Where each step of the screen flow stands, read from the current run.

The flow line under the session bar shows these: "done" ✓, "stopped" ✕, "waiting" !
(the run is paused there for a human decision). Steps with no entry are pending.

`step_status()` says the same in words, for the step chat and the model's context: the
step, what has (not) happened, and what the operator decides it with.
"""

from typing import Dict, NamedTuple

from ..models import (
    GATE_ACCOUNT, GATE_APPROVAL_PREFIX, GATE_CODE, GATE_PLAN, GATE_SCOPE, GATE_TEMPLATE,
)
from . import lists
from .approvals import get_approval, list_approval_decisions
from .plan_order import ORDER_RULE


def step_states() -> Dict[str, str]:
    """{"template": "done", "approval": "waiting", ...} for steps with a settled state."""
    assessment = lists.current()
    run = assessment.run
    gate = run.waiting_gate
    states: Dict[str, str] = {}
    if run.started:
        states["start"] = "done"

    scope_ok = assessment.scope is not None and assessment.scope.status == "APPROVED"
    if scope_ok:
        states["template"] = "done"
    elif run.stopped:
        states["template"] = "stopped"
    elif gate in (GATE_TEMPLATE, GATE_SCOPE):
        states["template"] = "waiting"

    if run.plan_started:
        states["plan"] = "done"
    elif gate == GATE_PLAN and not run.stopped:
        states["plan"] = "waiting"

    # A rejected action is skipped and the plan goes on, so a rejection is a decision like
    # any other: the step is done once every gated action is decided. A run that stopped
    # with actions still undecided (Ctrl+C, or a copy saved before rejections were skipped)
    # shows the step stopped.
    decisions = list_approval_decisions()
    all_decided = bool(assessment.approvals) and len(decisions) >= len(assessment.approvals)
    if gate.startswith(GATE_APPROVAL_PREFIX) and not run.stopped:
        states["approval"] = "waiting"
    elif all_decided:
        states["approval"] = "done"
    elif run.stopped and any(d.decision == "REJECTED" for d in decisions):
        states["approval"] = "stopped"

    if run.completed:
        states["execution"] = "done"
    elif run.stopped and run.plan_started:
        states["execution"] = "stopped"
    elif gate in (GATE_ACCOUNT, GATE_CODE) and not run.stopped:
        states["execution"] = "waiting"

    # The findings are final once the run completed (nothing else can add one): the step is
    # settled even before the Findings screen was opened.
    if run.completed and run.revealed:
        states["findings"] = "done"

    if run.report_path:
        states["report"] = "done"
    return states


class StepStatus(NamedTuple):
    """Where the assessment is, in plain words. `pending`: a decision waits for the operator."""

    step: str
    state: str
    choices: str
    pending: bool = False


def step_status() -> StepStatus:
    """The current step, what has happened so far and what the operator does next."""
    assessment = lists.current()
    run = assessment.run
    gate = run.waiting_gate
    scope = assessment.scope
    if not run.started:
        return StepStatus("Start", "no assessment yet; nothing has run",
                          "type a target to start one")
    if run.stopped:
        return StepStatus("Stopped", f"the assessment stopped ({run.stopped}); nothing "
                          "else will run", "/new starts another assessment")
    if run.completed:
        return StepStatus("Findings", "the plan has run to the end",
                          "review the findings, then generate the report")
    if gate == GATE_TEMPLATE:
        return StepStatus("Template", "the target fits more than one template; nothing has "
                          "run", "pick the template in the menu", pending=True)
    if gate == GATE_SCOPE and scope is not None:
        return StepStatus("Template · scope review", "the scope is a draft: nothing is "
                          "approved and nothing has run",
                          "Approve scope, Edit manifest or Reject in the menu (after Approve "
                          "scope comes the Plan step: nothing runs until the operator chooses "
                          "Run plan there)", pending=True)
    if scope is None or scope.status != "APPROVED":
        return StepStatus("Template", "Reconix is drafting the scope; nothing has run",
                          "wait for the scope draft")
    if gate == GATE_PLAN:
        if getattr(assessment, "plan_drafting", False):
            return StepStatus("Plan", "the scope is approved; the model is drafting the plan; "
                              "nothing has run", "wait for the draft, then Run plan")
        return StepStatus("Plan", "the scope is approved and locked; the plan waits for you "
                          "to run it; nothing has run yet",
                          "Run plan, Edit steps or Cancel in the menu (Run plan starts "
                          "testing; MEDIUM and HIGH steps still wait for approval). Order: "
                          f"{ORDER_RULE}", pending=True)
    if gate.startswith(GATE_APPROVAL_PREFIX):
        request = get_approval(gate[len(GATE_APPROVAL_PREFIX):])
        return StepStatus("Approval", f"the plan is running and paused at {request.action} "
                          f"({request.risk} risk); it has not run",
                          "Approve & run, Reject, View details or Edit params in the menu",
                          pending=True)
    if gate in (GATE_ACCOUNT, GATE_CODE):
        return StepStatus("Execution · login", "the run waits for the target login",
                          "press Enter on the Execution screen to open the secure input")
    if not run.plan_started:
        return StepStatus("Plan", "the scope is approved; Reconix is preparing the plan; "
                          "nothing has run", "wait for the plan")
    return StepStatus("Execution", "the plan is running; only the steps marked done in "
                      "the plan have run", "watch the Execution screen; /stop stops it")
