"""The test plan, drafted by the AI on the Core API after the scope is approved.

The API's agent plans inside the approved scope; the API checks each planned step and
keeps the plan as a draft: nothing is sent or run until you choose Run plan (then
store/live.py sends it). The plan screen shows the draft's steps and names the plan's
phases after them. The model never touches the run, the approvals or the scope here.

Three steps keep the network call off the UI thread: `plan_draft_request()` (UI thread),
`fetch_plan_draft()` (a worker: the API call, which waits for the model), and
`apply_plan_draft()` or `plan_draft_failed()` (UI thread) record the outcome.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..core_api import run_api
from ..core_api.scope_map import plan_phases
from ..models import Assessment
from . import lists
from .activity import log_event
from .live import record_plan
from .transcript import add_activity, add_chat


@dataclass(frozen=True)
class PlanDraftRequest:
    assessment: Assessment  # the one it is for (if you move on, the draft is dropped)
    assessment_id: str  # the API's assessment


def plan_draft_request() -> Optional[PlanDraftRequest]:
    """Start a draft (UI thread). None before the scope is approved on the API, once the
    plan runs, or while a draft is on its way; else Run plan waits for it."""
    assessment = lists.current()
    scope = assessment.scope
    if scope is None or scope.status != "APPROVED" or not assessment.live.assessment_id:
        return None
    if assessment.run.plan_started or assessment.plan_drafting:
        return None
    assessment.plan_drafting = True
    add_activity("AI", "Drafting the plan on the Core API…")
    return PlanDraftRequest(assessment, assessment.live.assessment_id)


def fetch_plan_draft(request: PlanDraftRequest) -> Dict[str, Any]:
    """The API's draft plan (PlanOut). Blocks until the model answers, so it runs in a
    worker. Raises CoreApiError (an LLMError) with the API's own reason. The API plans with
    whatever provider is active on it (chosen in /provider)."""
    return run_api.draft_plan(request.assessment_id)


def apply_plan_draft(request: PlanDraftRequest, out: Dict[str, Any]) -> bool:
    """Keep the API's draft (UI thread). False when it isn't used; a note says why."""
    assessment = request.assessment
    assessment.plan_drafting = False
    if assessment is not lists.current() or assessment.run.plan_started:
        return False  # you moved on: the draft is out of date
    record_plan(assessment, out)
    steps = assessment.live.plan_steps
    if not out.get("draft") or not steps:
        add_activity("AI", "The AI found nothing to plan inside this scope.", tone="warn")
        add_chat(
            "text",
            "reconix",
            (
                out.get("text")
                or "The AI has no plan for this scope. Edit the scope, or ask it in the chat."
            )[:600],
            tone="muted",
        )
        return False
    phases = {row["key"]: row for row in plan_phases(steps, assessment.scope)["phases"]}
    for task in assessment.plan:
        row = phases.get(task.key)
        if row is not None:
            task.label = (row["label"] or task.label)[:40]
            task.detail = (row["detail"] or "")[:90]
            task.tools = tuple(row["tools"])
    for blocked in assessment.live.blocked_steps:
        add_activity(
            "POLICY",
            f"Plan step {blocked.get('order')} refused by the "
            f"{blocked.get('blocked_by', 'check')} check: "
            f"{blocked.get('reason') or 'out of scope'}",
            tone="block",
        )
    assessment.plan_author = assessment.live.model_name or "the Core API's model"
    add_activity("AI", f"Plan drafted by {assessment.plan_author}: {len(steps)} steps", tone="ok")
    log_event("plan.drafted", assessment.plan_author)
    return True


def plan_draft_failed(request: PlanDraftRequest, reason: str) -> None:
    """The API couldn't draft the plan (UI thread): say why; Run plan stays closed."""
    request.assessment.plan_drafting = False
    if request.assessment is lists.current():
        add_activity("AI", f"The AI couldn't draft the plan: {reason}", tone="block")
        add_chat(
            "text",
            "reconix",
            f"The AI couldn't draft the plan: {reason}. Type /plan to try again.",
            tone="muted",
        )


def plan_drafting() -> bool:
    """Whether the AI is drafting the current assessment's plan (Run plan waits)."""
    return lists.current().plan_drafting


def plan_author() -> str:
    """The model that drafted the current plan ("" before there is one)."""
    return lists.current().plan_author
