"""The Core API calls an assessment run makes: plan, send, next step, decide, analyze.

Network only: each function takes the ids it needs and returns the API's answer as it
came (plus the findings, where a tool may have run). They never touch the app's store, so
the app can call them in a worker and apply the answer on the UI thread (store/live.py).

The API runs everything that matters: check() before every step and again before it runs
(S2), the scope, the risk rules (LOW runs, MEDIUM and HIGH wait for a person), the approval
expiry and the typed target for HIGH (S5), and the tool itself in Kali (S7). The app shows
the result; when the API refuses, the CoreApiError carries its code and message.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import quote

from . import connect


def findings(assessment_id: str) -> List[dict]:
    """Every finding of the assessment (FindingOut rows), newest last."""
    rows = connect.request("GET", f"/findings?assessment_id={quote(assessment_id)}")
    return sorted(rows or [], key=lambda row: row.get("created_at") or "")


def draft_plan(assessment_id: str) -> dict:
    """A plan as a draft (PlanOut): nothing is sent or run until `send_plan`."""
    return connect.request("POST", f"/assessments/{quote(assessment_id)}/plan?draft=true")


def cancel_plan(agent_run_id: str) -> None:
    """Drop a draft that will not be sent (a new plan replaces it)."""
    connect.request("POST", f"/agent-runs/{quote(agent_run_id)}/cancel")


def with_findings(out: Dict[str, Any], assessment_id: str) -> Dict[str, Any]:
    """The answer plus the assessment's findings (a LOW step may have run inside it) and,
    when its step waits for a person, that approval (the card shows its hash and risk)."""
    action = out.get("action") or {}
    pending = None
    if action.get("approval_id") and action.get("action_status") == "PENDING":
        pending = approval(str(action["approval_id"]))
    return {**out, "findings": findings(assessment_id), "approval": pending}


def send_plan(agent_run_id: str, assessment_id: str) -> Dict[str, Any]:
    """Send the drafted plan's first step (PlanOut + findings)."""
    out = connect.request("POST", f"/agent-runs/{quote(agent_run_id)}/send")
    return with_findings(out, assessment_id)


def next_step(assessment_id: str) -> Dict[str, Any]:
    """The agent's next step, from the newest tool outputs (PlanOut + findings)."""
    out = connect.request("POST", f"/assessments/{quote(assessment_id)}/next-step")
    return with_findings(out, assessment_id)


def approval(approval_id: str) -> dict:
    return connect.request("GET", f"/approvals/{quote(approval_id)}")


def decide(
    approval_id: str, approve: bool, assessment_id: str, typed_target: Optional[str] = None
) -> Dict[str, Any]:
    """A person's decision on an action. Approving runs the tool inside the call, so this
    can take as long as the tool does. Returns {"approval", "action", "findings"}."""
    body: Dict[str, Any] = {}
    if typed_target:
        body["typed_target"] = typed_target
    verb = "approve" if approve else "reject"
    decided = connect.request("POST", f"/approvals/{quote(approval_id)}/{verb}", body)
    action = None
    if decided.get("action_id"):
        action = connect.request("GET", f"/actions/{quote(decided['action_id'])}")
    return {"approval": decided, "action": action, "findings": findings(assessment_id)}


def analyze(assessment_id: str, finding_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """The agent's analysis of the findings (AnalysisOut + findings). With finding_ids, only
    those are analyzed (per step, as a step finds them); without, every OPEN finding."""
    body = {"finding_ids": finding_ids} if finding_ids else None
    out = connect.request("POST", f"/assessments/{quote(assessment_id)}/analyze", body)
    return with_findings(out, assessment_id)


def triage(finding_id: str, finding_status: str) -> dict:
    """A person's review of one finding (OPEN, FALSE_POSITIVE or FIXED)."""
    return connect.request(
        "PATCH", f"/findings/{quote(finding_id)}", {"finding_status": finding_status}
    )
