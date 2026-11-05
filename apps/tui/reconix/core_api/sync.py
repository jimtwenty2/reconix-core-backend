"""What the app sends to the Core API in Core API mode: its scope, chat lines and plan asks.

- The scope goes as a draft while you edit it, and is submitted and approved on the API
  when you approve it here (your approval in the app is the person's decision the API
  asks for). The API keeps one assessment per session, so a new assessment in the app
  opens a new API session.
- A chat line goes to /sessions/{id}/chat, with one line saying where the app's flow is
  (the API doesn't see the app's steps); the API answers with the scope and plan as
  context and saves both lines.
- A plan is asked for as a draft. The app runs its own plan, so the draft is discarded on
  the API right away: nothing is ever sent to run from here.
"""

import json
from typing import Dict, List, Optional, Tuple

from ..models import Assessment
from . import connect
from .client import CoreApiError
from .scope_map import plan_phases, scope_draft

# The app's assessment (planned id) -> its scope on the API.
_scopes: Dict[str, dict] = {}
_owner: Dict[str, str] = {}  # "planned_id": the app assessment the API session belongs to
# Scope errors that leave a chat answerable without the scope.
SCOPE_ONLY = {"SCOPE_NOT_SUPPORTED", "NO_API_TOOLS", "BAD_TARGET"}


def _forget() -> None:
    _scopes.clear()
    _owner.clear()


connect.on_new_session.append(_forget)


def sync_scope(assessment: Assessment) -> Optional[str]:
    """Send the assessment's scope (create, update, or submit and approve). Returns the
    API's assessment id once the scope is approved there, else None."""
    scope = assessment.scope
    if scope is None:
        return None
    draft = scope_draft(scope)
    key = assessment.planned_id
    if _owner.get("planned_id") not in (None, key):
        connect.reset()  # another assessment: a new API session for it
    session_id = connect.session_id()
    _owner["planned_id"] = key
    entry = _scopes.get(key)
    if entry is None:
        made = connect.request("POST", f"/sessions/{session_id}/scope-manifests", draft)
        entry = _scopes[key] = {
            "manifest_id": made["manifest_id"],
            "sent": draft,
            "assessment_id": None,
        }
        if assessment.requests:
            # What you asked for: the API plans toward it (it masks the text first).
            connect.request(
                "POST", f"/sessions/{session_id}/messages", {"content": assessment.requests[0].text}
            )
    elif entry["assessment_id"] is None and entry["sent"] != draft:
        connect.request("PATCH", f"/scope-manifests/{entry['manifest_id']}", draft)
        entry["sent"] = draft
    if scope.status == "APPROVED" and entry["assessment_id"] is None:
        submitted = connect.request(
            "POST",
            f"/scope-manifests/{entry['manifest_id']}/submit",
            {"name": assessment.label, "type": scope.kind},
        )
        connect.request("POST", f"/approvals/{submitted['approval_id']}/approve", {})
        entry["assessment_id"] = submitted["assessment"]["assessment_id"]
    return entry["assessment_id"]


def _use_active_model(approved: bool = False) -> List[str]:
    """Make the API use the app's active model; the activity lines to show."""
    from ..store.llm_chat import credentials
    from ..store.providers import active_model

    active = active_model()
    key, base = credentials(active) if active is not None else (None, None)
    note = connect.ensure_provider(active, key, base, approved)
    return [note] if note else []


def approve_active_model() -> List[str]:
    """You said yes in /provider: the API may use the active model (off this computer).
    Raises CoreApiError."""
    return _use_active_model(approved=True)


def chat_reply(text: str, assessment: Assessment) -> Tuple[str, List[str]]:
    """The API's answer to `text`, and notes for the activity log. Raises CoreApiError."""
    notes = _use_active_model()
    try:
        sync_scope(assessment)
    except CoreApiError as exc:
        if exc.code not in SCOPE_ONLY:
            raise
        notes.append(f"Core API chat without the scope: {exc}")
    sent = f"{text}\n{app_step_line()}"
    answered = connect.request("POST", f"/sessions/{connect.session_id()}/chat", {"content": sent})
    return answered["reply"]["content_masked"], notes


def app_step_line() -> str:
    """Where the app's flow is, added under the chat line: the API's model doesn't see the
    app's steps, and must not run ahead of them."""
    from ..store.progress import step_status

    status = step_status()
    return (f"(Reconix app: step {status.step}: {status.state}. The operator moves on only "
            f"with the app's menu: {status.choices}.)")


def plan_draft(assessment: Assessment) -> str:
    """The API's plan as the app's `{"phases": [...]}` JSON. Raises CoreApiError."""
    _use_active_model()
    assessment_id = sync_scope(assessment)
    if assessment_id is None:
        raise CoreApiError("SCOPE_NOT_APPROVED", "approve the scope first")
    drafted = connect.request("POST", f"/assessments/{assessment_id}/plan?draft=true")
    if drafted.get("draft"):
        run_id = drafted["agent_run"]["agent_run_id"]
        try:
            connect.request("POST", f"/agent-runs/{run_id}/discard")
        except CoreApiError:
            pass  # a new plan cancels an unsent draft anyway
    return json.dumps(plan_phases(drafted.get("plan", []), assessment.scope))
