"""What the app sends to the Core API in Core API mode: its scope, chat lines and plan asks.

- The scope goes as a draft while you edit it, and is submitted and approved on the API
  when you approve it here (your approval in the app is the person's decision the API
  asks for). The API keeps one assessment per session, so a new assessment in the app
  opens a new API session.
- A chat line goes to /sessions/{id}/chat, with one line saying where the app's flow is
  (the API doesn't see the app's steps); the API answers with the scope and plan as
  context and saves both lines.
- The plan, the run and the findings are the API's own (store/ai_plan.py, store/live.py).
"""

from typing import Dict, List, Optional, Tuple

from ..models import Assessment
from . import connect
from .client import CoreApiError
from .scope_map import scope_draft

# The app's assessment (planned id) -> its scope on the API.
_scopes: Dict[str, dict] = {}
_owner: Dict[str, str] = {}  # "planned_id": the app assessment the API session belongs to
# Scope errors that leave a chat answerable without the scope.
SCOPE_ONLY = {"SCOPE_NOT_SUPPORTED", "NO_API_TOOLS", "BAD_TARGET"}
# The scope's kind as the API's AI reads it: it picks that kind's testing techniques.
KIND_NAMES = {"web_url": "Web URL", "api": "API", "network": "Network", "source": "Source Code"}


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
    draft = scope_draft(scope, _spec_doc_url(assessment))
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
        first = first_message(assessment)
        if first:
            # What you asked for: the API plans toward it (it masks the text first).
            connect.request("POST", f"/sessions/{session_id}/messages", {"content": first})
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


def _spec_doc_url(assessment: Assessment) -> Optional[str]:
    """The OpenAPI document URL of an attached spec (one fetched from a URL), or None, so
    the API fuzzes that document path instead of a guessed <base>/openapi.json."""
    spec = assessment.api_spec
    url = getattr(spec, "source_url", "") if spec is not None else ""
    return url or None


def first_message(assessment: Assessment) -> str:
    """The first chat line the API gets: the assessment type, so its AI plans that kind's
    techniques, then what you asked for ("" when there is neither)."""
    kind = KIND_NAMES.get(assessment.scope.kind, "") if assessment.scope else ""
    lines = [f"Assessment type: {kind}"] if kind else []
    if assessment.requests:
        lines.append(assessment.requests[0].text)
    return "\n".join(lines)


def use_active_model(approved: bool = False) -> List[str]:
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
    return use_active_model(approved=True)



def ask_model(prompt: str) -> str:
    """One structured ask to the API's model (no scope sync, no app-step line): used for the
    scope suggestion. Returns the masked reply. Raises CoreApiError."""
    from ..store.providers import active_model

    if active_model() is not None:
        use_active_model()
    answered = connect.request(
        "POST", f"/sessions/{connect.session_id()}/chat", {"content": prompt}
    )
    return answered["reply"]["content_masked"]

def chat_reply(text: str, assessment: Assessment) -> Tuple[str, List[str]]:
    """The API's answer to `text`, and notes for the activity log. Raises CoreApiError.
    With no model of your own (/provider), the API answers with its own (.env)."""
    from ..store.providers import active_model

    notes = use_active_model() if active_model() is not None else []
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
