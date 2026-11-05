"""The Core API session, and the model it uses: the one active in this app.

One session per app run, opened on first use. Its token stays in this module's memory.
If the API restarts (the token is unknown, 401), a new session is opened once and the
caller's sync starts over (`on_new_session` hooks clear what belonged to the old one).

The API calls the model itself, so it must use the provider you chose with /provider:
`ensure_provider` adds it there (the key goes once, over this computer's loopback, and the
API keeps it encrypted) and makes it active. A model on this computer is active at once. A
model off this computer needs the API's `configuration` approval: that is approved only
with `approved=True`, which /provider passes after you said yes to it there; without it
the call raises NEEDS_APPROVAL and nothing is approved.
"""

from typing import Any, Callable, Dict, List, Optional, Tuple

from ..models import ActiveModel
from .client import CoreApiError, call

# The app's provider ids -> llm_providers.provider_type. The app's "reconix" entry is a
# hosted OpenAI-compatible model, not the API's built-in local RECONIX model.
PROVIDER_TYPES = {
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "deepseek": "DEEPSEEK",
    "ollama": "OLLAMA",
    "openai_compatible": "OPENAI_API_COMPATIBLE",
    "reconix": "OPENAI_API_COMPATIBLE",
}

_session: Dict[str, str] = {"token": "", "session_id": ""}
_provider_synced: Dict[str, Tuple[str, ...]] = {}
on_new_session: List[Callable[[], None]] = []


def session_id() -> str:
    """This app's session on the API, opened on first use."""
    if not _session["token"]:
        _open_session()
    return _session["session_id"]


def request(method: str, path: str, body: Any = None) -> Any:
    """A call as this app's session. A session the API no longer knows (it restarted) is
    opened again once; the call is not repeated, because the caller's ids are stale."""
    session_id()
    try:
        return call(method, path, body, _session["token"])
    except CoreApiError as exc:
        if exc.status == 401:
            reset()
        raise


def reset() -> None:
    """Forget the session (and everything synced to it)."""
    _session.update(token="", session_id="")
    _provider_synced.clear()
    for hook in on_new_session:
        hook()


def web_sign_in_code() -> str:
    """A one-time code (valid 2 minutes) the web dashboard trades for its own Core API
    session, so it signs in as this app's operator; "" when the API can't give one (the
    dashboard then opens its own session)."""
    try:
        return str(request("POST", "/sessions/web-sign-in-codes").get("code") or "")
    except CoreApiError:
        return ""


def _open_session() -> None:
    opened = call("POST", "/sessions", {"interface": "cli"})
    _session.update(token=opened["token"], session_id=opened["session_id"])


def ensure_provider(
    active: Optional[ActiveModel], key: Optional[str], base: Optional[str],
    approved: bool = False,
) -> Optional[str]:
    """Make the API use `active`. Returns a line for the activity log when something was
    changed on the API, else None. Raises CoreApiError (NEEDS_APPROVAL for a model off this
    computer that you haven't approved in /provider)."""
    if active is None:
        raise CoreApiError("NO_MODEL", "choose a model with /provider first")
    provider_type = PROVIDER_TYPES.get(active.provider_id)
    if provider_type is None:
        raise CoreApiError(
            "PROVIDER_NOT_SUPPORTED", f"the Core API can't use {active.label or active.provider_id}"
        )
    fingerprint = (provider_type, active.model, base or "", (key or "")[-4:])
    if _provider_synced.get("active") == fingerprint:
        return None
    row = _find(provider_type, active.model, base) or _add(provider_type, active, key, base)
    if key and row.get("api_key_last4") != key[-4:]:
        row = request("PATCH", f"/llm-providers/{row['llm_provider_id']}", {"api_key": key})
    if not row["is_active"]:
        label = f"{active.label or active.provider_id} · {active.model}"
        if not row.get("is_local") and not approved:
            raise CoreApiError("NEEDS_APPROVAL", f"the Core API needs your OK to use {label}: "
                                                 "choose it again in /provider")
        _activate(row["llm_provider_id"])
    _provider_synced["active"] = fingerprint
    return f"Core API uses {active.label or active.provider_id} · {active.model}"


def _activate(provider_id: str) -> None:
    """Make the provider active; approve its `configuration` approval (also one still
    waiting from an earlier try). Only called once you approved it, or for a local model."""
    try:
        activation = request("POST", f"/llm-providers/{provider_id}/activate")
        approval_id = (activation.get("approval") or {}).get("approval_id")
    except CoreApiError as exc:
        if exc.code != "APPROVAL_PENDING":
            raise
        approval_id = exc.details.get("approval_id")
    if approval_id:
        request("POST", f"/approvals/{approval_id}/approve", {})


def _find(provider_type: str, model: str, base: Optional[str]) -> Optional[dict]:
    for row in request("GET", "/llm-providers"):
        same_base = (row.get("base_url") or "") == (base or "")
        if row["provider_type"] == provider_type and row["model_name"] == model and same_base:
            return row
    return None


def _add(provider_type: str, active: ActiveModel, key: Optional[str], base: Optional[str]) -> dict:
    body: Dict[str, Any] = {
        "provider_type": provider_type,
        "display_name": f"{active.label or active.provider_id} (reconix-ai)"[:100],
        "model_name": active.model,
    }
    if base:
        body["base_url"] = base
    if key:
        body["api_key"] = key
    return request("POST", "/llm-providers", body)
