"""LLM providers, read and written through the Core API (`/api/v1/llm-providers`).

The Core API is the source of truth for providers and the active model: it keeps them,
tests them, and (for a model off this computer) asks a person to approve the one that
becomes active. This module makes those calls and caches the rows so the header can show
the active model without a call on every refresh.

The API stores one row per model (`model_name`, `is_active`, `is_local`); the app groups
the rows of one `provider_type` into a single provider the menus show. Test results are
not stored by the API, so this module keeps the last `POST /{id}/test` result in memory.
"""

from typing import Dict, List, Optional, Tuple

from .connect import on_new_session, request

# The app's provider ids <-> the API's provider_type.
TYPE_FOR_ID = {
    "reconix": "RECONIX",
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "deepseek": "DEEPSEEK",
    "ollama": "OLLAMA",
    "openai_compatible": "OPENAI_API_COMPATIBLE",
}
ID_FOR_TYPE = {api_type: app_id for app_id, api_type in TYPE_FOR_ID.items()}

# Caches, all per app run (cleared when the API session is opened again).
_rows: Optional[List[dict]] = None  # None: not fetched yet
_reach: Dict[str, Tuple[str, str]] = {}  # llm_provider_id -> (status, detail)
# A model off this computer that is waiting for your OK: (approval_id, app_id, model).
_pending: Dict[str, str] = {}


def reset() -> None:
    """Forget every cached row and test result (a fresh session re-reads the API)."""
    global _rows
    _rows = None
    _reach.clear()
    _pending.clear()


on_new_session.append(reset)


# --- rows -------------------------------------------------------------------------------------


def fetch_rows() -> List[dict]:
    """Read the providers from the API and cache them."""
    global _rows
    _rows = list(request("GET", "/llm-providers") or [])
    return _rows


def cached_rows() -> List[dict]:
    """The last rows read, without a call (empty before the first read)."""
    return list(_rows or [])


def rows_for_type(rows: List[dict], api_type: str) -> List[dict]:
    return [r for r in rows if r.get("provider_type") == api_type]


def active_row(rows: List[dict]) -> Optional[dict]:
    return next((r for r in rows if r.get("is_active")), None)


# --- reachability (kept in memory; the API does not store it) ---------------------------------


def group_status(rows: List[dict]) -> Tuple[str, str]:
    """The status to show for a group of rows: REACHABLE if any row tested ok, UNREACHABLE
    if some were tested and none answered, else UNTESTED."""
    seen = [_reach.get(r["llm_provider_id"]) for r in rows]
    seen = [s for s in seen if s]
    if any(s[0] == "REACHABLE" for s in seen):
        return "REACHABLE", next(s[1] for s in seen if s[0] == "REACHABLE")
    if seen:
        return "UNREACHABLE", seen[0][1]
    return "UNTESTED", ""


# --- writes -----------------------------------------------------------------------------------


def create(
    api_type: str,
    display_name: str,
    model_name: str,
    base_url: Optional[str],
    api_key: Optional[str],
) -> dict:
    body: Dict[str, object] = {
        "provider_type": api_type,
        "display_name": display_name[:100],
        "model_name": model_name,
    }
    if base_url:
        body["base_url"] = base_url
    if api_key:
        body["api_key"] = api_key
    return request("POST", "/llm-providers", body)


def patch(provider_id: str, fields: dict) -> dict:
    _reach.pop(provider_id, None)  # a changed key or address is untested again
    return request("PATCH", f"/llm-providers/{provider_id}", fields)


def delete(provider_id: str) -> None:
    request("DELETE", f"/llm-providers/{provider_id}")
    _reach.pop(provider_id, None)


def test(provider_id: str) -> dict:
    """Run the API's connectivity test and remember the result for the header and menus."""
    result = request("POST", f"/llm-providers/{provider_id}/test")
    status = "REACHABLE" if result.get("ok") else "UNREACHABLE"
    detail = (
        result.get("message")
        or (result.get("code") or "").replace("_", " ").lower()
        or ("ok" if result.get("ok") else "no answer")
    )
    _reach[provider_id] = (status, detail)
    return result


def models(provider_id: str) -> List[str]:
    answered = request("GET", f"/llm-providers/{provider_id}/models")
    return list(answered.get("models", []))


def activate(provider_id: str) -> dict:
    """Make the row active, or (for a model off this computer) start its approval. Returns
    the API's activation answer {llm_provider, approval}."""
    return request("POST", f"/llm-providers/{provider_id}/activate")


def approve(approval_id: str) -> None:
    request("POST", f"/approvals/{approval_id}/approve", {})


# --- the pending off-machine activation -------------------------------------------------------


def set_pending(approval_id: str, app_id: str, model: str) -> None:
    _pending.update(approval_id=approval_id, app_id=app_id, model=model)


def pending() -> Dict[str, str]:
    return dict(_pending)


def clear_pending() -> None:
    _pending.clear()
