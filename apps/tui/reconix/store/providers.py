"""LLM providers: the only seam the UI calls to configure and pick a model.

The Core API is the source of truth (`core_api.providers`): it keeps the providers, tests
them, and (for a model off this computer) asks you to approve the one that becomes active.
This module turns the API's rows into the `ProviderView`/`ActiveModel` the screens read,
and validates writes with the static catalog (labels, which fields a provider needs). The
deterministic core the API runs — scope, approvals, risk — is untouched: a model is only
ever configured, tested, activated or displayed.
"""

import ipaddress
from typing import List, Optional
from urllib.parse import urlsplit

from ..core_api import providers as api
from ..core_api.client import CoreApiError
from ..llm import catalog
from ..models import ActiveModel, ProviderView
from . import known_secrets
from .activity import log_event
from .errors import StoreValidationError
from .transcript import add_activity, add_chat

MAX_KEY = 4096
MAX_URL = 2048
MAX_MODEL = 200


def reset() -> None:
    """Forget the cached rows, test results and the keys typed this run."""
    api.reset()
    known_secrets.reset()


# --- helpers ----------------------------------------------------------------------------------


def _entry(provider_id: str) -> catalog.Provider:
    entry = catalog.get(provider_id)
    if entry is None or provider_id not in api.TYPE_FOR_ID:
        raise StoreValidationError("Unknown provider.")
    return entry


def _require_http(url: str) -> str:
    url = url.strip()
    if not (url.startswith("http://") or url.startswith("https://")):
        raise StoreValidationError("The base URL must start with http:// or https://.")
    if len(url) > MAX_URL:
        raise StoreValidationError("That base URL is too long.")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
    except ValueError:
        raise StoreValidationError("That base URL isn't a valid URL.") from None
    if parts.username is not None or parts.password is not None or "@" in parts.netloc:
        raise StoreValidationError("Put the API key in the key field, not in the base URL.")
    if _is_metadata_host(host):
        raise StoreValidationError("That address is a cloud metadata service, not a model server.")
    return url


_METADATA_HOSTS = ("metadata.google.internal", "metadata")


def _is_metadata_host(host: str) -> bool:
    if host in _METADATA_HOSTS:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_link_local or address == ipaddress.ip_address("fd00:ec2::254")


def _parse_models(entry: catalog.Provider, models: Optional[List[str]]) -> List[str]:
    names = [m.strip() for m in (models or []) if m and m.strip()]
    for name in names:
        if len(name) > MAX_MODEL:
            raise StoreValidationError("That model name is too long.")
    if not names:
        raise StoreValidationError("At least one model name is required.")
    if not entry.multi_model and len(names) > 1:
        raise StoreValidationError(f"{entry.label} holds a single model.")
    return names


def _key_hint(last4: Optional[str]) -> str:
    return f"…{last4}" if last4 else ""


def _rows(api_type: Optional[str] = None) -> List[dict]:
    """The API's provider rows, all of them or only this type.

    A Core API that is down or refuses answers with a CoreApiError, which no screen catches:
    the screens and the form catch StoreValidationError only, so it must be translated here,
    at the seam (see store/errors.py)."""
    try:
        rows = api.fetch_rows()
    except CoreApiError as exc:
        raise StoreValidationError(str(exc)) from None
    return rows if api_type is None else api.rows_for_type(rows, api_type)


# --- views ------------------------------------------------------------------------------------


def _view(entry: catalog.Provider, rows: List[dict], active: Optional[dict]) -> ProviderView:
    group = api.rows_for_type(rows, api.TYPE_FOR_ID[entry.id])
    status, detail = api.group_status(group)
    active_here = active and active in group
    facts = dict(
        needs_key=entry.needs_key,
        key_optional=entry.key_requirement == catalog.OPTIONAL,
        base_mode=entry.base_mode,
        multi_model=entry.multi_model,
    )
    if not group:
        return ProviderView(
            id=entry.id,
            label=entry.label,
            kind=entry.kind,
            configured=False,
            base_url=_default_base(entry),
            models=(),
            **facts,
        )
    first = group[0]
    return ProviderView(
        id=entry.id,
        label=entry.label,
        kind=entry.kind,
        configured=True,
        api_key_hint=_key_hint(first.get("api_key_last4")),
        base_url=first.get("base_url") or "",
        models=tuple(r["model_name"] for r in group),
        status=status,
        status_detail=detail,
        active_model=active["model_name"] if active_here else "",
        **facts,
    )


def _default_base(entry: catalog.Provider) -> str:
    if entry.base_mode == catalog.BASE_DEFAULT:
        return entry.default_base_url
    return ""


def list_providers() -> List[ProviderView]:
    """Every catalog provider, configured or not, from the API's current rows."""
    rows = _rows()
    active = api.active_row(rows)
    return [_view(entry, rows, active) for entry in catalog.all_providers()]


def get_provider(provider_id: str) -> ProviderView:
    entry = _entry(provider_id)
    rows = _rows()
    return _view(entry, rows, api.active_row(rows))


# --- writes -----------------------------------------------------------------------------------


def set_provider(
    provider_id: str,
    api_key: Optional[str] = None,
    base_url: Optional[str] = None,
    models: Optional[List[str]] = None,
) -> ProviderView:
    """Add or update a provider on the API: one row per model. A blank key on a model that
    already exists keeps its saved key."""
    entry = _entry(provider_id)
    api_key = (api_key or "").strip()
    if len(api_key) > MAX_KEY:
        raise StoreValidationError("That API key is too long.")
    if entry.id == "reconix":  # its address and model are the Core API's .env: only the key is sent
        return _set_reconix(entry, api_key)
    if entry.multi_model and not models:
        models = list(entry.default_models)
    final_models = _parse_models(entry, models)
    final_base = _resolve_base(entry, base_url)

    api_type = api.TYPE_FOR_ID[entry.id]
    existing = {r["model_name"]: r for r in _rows(api_type)}
    try:
        for model in final_models:
            row = existing.get(model)
            if row is None:
                if entry.needs_key and not api_key:
                    raise StoreValidationError(f"{entry.label} needs an API key.")
                api.create(
                    api_type, f"{entry.label} · {model}", model, final_base or None, api_key or None
                )
            elif api_key or (final_base and final_base != (row.get("base_url") or "")):
                if row.get("is_active"):
                    raise StoreValidationError(
                        f"{entry.label} · {model} is active; stop using it before changing its key."
                    )
                fields = {}
                if api_key:
                    fields["api_key"] = api_key
                if final_base:
                    fields["base_url"] = final_base
                api.patch(row["llm_provider_id"], fields)
    except CoreApiError as exc:
        raise StoreValidationError(str(exc)) from None
    if api_key:  # keep it masked if typed again in chat
        known_secrets.set_keys(provider_id, {api_key})
    log_event("llm.provider.set", provider_id)
    add_activity("SYS", f"LLM provider saved: {entry.label}")
    return get_provider(provider_id)


def _set_reconix(entry: catalog.Provider, api_key: str) -> ProviderView:
    """Save the Reconix key, or add the row back after it was unset. A blank key unsets the
    key: Reconix is then called with no key."""
    rows = _rows(api.TYPE_FOR_ID[entry.id])
    try:
        if rows:
            row = rows[0]
            if api_key or row.get("api_key_last4"):
                api.patch(row["llm_provider_id"], {"api_key": api_key or None})
        else:
            # The name the migration gives it. The Core API calls RECONIX_MODEL_NAME whatever
            # this says, so never take it from this computer's environment (LLM_MODEL).
            api.create(api.TYPE_FOR_ID[entry.id], "Reconix", "reconix", None, api_key or None)
    except CoreApiError as exc:
        raise StoreValidationError(str(exc)) from None
    if api_key:
        known_secrets.set_keys(entry.id, {api_key})
        log_event("llm.provider.set", entry.id)
        add_activity("SYS", f"LLM provider saved: {entry.label}")
    else:
        known_secrets.forget_provider(entry.id)
        log_event("llm.provider.key_cleared", entry.id)
        add_activity("SYS", f"LLM provider key removed: {entry.label}")
    return get_provider(entry.id)


def _resolve_base(entry: catalog.Provider, base_url: Optional[str]) -> str:
    provided = (base_url or "").strip()
    if provided:
        return _require_http(provided)
    if entry.base_mode == catalog.BASE_REQUIRED:
        raise StoreValidationError(f"{entry.label} needs a base URL.")
    if entry.base_mode == catalog.BASE_DEFAULT:
        return entry.default_base_url
    return ""


def unset_provider(provider_id: str) -> None:
    entry = _entry(provider_id)
    group = _rows(api.TYPE_FOR_ID[entry.id])
    if not group:
        raise StoreValidationError(f"{entry.label} is not configured.")
    # The API removes the active row too, and leaves no model active: the next /model picks one.
    try:
        for row in group:
            api.delete(row["llm_provider_id"])
        api.fetch_rows()
    except CoreApiError as exc:
        raise StoreValidationError(str(exc)) from None
    known_secrets.forget_provider(provider_id)
    log_event("llm.provider.unset", provider_id)
    add_activity("SYS", f"LLM provider removed: {entry.label}")


def test_provider(provider_id: str, model: Optional[str] = None) -> ProviderView:
    """Run the API's reachability test for one of the provider's models and show the result."""
    entry = _entry(provider_id)
    group = _rows(api.TYPE_FOR_ID[entry.id])
    if not group:
        raise StoreValidationError(f"{entry.label} is not configured.")
    model = (model or "").strip()
    row = next((r for r in group if r["model_name"] == model), group[0])
    try:
        result = api.test(row["llm_provider_id"])
    except CoreApiError as exc:
        raise StoreValidationError(str(exc)) from None
    status = "REACHABLE" if result.get("ok") else "UNREACHABLE"
    log_event("llm.provider.tested", f"{provider_id}:{status}")
    add_activity("SYS", f"LLM provider {entry.label}: {status.lower()}")
    return get_provider(provider_id)


def activate(provider_id: str, model: str) -> ActiveModel:
    """Make (provider, model) the active choice through the API. A model on this computer is
    active at once; a model off this computer is left waiting for your OK (`core_api_needs_ok`)."""
    entry = _entry(provider_id)
    group = _rows(api.TYPE_FOR_ID[entry.id])
    model = (model or "").strip()
    row = next((r for r in group if r["model_name"] == model), None)
    if row is None:
        raise StoreValidationError(f"{model or 'That model'} is not configured for {entry.label}.")
    if entry.id != "reconix" and not row.get("is_active"):
        if api.group_status(group)[0] != "REACHABLE":
            raise StoreValidationError("Test the connection first — the provider is not reachable.")

    api.clear_pending()
    try:
        answer = api.activate(row["llm_provider_id"])
    except CoreApiError as exc:
        if exc.code != "APPROVAL_PENDING":
            raise StoreValidationError(str(exc)) from None
        api.set_pending(exc.details.get("approval_id", ""), provider_id, model)
        return ActiveModel(provider_id, model, entry.label)
    approval = answer.get("approval")
    if approval:
        api.set_pending(approval["approval_id"], provider_id, model)
    else:
        _rows()  # refresh the cache; a Core API that died here is a store error, not a crash
        add_chat("text", "reconix", f"Switched to {entry.label} · {model}", tone="muted")
        add_activity("SYS", f"LLM model active: {entry.label} · {model}")
        log_event("llm.model.activated", f"{provider_id}/{model}")
    return ActiveModel(provider_id, model, entry.label)


def active_llm_settings() -> Optional[dict]:
    """Kept for callers being removed: the Core API uses its own active provider now."""
    return None


def active_model() -> Optional[ActiveModel]:
    """The provider/model active on the API (from the cached rows, no call)."""
    active = api.active_row(api.cached_rows())
    if active is None:
        return None
    provider_id = api.ID_FOR_TYPE.get(active["provider_type"])
    if provider_id is None:
        return None
    entry = catalog.get(provider_id)
    return ActiveModel(provider_id, active["model_name"], entry.label if entry else provider_id)


def is_local_url(url: str) -> bool:
    """Whether `url` names this computer: `localhost` or a loopback address."""
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return False
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def active_remote_label() -> Optional[str]:
    """The active provider's label when the active model runs off this computer, else None.
    What the operator is told before reference text goes out with their questions."""
    active = api.active_row(api.cached_rows())
    if active is None:
        return None
    if active.get("is_local"):
        return None
    base = active.get("base_url") or ""
    if base and is_local_url(base):
        return None
    provider_id = api.ID_FOR_TYPE.get(active["provider_type"], active["provider_type"])
    entry = catalog.get(provider_id)
    return entry.label if entry else provider_id


def core_api_needs_ok() -> bool:
    """A model off this computer was chosen and is waiting for your OK to become active."""
    return bool(api.pending())


def core_api_approve() -> None:
    """You said yes: approve the waiting activation so the Core API uses that model.
    Blocks on the network (a worker runs it). Raises a CoreApiError."""
    pending = api.pending()
    if not pending:
        return
    api.approve(pending["approval_id"])
    api.clear_pending()
    api.fetch_rows()
    entry = catalog.get(pending["app_id"])
    label = entry.label if entry else pending["app_id"]
    add_activity("AI", f"Core API model active: {label} · {pending['model']}", tone="ok")
    log_event("core_api.provider.approved")
