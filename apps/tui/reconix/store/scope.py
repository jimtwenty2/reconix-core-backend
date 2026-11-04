"""The scope manifest, its approval, and the policy check every proposed request goes through.

`check_request` is the policy engine of this in-memory backend. The UI never decides
whether a request may run; it shows the verdict recorded here.
"""

from datetime import timedelta
from typing import List, Optional

from ..models import GATE_SCOPE, PolicyVerdict, ScopeManifest
from ..models.base import utc_now
from . import lists
from .activity import log_event
from .assessment import shown_line
from .errors import StoreValidationError
from .policy import (
    network_entry, request_reason,
)
from .tools import known_tool
from .transcript import add_activity, add_chat


def _shown(items: List[str]) -> str:
    """Typed values repeated in an error, masked (a pasted URL may hold a password)."""
    return ", ".join(shown_line(item) for item in items)


def get_scope() -> Optional[ScopeManifest]:
    """The current assessment's scope, or None before a template has been chosen."""
    return lists.current().scope


def is_scope_approved() -> bool:
    scope = get_scope()
    return scope is not None and scope.status == "APPROVED"


def approve_scope() -> ScopeManifest:
    """Approve the drafted scope. Testing cannot start before this."""
    run = lists.current().run
    if run.waiting_gate != GATE_SCOPE:
        raise StoreValidationError("The scope can only be approved when Reconix asks for it.")
    scope = get_scope()
    if scope.status == "APPROVED":
        raise StoreValidationError("The scope is already approved.")
    from .templates import align_to_scope   # templates import the policy, so not at the top

    scope.status = "APPROVED"
    assessment = lists.current()
    align_to_scope(assessment)
    assessment.assessment_id = assessment.planned_id
    run.started_at = utc_now()
    add_activity("USER", "Scope approved", tone="ok")
    add_activity("SYS", f"Assessment {assessment.assessment_id} created")
    log_event("scope.approved", assessment.assessment_id)
    return scope


MAX_TIME_LIMIT = 480     # 8 hours
HTTP_METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")
# scope kind -> the methods a scope of that kind may allow (the templates' own words)
KIND_METHODS = {"web_url": HTTP_METHODS, "api": HTTP_METHODS,
                "network": ("TCP connect",), "source": ("read",)}


def _clean_list(values) -> list:
    seen, out = set(), []
    for value in values:
        value = value.strip()
        key = value.casefold()
        if value and key not in seen:
            seen.add(key)
            out.append(value)
    return out


def scope_editable() -> bool:
    """The scope waits for approval, so the operator may still edit it."""
    scope = get_scope()
    return scope is not None and scope.status != "APPROVED" \
        and lists.current().run.waiting_gate == GATE_SCOPE


def edit_scope(*, allowed_methods=None, excluded_paths=None, time_limit_minutes=None,
               tools=None, allowed_ports=None) -> ScopeManifest:
    """Apply the operator's scope edits before approval. Only the fields given change.

    Validates every field for the scope's kind first and raises StoreValidationError on bad
    input; only when all of them pass is the scope changed (all or nothing). The policy
    engine then enforces exactly what was approved.
    """
    if not scope_editable():
        raise StoreValidationError("The scope can only be edited while it waits for approval.")
    scope = get_scope()
    changes = {}

    if allowed_methods is not None:
        allowed = {m.casefold(): m for m in KIND_METHODS.get(scope.kind, ())}
        methods = _clean_list(allowed_methods)
        if not methods:
            raise StoreValidationError("Keep at least one allowed method.")
        bad = [m for m in methods if m.casefold() not in allowed]
        if bad:
            raise StoreValidationError(f"Not an allowed method: {_shown(bad)} (use "
                                       f"{', '.join(allowed.values())}).")
        changes["allowed_methods"] = [allowed[m.casefold()] for m in methods]

    if excluded_paths is not None:
        paths = _clean_list(excluded_paths)
        if scope.kind in ("web_url", "api"):
            bad = [p for p in paths if not p.startswith("/")]
            if bad:
                raise StoreValidationError(f"Excluded paths start with '/': {_shown(bad)}.")
        if scope.kind == "network":
            bad = [p for p in paths if network_entry(p) is None]
            if bad:
                raise StoreValidationError(
                    f"Exclude a host, range or host:port (e.g. 10.0.0.5:22): {_shown(bad)}.")
        changes["excluded_paths"] = paths

    if allowed_ports is not None:
        ports = []
        for item in allowed_ports:
            item = str(item).strip()
            if not item:
                continue
            if not (item.isascii() and item.isdigit()) or not 1 <= int(item) <= 65535:
                raise StoreValidationError(f"Not a valid port (1–65535): {shown_line(item)}.")
            if int(item) not in ports:
                ports.append(int(item))
        if not ports:
            raise StoreValidationError("Keep at least one allowed port.")
        changes["allowed_ports"] = ports

    if time_limit_minutes is not None:
        try:
            minutes = int(time_limit_minutes)
        except (TypeError, ValueError):
            raise StoreValidationError("The time limit is a number of minutes.") from None
        if not 1 <= minutes <= MAX_TIME_LIMIT:
            raise StoreValidationError(
                f"Keep the time limit between 1 and {MAX_TIME_LIMIT} minutes.")
        changes["time_limit_minutes"] = minutes

    if tools is not None:
        cleaned = _clean_list(tools)
        if not cleaned:
            raise StoreValidationError("Keep at least one tool.")
        unknown = [t for t in cleaned if not known_tool(t)]
        if unknown:
            raise StoreValidationError(f"Unknown tool: {_shown(unknown)}.")
        changes["tools"] = _clean_list(known_tool(t) for t in cleaned)

    for field, value in changes.items():      # every field passed: now change the scope
        setattr(scope, field, value)
    add_activity("USER", "Scope edited", tone="ok")
    add_chat("text", "reconix", "Scope updated. Review the manifest and approve when ready.",
             tone="muted")
    log_event("scope.edited")
    return scope


def time_limit_reached() -> bool:
    """True once testing has run longer than the scope's time limit."""
    scope = get_scope()
    started = lists.current().run.started_at
    if scope is None or started is None:
        return False
    return utc_now() - started > timedelta(minutes=scope.time_limit_minutes)


def _decide(method: str, target: str) -> str:
    """"" when the request may run, else the reason it is blocked.

    Status and time limit are checked here; the rest depends on the scope's kind and lives in
    `policy.request_reason` (shared with the agent guard).
    """
    scope = get_scope()
    if scope is None or scope.status != "APPROVED":
        return "Scope not approved"
    if time_limit_reached():
        return "Time limit reached"
    return request_reason(scope, method, target)


def policy_reason(method: str, target: str) -> str:
    """"" when the policy would let the request run, else why not. Records nothing: for
    checking an operator's edit before it becomes a request (`approvals.edit_approval`)."""
    return _decide(method.strip().upper(), target)


def check_request(method: str, target: str) -> PolicyVerdict:
    """Decide whether a proposed request may run, and record the verdict.

    `target` is a path ("/admin") or a full URL; both are normalized before the
    excluded paths are compared, so case, encoding, `..` and `;params` can't slip past.
    """
    method = method.strip().upper()
    return record_verdict(method, target, _decide(method, target))


def record_verdict(method: str, target: str, reason: str) -> PolicyVerdict:
    """Record a verdict on the current assessment ("" reason = allowed) and audit a block."""
    verdict = PolicyVerdict(method, target, not reason, reason or "Within approved scope")
    lists.current().verdicts.append(verdict)
    if reason:
        log_event("policy.blocked", f"{method} {target} · {reason}")
    return verdict


def list_verdicts() -> List[PolicyVerdict]:
    return list(lists.current().verdicts)


def blocked_count() -> int:
    return sum(1 for verdict in lists.current().verdicts if not verdict.allowed)
