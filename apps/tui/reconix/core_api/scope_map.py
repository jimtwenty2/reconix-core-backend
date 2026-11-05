"""The app's scope manifest in the Core API's shape (a ScopeDraft), and back for plans.

Only what the API knows is sent. The API takes 5 tools (NMAP, NUCLEI, ZAP, SEMGREP,
GITLEAKS); a scope tool it doesn't know (testssl.sh) stays the app's own and is left out.
A source-code scope has no API target type yet, so it can't be sent at all.
"""

import ipaddress
from typing import Dict, List, Optional

from ..models import ScopeManifest
from .client import CoreApiError

# The app's tool names (any case) -> the API's ToolName.
API_TOOLS = {
    "nmap": "NMAP",
    "nuclei": "NUCLEI",
    "zap": "ZAP",
    "owasp zap": "ZAP",
    "semgrep": "SEMGREP",
    "gitleaks": "GITLEAKS",
}
API_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
# The app's plan phases <- the API plan step's phase.
PHASE_KEYS = {"discovery": "discovery", "scan": "scanning", "validation": "validation"}
# The app's approval gates decide MEDIUM and HIGH steps itself; the API's own check stops
# anything above MEDIUM.
MAX_RISK = "MEDIUM"


def api_tools(scope: ScopeManifest) -> Dict[str, str]:
    """The scope's tools the API knows: API name -> the app's own name."""
    tools: Dict[str, str] = {}
    for name in scope.tools:
        api_name = API_TOOLS.get(name.strip().casefold())
        if api_name and api_name not in tools:
            tools[api_name] = name
    return tools


def scope_draft(scope: ScopeManifest) -> dict:
    """The API's ScopeDraft for `scope`. Raises CoreApiError when it can't be sent."""
    if scope.kind == "source":
        raise CoreApiError(
            "SCOPE_NOT_SUPPORTED", "a source-code scope can't be sent to the Core API yet"
        )
    tools = list(api_tools(scope))
    if not tools:
        raise CoreApiError(
            "NO_API_TOOLS",
            "none of the scope's tools is one the Core API "
            "runs (nmap, nuclei, zap, semgrep, gitleaks)",
        )
    draft = {
        "max_risk": MAX_RISK,
        "allowed_tools": tools,
        "allowed_actions": _actions(scope.allowed_actions),
        "allowed_methods": [m.upper() for m in scope.allowed_methods if m.upper() in API_METHODS],
        "limitations": f"Time limit {scope.time_limit_minutes} min (kept by reconix-ai).",
        "targets": _targets(scope),
    }
    if scope.kind == "network":
        draft["allowed_ports"] = sorted(set(scope.allowed_ports))
    return draft


def _actions(actions: List[str]) -> List[str]:
    """The API's three action words found in the app's own wording."""
    found = []
    for word, key in (("discover", "discovery"), ("scan", "scan"), ("valid", "validation")):
        if any(word in action.casefold() for action in actions) and key not in found:
            found.append(key)
    return found


def _targets(scope: ScopeManifest) -> List[dict]:
    if scope.kind == "network":
        targets = [_network_target(scope.target_url)]
        for entry in scope.excluded_paths:
            host = entry.rsplit(":", 1)[0] if entry.count(":") == 1 else entry
            excluded = _network_target(host, required=False)
            if excluded is not None:
                targets.append({**excluded, "excluded": True})
        return targets
    base = scope.target_url.rstrip("/")
    targets = [{"type": "url", "value": base + "/"}]
    for path in scope.excluded_paths:
        if path.startswith("/"):
            targets.append({"type": "url", "value": base + path, "excluded": True})
    return targets


def _network_target(value: str, required: bool = True) -> Optional[dict]:
    value = value.strip()
    try:
        if "/" in value:
            return {"type": "cidr", "value": str(ipaddress.ip_network(value, strict=False))}
        return {"type": "ip", "value": str(ipaddress.ip_address(value))}
    except ValueError:
        pass
    if value and all(part.isalnum() or "-" in part for part in value.split(".")):
        return {"type": "domain", "value": value.lower()}
    if required:
        raise CoreApiError("BAD_TARGET", "the scope's target can't be sent to the Core API")
    return None


def plan_phases(steps: List[dict], scope: ScopeManifest) -> dict:
    """The API's plan steps as the app's `{"phases": [...]}` draft, one phase per key (the
    first step of each phase), tools named as the scope names them."""
    names = api_tools(scope)
    phases: Dict[str, dict] = {}
    for step in steps:
        key = PHASE_KEYS.get(step.get("phase") or "", "discovery")
        if key in phases:
            continue
        action = step.get("action") or {}
        tool = names.get(action.get("tool", ""))
        phases[key] = {
            "key": key,
            "label": step.get("title", ""),
            "detail": step.get("reason", ""),
            "tools": [tool] if tool else [],
        }
    return {"phases": list(phases.values())}
