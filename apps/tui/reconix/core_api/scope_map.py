"""The app's scope manifest in the Core API's shape (a ScopeDraft), and back for plans.

Only what the API knows is sent. A scope tool is named as the Kali catalog names it
(testssl.sh -> TESTSSL, OWASP ZAP -> ZAP, Postman -> NEWMAN); the API refuses a tool that
isn't in the catalog, and that refusal is shown as it came. A source-code scope needs its
code uploaded to the API first (the code-scan flow), so it can't be sent from here yet.
"""

import ipaddress
from typing import Dict, List, Optional

from ..models import ScopeManifest
from .client import CoreApiError

# The app's tool names whose Kali catalog name differs (any other: upper case, "_" for
# spaces and dashes, e.g. "nmap" -> "NMAP", "osv-scanner" -> "OSV_SCANNER").
API_TOOLS = {
    "owasp zap": "ZAP",
    "zap api scan": "ZAP",
    "testssl.sh": "TESTSSL",
    "postman": "NEWMAN",
    "httpx": "HTTPX_PROBE",
}
API_METHODS = {"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}
# The app's plan phases <- the API plan step's phase.
PHASE_KEYS = {"discovery": "discovery", "scan": "scanning", "validation": "validation"}
# The highest risk a step may have. MEDIUM and HIGH steps always wait for your approval
# (HIGH with the target typed in), so the AI can propose them but never run them alone.
MAX_RISK = "HIGH"


def api_tools(scope: ScopeManifest) -> Dict[str, str]:
    """The scope's tools the API knows: API name -> the app's own name."""
    tools: Dict[str, str] = {}
    for name in scope.tools:
        api_name = api_tool(name)
        if api_name and api_name not in tools:
            tools[api_name] = name
    return tools


def api_tool(name: str) -> str:
    """The Kali catalog name for one of the app's tool names ("" for an empty one)."""
    key = name.strip().casefold()
    if key in API_TOOLS:
        return API_TOOLS[key]
    return "".join(c if c.isalnum() else "_" for c in key).upper()


def scope_draft(scope: ScopeManifest) -> dict:
    """The API's ScopeDraft for `scope`. Raises CoreApiError when it can't be sent."""
    if scope.kind == "source":
        raise CoreApiError(
            "SCOPE_NOT_SUPPORTED", "a source-code scope can't be sent to the Core API yet"
        )
    tools = list(api_tools(scope))
    if not tools:
        raise CoreApiError(
            "NO_API_TOOLS", "the scope names no tool",
        )
    draft = {
        "max_risk": MAX_RISK,
        "allowed_tools": tools,
        "allowed_actions": _actions(scope.allowed_actions),
        "allowed_methods": [m.upper() for m in scope.allowed_methods if m.upper() in API_METHODS],
        "limitations": f"Time limit {scope.time_limit_minutes} min (kept by the Reconix app).",
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
