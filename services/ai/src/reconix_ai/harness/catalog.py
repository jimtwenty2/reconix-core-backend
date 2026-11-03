"""The Kali tool catalog, loaded from tool_specs.json + risk_ops.json.

`tool_specs.json` is the committed mirror of the Reconix-Kali-MCP catalog (copied
from that repo, never hand-edited). `risk_ops.json` is the per-call risk-escalation
policy copied from the same repo. Together they let the command and risk checks
gate every tool the container offers, instead of a hand-written five-tool table:

- a tool is known if it is in `tool_specs.json`;
- its baseline risk is the tool's `risk` field;
- a destructive tool, or a free-shell tool, is pushed to at least HIGH;
- `risk_ops.json` raises a single call above its baseline by substring-matching
  the (lowercased, space-joined) argument values against the tool's patterns.

Both files load lazily and are cached; a missing or malformed file raises on first
use rather than at import time.
"""

import json
from functools import lru_cache
from pathlib import Path

from reconix_ai.harness.checks.result import RiskLevel

_SPECS_DIR = Path(__file__).parent.parent / "tool_specs"
_TOOL_SPECS = _SPECS_DIR / "tool_specs.json"
_RISK_OPS = _SPECS_DIR / "risk_ops.json"

# Tools whose input is a real shell command (pipes, chaining, substitution): the
# command check cannot flag-vet them, so they are exempt from the shell-character
# block and the risk check pins them to HIGH (a person approves and types the
# target every time).
FREE_SHELL = frozenset({"run_command", "proxychains", "msfconsole", "smbclient"})

# Core's historical tool names that differ from the catalog's. "ZAP" is one full
# scan (spider + active scan) that the container exposes as the tool `zap_scan`.
ALIASES = {"zap": "zap_scan"}

_RISK = {"low": RiskLevel.LOW, "medium": RiskLevel.MEDIUM, "high": RiskLevel.HIGH}


def canonical(tool: str) -> str:
    """The catalog's name for a tool, applying Core's aliases (ZAP -> zap_scan)."""
    name = tool.lower()
    return ALIASES.get(name, name)


@lru_cache(maxsize=1)
def _tools() -> dict[str, dict]:
    data = json.loads(_TOOL_SPECS.read_text(encoding="utf-8"))
    rows = data.get("tools", data)
    rows = rows.values() if isinstance(rows, dict) else rows
    return {t["name"].lower(): t for t in rows if isinstance(t, dict) and t.get("name")}


@lru_cache(maxsize=1)
def _escalations() -> dict[str, dict[str, list[str]]]:
    data = json.loads(_RISK_OPS.read_text(encoding="utf-8"))
    out: dict[str, dict[str, list[str]]] = {}
    for name, tiers in data.get("per_tool", {}).items():
        if name.startswith("_") or not isinstance(tiers, dict):
            continue
        out[name.lower()] = {
            tier: [str(p).lower() for p in patterns]
            for tier, patterns in tiers.items()
            if tier in _RISK and isinstance(patterns, list)
        }
    return out


def is_known_tool(tool: str) -> bool:
    return canonical(tool) in _tools()


def is_free_shell(tool: str) -> bool:
    return canonical(tool) in FREE_SHELL


def is_destructive(tool: str) -> bool:
    return bool(_tools().get(canonical(tool), {}).get("destructive"))


def baseline_risk(tool: str) -> RiskLevel:
    """The tool's `risk` field, or HIGH for a tool the catalog does not know."""
    row = _tools().get(canonical(tool))
    if row is None:
        return RiskLevel.HIGH
    return _RISK.get(str(row.get("risk", "")).lower(), RiskLevel.HIGH)


def escalations(tool: str) -> dict[RiskLevel, list[str]]:
    """{risk level: lowercased patterns that raise a call to that level}."""
    return {_RISK[tier]: pats for tier, pats in _escalations().get(canonical(tool), {}).items()}


def input_schema(tool: str) -> dict:
    return _tools().get(canonical(tool), {}).get("inputSchema") or {}


def description(tool: str) -> str:
    return str(_tools().get(canonical(tool), {}).get("description", ""))


def param_names(tool: str) -> list[str]:
    """The tool's input param names, minus `timeout` (always supplied by Core)."""
    props = input_schema(tool).get("properties") or {}
    return [name for name in props if name != "timeout"]


def tool_names() -> set[str]:
    return set(_tools())
