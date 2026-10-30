"""Builds the messages for each model step from the Markdown prompt files.

Prompts and rules live in prompts/ and policies/ as plain Markdown, so they are
changed by PR and never hidden in code. Knowledge hits and tool output are put
inside tags and marked as data, because an attacker may have written them.
"""

import json
import unicodedata
from pathlib import Path
from typing import Any

from reconix_ai.agent.state import AgentState
from reconix_ai.contracts import severity_rank
from reconix_ai.harness.checks.command import ALLOWED_OPTIONS
from reconix_ai.harness.checks.scope import TOOL_TARGET_KINDS
from reconix_ai.providers import Message

PACKAGE_DIR = Path(__file__).resolve().parents[1]
PROMPTS_DIR = PACKAGE_DIR / "prompts"
POLICIES_DIR = PACKAGE_DIR / "policies"


def read_markdown(path: Path) -> str:
    return path.read_text(encoding="utf-8").strip()


def system_message() -> Message:
    rules = read_markdown(POLICIES_DIR / "agent-rules.md")
    return Message("system", f"{read_markdown(PROMPTS_DIR / 'system.md')}\n\n{rules}")


def understand_messages(state: AgentState) -> list[Message]:
    parts = [
        read_markdown(PROMPTS_DIR / "understand.md"),
        scope_text(state["scope"]),
        chat_text(state.get("messages", [])),
    ]
    return [system_message(), Message("user", "\n\n".join(parts))]


def plan_messages(state: AgentState) -> list[Message]:
    parts = [
        read_markdown(PROMPTS_DIR / "plan.md"),
        scope_text(state["scope"]),
        tools_text(state["scope"]["allowed_tools"]),
        "## Goal\n" + fenced("goal", state.get("goal", "")),
        knowledge_text(state.get("knowledge", [])),
    ]
    if state.get("tool_results"):
        parts.append(tool_results_text(state["tool_results"]))
    return [system_message(), Message("user", "\n\n".join(parts))]


def analyze_messages(state: AgentState) -> list[Message]:
    parts = [
        read_markdown(PROMPTS_DIR / "analyze.md"),
        scope_text(state["scope"]),
        tools_text(state["scope"]["allowed_tools"]),
        findings_text(state.get("findings", [])),
        knowledge_text(state.get("knowledge", [])),
    ]
    if state.get("tool_results"):
        parts.append(tool_results_text(state["tool_results"]))
    return [system_message(), Message("user", "\n\n".join(parts))]


MAX_REPORT_PROMPT_ROWS = 50


def report_messages(state: AgentState) -> list[Message]:
    report = state["report"]
    findings = sorted(report["findings"], key=severity_rank)
    rows = [report_row(finding) for finding in findings[:MAX_REPORT_PROMPT_ROWS]]
    runs = report["tool_runs"][:MAX_REPORT_PROMPT_ROWS]
    parts = [
        read_markdown(PROMPTS_DIR / "report.md"),
        scope_text(state["scope"]),
        counts_text(report["severity_counts"]),
        findings_text(rows) + more_text(len(findings) - len(rows), "findings"),
        "## Tool runs\n"
        + fenced("tool_results", json.dumps(runs, indent=1))
        + more_text(len(report["tool_runs"]) - len(runs), "tool runs"),
    ]
    return [system_message(), Message("user", "\n\n".join(parts))]


def more_text(left_out: int, what: str) -> str:
    return f"\n({left_out} more {what} are in the report but not shown here.)" if left_out else ""


def counts_text(counts: dict[str, int]) -> str:
    lines = [f"- {level}: {count}" for level, count in counts.items()]
    return "## Findings by severity (final)\n" + ("\n".join(lines) or "- none")


def report_row(finding: dict[str, Any]) -> dict[str, Any]:
    """What the report text needs of a finding; the full text stays in the files."""
    names = ("code", "title", "target", "severity_status", "finding_status")
    return {name: finding.get(name) for name in names}


def findings_text(findings: list[dict[str, Any]]) -> str:
    return "## Findings\n" + fenced("findings", json.dumps(findings, indent=1))


def scope_text(scope: dict[str, Any]) -> str:
    lines = ["## Approved scope"]
    for name, label in (
        ("ip_ranges", "IP ranges"),
        ("domains", "Domains"),
        ("url_prefixes", "URL prefixes"),
        ("repo_paths", "Repo paths"),
        ("excluded_targets", "Never touch"),
    ):
        lines.append(f"- {label}: {', '.join(scope[name]) or 'none'}")
    lines.append(f"- Highest risk allowed: {scope['max_risk']}")
    return "\n".join(lines)


def tools_text(allowed_tools: list[str]) -> str:
    lines = ["## Allowed tools and options"]
    for tool in allowed_tools:
        options = ALLOWED_OPTIONS.get(tool)
        if options is None:
            continue
        kinds = ", ".join(sorted(kind.lower() for kind in TOOL_TARGET_KINDS[tool]))
        written = [
            option if value is None else f"{option} <value>" for option, value in options.items()
        ]
        lines.append(f"- {tool} (target: {kinds}): {', '.join(written) or 'no options'}")
    if len(lines) == 1:
        lines.append("- none")
    return "\n".join(lines)


def chat_text(messages: list[str]) -> str:
    if not messages:
        return "## Chat\n(empty)"
    return "## Chat\n" + fenced("chat", "\n".join(f"- {message}" for message in messages))


def knowledge_text(hits: list[dict[str, str]]) -> str:
    if not hits:
        return "## Knowledge\n(none found)"
    pieces = [f"[{hit['ref_id']}] {hit['title']}\n{hit['text']}" for hit in hits]
    return "## Knowledge\n" + fenced("reference_data", "\n\n".join(pieces))


def tool_results_text(results: list[str]) -> str:
    return "## Earlier tool results\n" + fenced("tool_results", "\n\n".join(results))


def fenced(tag: str, text: str) -> str:
    """Wrap data in a tag it cannot close or reopen itself.

    Look-alike characters (a full-width "<") are folded first and invisible
    format characters dropped, then every < and > is escaped, so no tag in the
    data survives, however it is nested or spelled.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(char for char in text if unicodedata.category(char) != "Cf")
    text = text.replace("<", "&lt;").replace(">", "&gt;")
    return f"<{tag}>\n{text}\n</{tag}>"
