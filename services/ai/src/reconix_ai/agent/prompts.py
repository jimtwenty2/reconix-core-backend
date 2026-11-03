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
from reconix_ai.harness.catalog import description
from reconix_ai.harness.tool_rules import rule_for
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
    if state.get("reflections"):
        parts.append(reflections_text(state["reflections"]))
    return [system_message(), Message("user", "\n\n".join(parts))]


def reflect_messages(state: AgentState) -> list[Message]:
    parts = [
        read_markdown(PROMPTS_DIR / "reflect.md"),
        scope_text(state["scope"]),
        "## Goal\n" + fenced("goal", state.get("goal", "")),
        knowledge_text(state.get("knowledge", [])),
        tool_results_text(state["tool_results"]),
    ]
    if state.get("reflections"):
        parts.append(reflections_text(state["reflections"]))
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


def validate_messages(state: AgentState) -> list[Message]:
    """One finding plus the PoC tool output, for the verdict."""
    parts = [
        read_markdown(PROMPTS_DIR / "validate.md"),
        scope_text(state["scope"]),
        findings_text(state.get("findings", [])),
        tool_results_text(state.get("tool_results", [])),
    ]
    return [system_message(), Message("user", "\n\n".join(parts))]


def chat_messages(state: AgentState) -> list[Message]:
    parts = [
        read_markdown(PROMPTS_DIR / "chat.md"),
        chat_scope_text(state.get("scope"), state.get("scope_status", "NONE")),
        plan_text(state.get("plan_lines", [])),
    ]
    if state.get("findings"):
        parts.append(findings_text(state["findings"]))
    parts.append(knowledge_text(state.get("knowledge", [])))
    parts.append(chat_text(state.get("messages", [])))
    return [system_message(), Message("user", "\n\n".join(parts))]


def chat_scope_text(scope: dict[str, Any] | None, status: str) -> str:
    if scope is None:
        return "## Scope\nNo scope has been written yet."
    title = "Approved scope"
    if status != "APPROVED":
        title = "Draft scope (not approved yet: nothing may run on it)"
    tools = ", ".join(scope["allowed_tools"]) or "none"
    text = f"{scope_text(scope, title)}\n- Allowed tools: {tools}"
    if status != "APPROVED":
        # A draft is half written and nobody has checked it yet.
        heading, _, body = text.partition("\n")
        text = f"{heading}\n" + fenced("scope_draft", body)
    return text


def plan_text(lines: list[str]) -> str:
    if not lines:
        return "## Plan\n(no plan yet)"
    # The agent wrote the plan earlier, from data an attacker may have written.
    return "## Plan\n" + fenced("plan", "\n".join(lines))


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


def scope_text(scope: dict[str, Any], title: str = "Approved scope") -> str:
    lines = [f"## {title}"]
    for name, label in (
        ("ip_ranges", "IP ranges"),
        ("domains", "Domains"),
        ("url_prefixes", "URL prefixes"),
        ("repo_paths", "Repo paths"),
        ("excluded_targets", "Never touch"),
    ):
        lines.append(f"- {label}: {', '.join(scope[name]) or 'none'}")
    ports = scope.get("allowed_ports") or []
    lines.append(f"- Allowed ports: {', '.join(map(str, ports)) or 'any'}")
    lines.append(f"- Highest risk allowed: {scope['max_risk']}")
    return "\n".join(lines)


def tools_text(allowed_tools: list[str]) -> str:
    lines = ["## Allowed tools"]
    for tool in allowed_tools:
        tool_rule = rule_for(tool)
        if tool_rule is None:
            continue
        kinds = "/".join(sorted(tool_rule.kinds))
        options = " ".join(
            sorted(tool_rule.flags) + [f"{o} <value>" for o in sorted(tool_rule.valued)]
        )
        summary = description(tool).split(". ")[0].strip()
        lines.append(f"- {tool} (target: {kinds}; options: {options or 'none'}): {summary}")
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


def reflections_text(reflections: list[str]) -> str:
    # The model wrote these from tool output, so they are fenced as data too.
    lines = "\n".join(f"- {line}" for line in reflections)
    return "## Notes on the tool results (untrusted)\n" + fenced("reflections", lines)


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
