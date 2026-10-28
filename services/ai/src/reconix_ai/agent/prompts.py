"""Builds the messages for each model step from the Markdown prompt files.

Prompts and rules live in prompts/ and policies/ as plain Markdown, so they are
changed by PR and never hidden in code. Knowledge hits and tool output are put
inside tags and marked as data, because an attacker may have written them.
"""

import unicodedata
from pathlib import Path
from typing import Any

from reconix_ai.agent.state import AgentState
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
