"""Reads the model's JSON answers.

A malformed step is dropped, never repaired. In particular an arguments value
that is one string is never split into a list, because that would build a
command from a string.
"""

import json
import unicodedata
from typing import Any

from reconix_ai.contracts import TOOL_NAMES

MAX_GOAL_CHARS = 500
MAX_QUERIES = 3
MAX_QUERY_CHARS = 200
MAX_REFLECTION_CHARS = 300
MAX_SUMMARY_CHARS = 2000
MAX_PLAN_STEPS = 5
MAX_TITLE_CHARS = 200
MAX_ARGUMENTS = 20
NO_TOOL = {"", "NONE", "NULL"}


class BadAnswer(Exception):
    """The model's answer is not the JSON shape the step asked for."""


def json_object(text: str) -> dict[str, Any]:
    # Some models wrap the object in ```json fences or a sentence; take the outer braces.
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise BadAnswer("no JSON object")
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        raise BadAnswer("not valid JSON") from None
    if not isinstance(value, dict):
        raise BadAnswer("not a JSON object")
    return value


def read_understanding(data: dict[str, Any]) -> tuple[str, list[str]]:
    """The goal and up to 3 knowledge searches."""
    goal = data.get("goal")
    if not isinstance(goal, str) or not goal.strip():
        raise BadAnswer("no goal")
    goal = goal.strip()[:MAX_GOAL_CHARS]
    searches = data.get("search")
    queries = []
    if isinstance(searches, list):
        queries = [q.strip()[:MAX_QUERY_CHARS] for q in searches if isinstance(q, str)]
        queries = [query for query in queries if query]
    return goal, queries[:MAX_QUERIES] or [goal[:MAX_QUERY_CHARS]]


def read_reflection(data: dict[str, Any]) -> tuple[str, str | None]:
    """One line on what is known now, and a knowledge search or None."""
    reflection = data.get("reflection")
    if not isinstance(reflection, str) or not reflection.strip():
        raise BadAnswer("no reflection")
    line = reflection.strip().splitlines()[0]
    # No control characters: the line is shown in the terminal app and the web terminal.
    line = "".join(char for char in line if unicodedata.category(char) != "Cc")
    line = line.strip()[:MAX_REFLECTION_CHARS]
    if not line:
        raise BadAnswer("no reflection")
    search = data.get("search")
    query = search.strip()[:MAX_QUERY_CHARS] if isinstance(search, str) else ""
    return line, query or None


def read_plan(data: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    """The summary and 1 to 5 plan steps, each with an action or None."""
    summary = data.get("summary")
    summary = summary.strip()[:MAX_SUMMARY_CHARS] if isinstance(summary, str) else ""
    raw_steps = data.get("steps")
    if not isinstance(raw_steps, list):
        raise BadAnswer("no steps")
    steps = []
    for raw in raw_steps:
        step = read_step(raw)
        if step is not None:
            steps.append({**step, "order": len(steps) + 1})
        if len(steps) == MAX_PLAN_STEPS:
            break
    if not steps:
        raise BadAnswer("no usable steps")
    return summary, steps


def read_step(raw: Any) -> dict[str, Any] | None:
    if not isinstance(raw, dict):
        return None
    title = raw.get("title")
    if not isinstance(title, str) or not title.strip():
        return None
    tool = raw.get("tool")
    if tool is None or (isinstance(tool, str) and tool.strip().upper() in NO_TOOL):
        return {"title": title.strip()[:MAX_TITLE_CHARS], "action": None}
    action = read_action(tool, raw.get("target"), raw.get("arguments", []))
    if action is None:
        return None
    return {"title": title.strip()[:MAX_TITLE_CHARS], "action": action}


def read_action(tool: Any, target: Any, arguments: Any) -> dict[str, Any] | None:
    if not isinstance(tool, str) or tool.strip().upper() not in TOOL_NAMES:
        return None
    if not isinstance(target, str) or not target.strip():
        return None
    if not isinstance(arguments, list) or len(arguments) > MAX_ARGUMENTS:
        return None
    if not all(isinstance(argument, str) for argument in arguments):
        return None
    return {
        "tool": tool.strip().upper(),
        "target": target.strip(),
        "arguments": list(arguments),
        "is_validation": False,
    }
