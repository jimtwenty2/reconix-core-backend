"""Reads the model's JSON answers.

A malformed step is dropped, never repaired. In particular an arguments value
that is one string is never split into a list, because that would build a
command from a string.
"""

import json
import re
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
MAX_REASON_CHARS = 300
PHASES = {"discovery", "scan", "validation"}  # scope_manifests.allowed_actions values
MAX_ARGUMENTS = 20
MAX_ANSWER_CHARS = 4000
MAX_CHAT_REFERENCES = 10
NO_TOOL = {"", "NONE", "NULL"}


# A chat answer as it arrives: {"answer": "... (the rest may not have come yet)
ANSWER_START = re.compile(r'\{\s*"answer"\s*:\s*"')
JSON_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}


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
    step = {
        "title": title.strip()[:MAX_TITLE_CHARS],
        "phase": read_phase(raw.get("phase")),
        "reason": read_reason(raw.get("reason")),
    }
    tool = raw.get("tool")
    if tool is None or (isinstance(tool, str) and tool.strip().upper() in NO_TOOL):
        return {**step, "action": None}
    action = read_action(tool, raw.get("target"), raw.get("arguments", []))
    if action is None:
        return None
    return {**step, "action": action}


def read_phase(phase: Any) -> str | None:
    """Only a known phase is kept; anything else is no phase, never a guess."""
    if isinstance(phase, str) and phase.strip().lower() in PHASES:
        return phase.strip().lower()
    return None


def read_reason(reason: Any) -> str:
    if not isinstance(reason, str):
        return ""
    # One line without control characters: it is shown on the approval card.
    line = reason.strip().splitlines()[0] if reason.strip() else ""
    line = "".join(char for char in line if unicodedata.category(char) != "Cc")
    return line.strip()[:MAX_REASON_CHARS]


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


def read_chat(data: dict[str, Any]) -> tuple[str, list[str]]:
    """The chat answer and the ids it names. Only line breaks and tabs are kept of the
    control characters, because the answer is shown in the terminal app and the web."""
    answer = data.get("answer")
    if not isinstance(answer, str):
        raise BadAnswer("no answer")
    text = "".join(c for c in answer if c in "\n\t" or unicodedata.category(c) != "Cc")
    text = text.strip()[:MAX_ANSWER_CHARS]
    if not text:
        raise BadAnswer("no answer")
    named = data.get("references")
    references = []
    if isinstance(named, list):
        references = [item.strip() for item in named if isinstance(item, str) and item.strip()]
    return text, references[:MAX_CHAT_REFERENCES]


def answer_so_far(text: str) -> str:
    """The chat answer's text from a JSON object that is still arriving: the "answer"
    string up to its end or to the last character that is whole. Empty when the object
    does not start with "answer". Only for showing; read_chat reads the final answer."""
    start = ANSWER_START.search(text)
    if start is None:
        return ""
    parts, index = [], start.end()
    while index < len(text):
        char = text[index]
        if char == '"':
            break
        if char != "\\":
            parts.append(char)
            index += 1
            continue
        escape = text[index + 1 : index + 2]
        if escape == "u":
            code = text[index + 2 : index + 6]
            if len(code) < 4 or not all(c in "0123456789abcdefABCDEF" for c in code):
                break
            parts.append(chr(int(code, 16)))
            index += 6
        elif escape in JSON_ESCAPES:
            parts.append(JSON_ESCAPES[escape])
            index += 2
        else:
            break  # not arrived yet, or not JSON
    shown = "".join(c for c in "".join(parts) if c in "\n\t" or unicodedata.category(c) != "Cc")
    return shown.lstrip()[:MAX_ANSWER_CHARS]
