"""The AI reads the operator's goal at the Scope step and suggests how to scope it.

Each template carries a `SCOPE_PROMPT` (what that assessment covers, which catalog tools
suit which goals, and its limits) and a `SUGGEST_TOOLS` list. When the operator opens with
a goal ("list all paths on this URL"), Reconix asks the Core API's model, guided by that
prompt, to read the goal and name the tools and paths that would help. The suggestions are
offered unticked in the scope tick list; only the operator's tick changes the scope
(the AI never sets a scope value). Nothing destructive is ever suggested.

Three steps keep the network call off the UI thread: `scope_suggest_request()` (UI thread)
builds the ask, `fetch_scope_suggest()` (a worker) calls the API, and
`apply_scope_suggest()` (UI thread) records the reading and the suggestions.
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

from ..models import Assessment, ScopeSuggest
from . import lists
from .activity import log_event
from .redact import redact
from .kali_catalog import suggestible
from .tools import known_tool
from .templates import MODULES
from .transcript import add_activity, add_chat

READING_MAX = 300
MAX_SUGGESTED_TOOLS = 6
MAX_PATHS = 6


@dataclass(frozen=True)
class SuggestRequest:
    assessment: Assessment
    prompt: str
    tools: Tuple[str, ...]  # the tools the AI may suggest (this template's catalog set)


def _goal(assessment: Assessment) -> str:
    """The operator's opening request (already masked), or "" when there is none."""
    return assessment.requests[0].text if assessment.requests else ""


def scope_suggest_request() -> Optional[SuggestRequest]:
    """Start the evaluation (UI thread). None when there is no goal to read, the scope is not
    a fresh draft, or it was already evaluated/is being evaluated."""
    assessment = lists.current()
    scope = assessment.scope
    if scope is None or scope.status != "DRAFT":
        return None
    if assessment.scope_suggest is not None or assessment.scope_suggesting:
        return None
    goal = _goal(assessment)
    module = MODULES.get(assessment.selected_template or "")
    prompt_text = getattr(module, "SCOPE_PROMPT", "")
    categories = list(getattr(module, "SUGGEST_CATEGORIES", ()))
    tools = tuple(t.name for t in suggestible(categories))
    if not goal or not prompt_text or not tools:
        return None
    assessment.scope_suggesting = True
    prompt = (
        f"{prompt_text}\n\n"
        f"Target: {assessment.target}\n"
        f"The operator's goal: {redact(goal)}\n"
        f"Tools you may suggest, by these exact names: {', '.join(tools)}.\n"
        "Reply in two or three short sentences: what the goal needs, and which of those "
        "tools help (name them). If specific paths matter, add a line 'PATHS: /a, /b'. "
        "Suggest nothing destructive and nothing outside the list."
    )
    return SuggestRequest(assessment, prompt, tools)


def fetch_scope_suggest(request: SuggestRequest) -> str:
    """The model's reply (a worker; blocks on the network). Raises CoreApiError."""
    from ..core_api import sync

    return sync.ask_model(request.prompt)


def _tools_in(reply: str, tools: Tuple[str, ...]) -> List[str]:
    """The suggested tools the reply names, in the list's order (never more than the cap)."""
    low = reply.casefold()
    found: List[str] = []
    for tool in tools:
        key = tool.casefold()
        word = key.split()[-1] if " " in key else key  # "owasp zap" -> "zap"
        if re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", low):
            found.append(tool)
    return found[:MAX_SUGGESTED_TOOLS]


def _paths_in(reply: str) -> List[str]:
    """Paths on a 'PATHS:' line, if the reply gave one."""
    match = re.search(r"PATHS:\s*(.+)", reply)
    if not match:
        return []
    parts = re.split(r"[,\s]+", match.group(1).strip())
    paths = [p for p in parts if p.startswith("/")]
    return paths[:MAX_PATHS]


def apply_scope_suggest(request: SuggestRequest, reply: str) -> bool:
    """Record the AI's reading and suggestions (UI thread). False when nothing is suggested."""
    assessment = request.assessment
    assessment.scope_suggesting = False
    scope = assessment.scope
    if assessment is not lists.current() or scope is None or scope.status != "DRAFT":
        return False
    matched = [known_tool(t) or t for t in _tools_in(reply, request.tools)]
    have = {s.casefold() for s in scope.tools}
    tools = [t for t in dict.fromkeys(matched) if t.casefold() not in have]
    paths = _paths_in(reply)
    reading = redact(" ".join(reply.split()))[:READING_MAX]
    assessment.scope_suggest = ScopeSuggest(reading, tools, paths)
    add_chat("text", "reconix", reading or "I read your goal.", tone="default")
    if tools:
        add_chat(
            "text", "reconix", "Suggested tools (tick to add): " + ", ".join(tools), tone="muted"
        )
    log_event("scope.suggested", ", ".join(tools) or "none")
    return bool(tools or paths)


def scope_suggest_failed(request: SuggestRequest, reason: str) -> None:
    """The model call failed (UI thread): the template scope stands, with a quiet note."""
    request.assessment.scope_suggesting = False
    if request.assessment is lists.current():
        add_activity(
            "AI", f"Couldn't read the goal for scope suggestions ({reason}).", tone="muted"
        )


def scope_reading() -> str:
    """The AI's one-line reading of the operator's goal ("" when none was evaluated)."""
    suggest = lists.current().scope_suggest
    return suggest.reading if suggest else ""


def suggested_tools() -> List[str]:
    """The AI's suggested tools for the current assessment ([] when there are none)."""
    suggest = lists.current().scope_suggest
    return list(suggest.tools) if suggest else []


def scope_suggesting() -> bool:
    return lists.current().scope_suggesting
