"""A line in the step chat that asks to change the scope ("add port 3389").

Only the operator changes the scope. No model is asked: a plain keyword check spots the
request, and the step chat opens a tick list of the scope's ports and tools for the
operator to tick. The list starts with exactly what the scope allows today (nothing new is
ticked for you); ports the operator typed are added unticked. Saving goes through
`edit_scope`, which validates every value.
"""

import re
from typing import List, NamedTuple, Optional, Tuple

from . import lists
from .errors import StoreValidationError
from .scope import scope_editable
from .templates import MODULES
from .transcript import add_chat

_CHANGE = re.compile(
    r"\b(?:add|remove|drop|allow|open|include|exclude|delete|change|edit|"
    r"extend|disallow|close)\b",
    re.IGNORECASE,
)
_SUBJECT = re.compile(r"\b(?:ports?|tools?|scope)\b", re.IGNORECASE)
_NUMBER = re.compile(r"\b\d{1,5}\b")

ONLY_YOU = "Only you can change the scope. Tick what it allows, then press Enter to save."
LOCKED = (
    "The scope is approved and locked, so it can't change now. Start a new "
    "assessment (/new) to test with a different scope."
)


class ScopeChoices(NamedTuple):
    """The tick list's rows: (value, ticked). `ports` is empty for a scope without ports."""

    ports: List[Tuple[int, bool]]
    tools: List[Tuple[str, bool]]


def wants_scope_change(text: str) -> bool:
    """A line that asks to add or remove ports, tools or the scope itself."""
    return bool(_CHANGE.search(text) and _SUBJECT.search(text))


def typed_ports(text: str) -> List[int]:
    """The port numbers in the line (1-65535), in order, each once."""
    ports: List[int] = []
    for match in _NUMBER.findall(text):
        port = int(match)
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)
    return ports


def scope_choices(text: str) -> ScopeChoices:
    """The rows to tick for this scope; raises once the scope is approved."""
    if not scope_editable():
        raise StoreValidationError(LOCKED)
    assessment = lists.current()
    scope = assessment.scope
    module = MODULES.get(assessment.selected_template or "")
    ports: List[Tuple[int, bool]] = []
    if scope.kind == "network":
        known = list(getattr(module, "ALLOWED_PORTS", [])) + list(scope.allowed_ports)
        candidates = sorted(set(known + typed_ports(text)))
        ports = [(port, port in scope.allowed_ports) for port in candidates]
    allowed = {tool.casefold() for tool in scope.tools}
    names = list(scope.tools) + [
        tool for tool in getattr(module, "TOOLS", []) if tool.casefold() not in allowed
    ]
    tools = [(tool, tool.casefold() in allowed) for tool in names]
    return ScopeChoices(ports, tools)


def scope_tick_choices(text: str) -> Optional[ScopeChoices]:
    """The tick rows while the scope can still change, else None (no chat line added)."""
    return scope_choices(text) if scope_editable() else None


def answer_scope_change(text: str) -> Optional[ScopeChoices]:
    """Reply to a line asking to change the scope: the rows to tick, or None once locked.

    Record the operator's line first (`say_operator_line`); this adds Reconix's reply.
    """
    try:
        choices = scope_choices(text)
    except StoreValidationError:
        add_chat("text", "reconix", LOCKED, tone="muted")
        return None
    add_chat("text", "reconix", ONLY_YOU)
    return choices
