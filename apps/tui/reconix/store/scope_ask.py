"""A line in the step chat that asks to change the scope ("add port 3389").

Only the operator changes the scope. No model is asked: a plain keyword check spots the
request, and the step chat opens a tick list of the scope's ports and tools for the
operator to tick. The list starts with exactly what the scope allows today (nothing new is
ticked for you); ports the operator typed, and ports the model's reply suggests, are added
unticked. Saving goes through `edit_scope`, which validates every value.

A number is a port only where it reads like one: "port 4000", "21 (FTP)", "3306/tcp", a
list of numbers in a sentence about ports ("add 4000, 3000 and 5432"), or a bare number in
the operator's own line. A count ("12 ports") or a part of an address or
range (1.1.1.0/24) is never a port. On a scope with ports (network), "add 3389, 8080" asks
for a change even without the word "port".
"""

import re
from typing import List, NamedTuple, Optional, Sequence, Tuple

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
# A change verb right before a bare number list ("add 3389, 0, 99999, 8080"): ports, on a scope
# that has ports. Not "change": "change step 2" is about the plan. Not a count of something.
_BARE_PORTS = re.compile(
    r"\b(?:add|remove|drop|allow|open|include|exclude|delete|disallow|close)\s+(?:also\s+)?"
    r"\d{1,5}(?:(?:\s*,\s*(?:and\s+|or\s+)?|\s+and\s+|\s+or\s+)\d{1,5})*(?![\w.:/-])"
    r"(?!\s*(?:steps?|hosts?|minutes?|mins?|seconds?|requests?|rows?|phases?|%))",
    re.IGNORECASE,
)
# A bare number that isn't part of an address, range, version or time (1.1.1.0/24, 1.2).
_NUMBER = re.compile(r"(?<![\w.:/-])\d{1,5}(?![\w:/-]|\.\d)")
_COUNT = re.compile(r"\b(\d{1,5})\s+(?:more\s+|common\s+|open\s+)?ports?\b", re.IGNORECASE)
# Where a reply names a port: "port 4000", "ports 21, 23 and 25", "21 (FTP)", "3306/tcp".
_PORT_LIST = re.compile(r"\bports?\s+((?:\d{1,5}(?:\s*\([^)]{0,30}\))?(?:\s*,\s*|\s+and\s+|"
                        r"\s+or\s+|\s*/\s*|\s+)?)+)", re.IGNORECASE)
_SERVICE = re.compile(r"(?<![\w.:/-])(\d{1,5})\s*\((?=[A-Za-z])[^)]{1,30}\)")
# A list of numbers ("4000, 3000, 5432 and 3306") in a sentence about ports.
_NUM_LIST = re.compile(r"(?<![\w.:/-])\d{1,5}(?:(?:\s*,\s*(?:and\s+|or\s+)?|\s+and\s+|\s+or\s+)"
                       r"\d{1,5}(?![\w:/-]|\.\d))+")
_NOT_PORTS = re.compile(r"(?:\b(?:steps?|phases?|rows?)\s+$)|(?:^\s*(?:hosts?|steps?|minutes?|"
                        r"min|seconds?|requests?|%))", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<=[!?;])\s+|(?<=\.)\s+|\n+")
_PROTO = re.compile(r"(?<![\w.:/-])(\d{1,5})/(?:tcp|udp)\b", re.IGNORECASE)
MAX_SUGGESTED = 20

ONLY_YOU = "Only you can change the scope. Tick what it allows, then press Enter to save."
LOCKED = (
    "The scope is approved and locked, so it can't change now. Start a new "
    "assessment (/new) to test with a different scope."
)


class ScopeChoices(NamedTuple):
    """The tick list's rows: (value, ticked). `ports` is empty for a scope without ports.
    `suggested`: ports added because the model's reply named them (shown as such)."""

    ports: List[Tuple[int, bool]]
    tools: List[Tuple[str, bool]]
    suggested: Tuple[int, ...] = ()


def wants_scope_change(text: str) -> bool:
    """A line that asks to add or remove ports, tools or the scope itself; on a scope with
    ports also a change verb before bare numbers ("add 3389, 8080")."""
    if _CHANGE.search(text) and _SUBJECT.search(text):
        return True
    scope = lists.current().scope
    return bool(scope is not None and scope.kind == "network" and _BARE_PORTS.search(text))


def _add(ports: List[int], values: Sequence[str]) -> None:
    for value in values:
        port = int(value)
        if 1 <= port <= 65535 and port not in ports:
            ports.append(port)


def _counts(text: str) -> set:
    """Where "12 ports" says how many: those spans are never ports."""
    return {m.start(1) for m in _COUNT.finditer(text)}


def named_ports(text: str) -> List[int]:
    """Ports `text` names as ports ("port 4000", "21 (FTP)", "3306/tcp"), in order."""
    counts = _counts(text)
    found: List[Tuple[int, str]] = []
    for match in _PORT_LIST.finditer(text):
        start = match.start(1)
        for number in _NUMBER.finditer(match.group(1)):
            found.append((start + number.start(), number.group()))
    for pattern in (_SERVICE, _PROTO):
        found += [(m.start(1), m.group(1)) for m in pattern.finditer(text)]
    found += _listed_ports(text)
    ports: List[int] = []
    _add(ports, [value for at, value in sorted(found) if at not in counts])
    return ports


def _listed_ports(text: str) -> List[Tuple[int, str]]:
    """Numbers listed ("4000, 3000 and 5432") in a sentence about ports, or right after one;
    a list of steps, hosts or minutes is left out."""
    found: List[Tuple[int, str]] = []
    start, about_ports = 0, False
    for end in [m.start() for m in _SENTENCE_END.finditer(text)] + [len(text)]:
        sentence = text[start:end]
        mentions = "port" in sentence.casefold()
        if mentions or about_ports:
            for listed in _NUM_LIST.finditer(sentence):
                before = sentence[:listed.start()][-12:]
                after = sentence[listed.end():][:10]
                if _NOT_PORTS.search(before) or _NOT_PORTS.search(after):
                    continue
                at = start + listed.start()
                found += [(at + n.start(), n.group()) for n in _NUMBER.finditer(listed.group())]
        about_ports = mentions
        start = end
    return found


def typed_ports(text: str) -> List[int]:
    """The ports in the operator's own line: named ones, and bare numbers that aren't a
    count or a part of an address (1-65535), in order, each once."""
    counts = _counts(text)
    ports = named_ports(text)
    _add(ports, [m.group() for m in _NUMBER.finditer(text) if m.start() not in counts])
    return ports


def suggested_ports(reply: str) -> List[int]:
    """Ports the model's reply names (at most MAX_SUGGESTED): rows to tick, never ticked."""
    return named_ports(reply)[:MAX_SUGGESTED]


def scope_choices(text: str, reply: str = "") -> ScopeChoices:
    """The rows to tick for this scope; raises once the scope is approved. `reply`: the
    model's answer, whose ports are added unticked as suggestions."""
    if not scope_editable():
        raise StoreValidationError(LOCKED)
    assessment = lists.current()
    scope = assessment.scope
    module = MODULES.get(assessment.selected_template or "")
    ports: List[Tuple[int, bool]] = []
    suggested: Tuple[int, ...] = ()
    if scope.kind == "network":
        known = list(getattr(module, "ALLOWED_PORTS", [])) + list(scope.allowed_ports)
        typed = typed_ports(text)
        suggested = [p for p in suggested_ports(reply) if p not in known and p not in typed]
        candidates = sorted(set(known + typed + suggested))
        ports = [(port, port in scope.allowed_ports) for port in candidates]
    allowed = {tool.casefold() for tool in scope.tools}
    names = list(scope.tools) + [
        tool for tool in getattr(module, "TOOLS", []) if tool.casefold() not in allowed
    ]
    tools = [(tool, tool.casefold() in allowed) for tool in names]
    return ScopeChoices(ports, tools, tuple(suggested))


def answer_scope_change(text: str, reply: str = "") -> Optional[ScopeChoices]:
    """Reply to a line asking to change the scope: the rows to tick, or None once locked.

    Record the operator's line first (`say_operator_line`); this adds Reconix's reply.
    `reply` is the model's answer to the line ("" without a model).
    """
    try:
        choices = scope_choices(text, reply)
    except StoreValidationError:
        add_chat("text", "reconix", LOCKED, tone="muted")
        return None
    add_chat("text", "reconix", ONLY_YOU)
    return choices
