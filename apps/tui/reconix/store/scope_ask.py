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

Some changes the tick list can't make, so Reconix says why instead: a port range ("add ports
1-1024": the scope lists single ports), a host ("add 10.0.0.99 to the scope": the target is
fixed, /new starts again), and a tool the template doesn't use ("add nikto"). The tick list
opens on the first row the line named (the new port, the tool), so Space ticks that one.
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
# "1-1024", "1000 to 2000": a range of ports (not part of an address: 10.0.0.1-10.0.0.20).
_PORT_RANGE = re.compile(r"(?<![\w.:/-])(\d{1,5})\s*(?:-|–|\bto\b)\s*(\d{1,5})(?![\w.:/-])",
                         re.IGNORECASE)
# A host in the line: an IPv4 address or range, a URL, or a host name (a tool name is not one).
_HOST = re.compile(r"(?<![\w.])\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?![\w.])|\bhttps?://|"
                   r"(?<![\w.-])[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}(?![\w.-])", re.IGNORECASE)
MAX_SUGGESTED = 20

ONLY_YOU = "Only you can change the scope. Tick what it allows, then press Enter to save."
LOCKED = (
    "The scope is approved and locked, so it can't change now. Start a new "
    "assessment (/new) to test with a different scope."
)
RANGE = ("The scope lists single ports, not a range ({range}). Name each port you want "
         "(add ports 8000, 8080), then tick it.")
HOSTS = ("Hosts can't change here: the target is fixed for this assessment. To test another "
         "host, start again with /new.")
HOSTS_EXCLUDE = " To leave a host out, use Edit manifest (Excluded)."
TOOLS = ("{names} can't be added here: this template uses only {tools}. To test with other "
         "tools, start again with /new.")


class ScopeChoices(NamedTuple):
    """The tick list's rows: (value, ticked). `ports` is empty for a scope without ports.
    `suggested`: ports added because the model's reply named them (shown as such)."""

    ports: List[Tuple[int, bool]]
    tools: List[Tuple[str, bool]]
    suggested: Tuple[int, ...] = ()
    focus: str = ""   # the row the list opens on ("port:3389", "tool:nmap"; "" = the first)


def _named_tools(text: str) -> List[str]:
    """The tools `text` names, as Reconix names them ("nikto" -> "Nikto")."""
    from .parser import extract_tools   # the parser imports the templates, so not at the top

    return list(extract_tools(text))


def wants_scope_change(text: str) -> bool:
    """A line that asks to add or remove ports, tools or the scope itself, or to change its
    hosts or name a tool ("add nikto", "add 10.0.0.99"); on a scope with ports also a change
    verb before bare numbers ("add 3389, 8080")."""
    if _CHANGE.search(text) and (
        _SUBJECT.search(text) or _named_tools(text) or _HOST.search(_no_tools(text))
    ):
        return True
    scope = lists.current().scope
    return bool(scope is not None and scope.kind == "network" and _BARE_PORTS.search(text))


def _no_tools(text: str) -> str:
    """`text` without the tool names in it ("testssl.sh" reads like a host name)."""
    from .parser import _TOOL_RE

    return _TOOL_RE.sub(" ", text)


def refusal(text: str) -> str:
    """Why the tick list can't make the change `text` asks for ("" when it can): a port
    range, a host, or a tool this template doesn't use."""
    assessment = lists.current()
    scope = assessment.scope
    network = scope is not None and scope.kind == "network"
    span = _PORT_RANGE.search(text)
    if network and span and ("port" in text.casefold() or _BARE_PORTS.search(text)
                             or _CHANGE.search(text)):
        return RANGE.format(range=f"{int(span.group(1))}-{int(span.group(2))}")
    if _HOST.search(_no_tools(text)) and not typed_ports(_HOST.sub(" ", text)):
        return HOSTS + (HOSTS_EXCLUDE if network else "")
    module = MODULES.get(assessment.selected_template or "")
    template_tools = list(getattr(module, "TOOLS", [])) or list(scope.tools if scope else [])
    usable = {tool.casefold() for tool in template_tools}
    others = [tool for tool in _named_tools(text) if tool.casefold() not in usable]
    if others:
        return TOOLS.format(names=_and(others), tools=_and(template_tools))
    return ""


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


def _and(names: Sequence[str]) -> str:
    """ "a", "a and b", "a, b and c"."""
    names = list(names)
    return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} and {names[-1]}"


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
    return ScopeChoices(ports, tools, tuple(suggested), _focus(text, ports, tools, suggested))


def _focus(text: str, ports: Sequence[Tuple[int, bool]], tools: Sequence[Tuple[str, bool]],
           suggested: Sequence[int]) -> str:
    """The row the tick list opens on: the first port the line named, else the first tool it
    named, else the first port the model suggested ("" = the first row)."""
    rows = {port for port, _ticked in ports}
    for port in typed_ports(text) if rows else []:
        if port in rows:
            return f"port:{port}"
    names = {tool.casefold(): tool for tool, _ticked in tools}
    for tool in _named_tools(text):
        if tool.casefold() in names:
            return f"tool:{names[tool.casefold()]}"
    return f"port:{suggested[0]}" if suggested else ""


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
    why = refusal(text)
    if why:
        add_chat("text", "reconix", why, tone="muted")
        return None
    add_chat("text", "reconix", ONLY_YOU)
    return choices
