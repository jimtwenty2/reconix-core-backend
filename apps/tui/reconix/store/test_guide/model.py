"""The evaluator test guide's shapes: a flow holds cases; a result marks one case."""

from dataclasses import dataclass, field
from typing import Tuple

MARKS = ("PASS", "FAIL", "SKIP")


@dataclass(frozen=True)
class Case:
    """One test case: what to type (`ask`), the steps to follow and what should happen."""

    id: str
    title: str
    steps: Tuple[str, ...]
    expect: str
    ask: str = ""  # the general question typed on the Start screen ("" when none)
    note: str = ""  # e.g. what is needed first, or "Core API only"


@dataclass(frozen=True)
class Flow:
    """A group of cases: a template of the main flow, the chat, the commands, the web."""

    id: str  # "PROV", "MF-WEB", "CHAT", …
    number: str  # "0", "1.1", "2", … (the order in the guide)
    title: str
    intro: Tuple[str, ...]
    cases: Tuple[Case, ...]
    facts: Tuple[Tuple[str, str], ...] = field(default=())  # what the template sets up


@dataclass(frozen=True)
class Result:
    """The evaluator's mark on a case ("" = not tested yet), a note and when it was set."""

    mark: str = ""
    note: str = ""
    at: str = ""
