"""What the graph remembers between steps.

The state is saved in every checkpoint, so it holds only plain JSON values and
nothing secret: messages and tool results are masked when they come in, and the
provider settings (with the API key) are passed beside the state, never in it.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, TypedDict

from reconix_ai.harness import mask_secrets

MAX_MESSAGES = 10
MAX_TOOL_RESULTS = 3
MAX_INPUT_CHARS = 4000

SCOPE_LISTS = ("ip_ranges", "domains", "url_prefixes", "repo_paths", "excluded_targets")


class AgentState(TypedDict, total=False):
    task: str  # PLAN or SUGGEST
    assessment_id: str
    scope: dict[str, Any]  # the approved scope, see scope_to_dict()
    messages: list[str]  # masked chat, oldest first
    tool_results: list[str]  # masked raw output of earlier runs
    goal: str
    queries: list[str]
    knowledge: list[dict[str, str]]  # hits: source, ref_id, title, section, text, url
    knowledge_unavailable: bool
    summary: str
    steps: list[dict[str, Any]]  # the plan; see contracts.PlanStep
    proposed_action: dict[str, Any] | None  # see contracts.ProposedAction
    risk: str | None
    blocked: list[dict[str, Any]]  # see contracts.BlockedStep
    decision: str | None  # APPROVED or REJECTED
    # Totals for the current ask; ask_agent() starts them again.
    prompt_tokens: int
    completion_tokens: int
    masked_count: int


class ScopeLike(Protocol):
    """The fields of the shared ApprovedScope the agent needs."""

    ip_ranges: list[str]
    domains: list[str]
    url_prefixes: list[str]
    repo_paths: list[str]
    excluded_targets: list[str]
    allowed_tools: list[str]
    max_risk: str
    window_start: datetime | None
    window_end: datetime | None


@dataclass(frozen=True)
class AgentScope:
    """The approved scope in the shape the harness checks read."""

    ip_ranges: list[str]
    domains: list[str]
    url_prefixes: list[str]
    repo_paths: list[str]
    excluded_targets: list[str]
    allowed_tools: list[str]
    max_risk: str
    window_start: datetime | None
    window_end: datetime | None


def scope_to_dict(scope: ScopeLike) -> dict[str, Any]:
    data: dict[str, Any] = {
        name: [str(item) for item in getattr(scope, name)] for name in SCOPE_LISTS
    }
    data["allowed_tools"] = [str(tool).upper() for tool in scope.allowed_tools]
    data["max_risk"] = str(scope.max_risk).upper()
    data["window_start"] = scope.window_start.isoformat() if scope.window_start else None
    data["window_end"] = scope.window_end.isoformat() if scope.window_end else None
    return data


def scope_from_dict(data: dict[str, Any]) -> AgentScope:
    return AgentScope(
        **{name: list(data[name]) for name in SCOPE_LISTS},
        allowed_tools=list(data["allowed_tools"]),
        max_risk=data["max_risk"],
        window_start=parse_time(data["window_start"]),
        window_end=parse_time(data["window_end"]),
    )


def parse_time(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None


def masked_texts(texts: list[str], keep: int) -> tuple[list[str], int]:
    """The last `keep` texts, each masked then cut, and how many secrets were hidden.

    Masked before cutting, so a cut can never leave half a secret unmasked.
    """
    kept, total = [], 0
    for text in texts[-keep:] if keep else []:
        masked, count = mask_secrets(text)
        kept.append(masked[:MAX_INPUT_CHARS])
        total += count
    return kept, total
