"""What the graph remembers between steps.

The state is saved in every checkpoint, so it holds only plain JSON values and
nothing secret: messages and tool results are masked when they come in, and the
provider settings (with the API key) are passed beside the state, never in it.
"""

from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from typing import Any, Protocol, TypedDict

from reconix_ai.harness import mask_secrets

MAX_MESSAGES = 10
MAX_TOOL_RESULTS = 3
MAX_INPUT_CHARS = 4000

SCOPE_LISTS = ("ip_ranges", "domains", "url_prefixes", "repo_paths", "excluded_targets")


class AgentState(TypedDict, total=False):
    task: str  # PLAN, SUGGEST, ANALYZE, REPORT or CHAT
    assessment_id: str
    scope: dict[str, Any] | None  # the approved scope, see scope_to_dict(); CHAT: maybe none
    scope_status: str  # CHAT: APPROVED, DRAFT or NONE
    plan_lines: list[str]  # CHAT: the current plan, masked, written by the agent earlier
    messages: list[str]  # masked chat, oldest first
    tool_results: list[str]  # masked raw output of earlier runs
    goal: str
    queries: list[str]
    knowledge: list[dict[str, str]]  # hits: source, ref_id, title, section, text, url
    knowledge_unavailable: bool
    reflections: list[str]  # ReflAct: one masked line per look at the tool results
    reflect_more: bool
    summary: str
    steps: list[dict[str, Any]]  # the plan; see contracts.PlanStep
    proposed_action: dict[str, Any] | None  # see contracts.ProposedAction
    risk: str | None
    blocked: list[dict[str, Any]]  # see contracts.BlockedStep
    decision: str | None  # APPROVED or REJECTED
    findings: list[dict[str, Any]]  # ANALYZE: masked, see contracts.FindingInput
    analysis_summary: str
    analysis: list[dict[str, Any]]  # see contracts.FindingAnalysis
    report: dict[str, Any]  # REPORT: the masked locked copy, see contracts.ReportInput
    executive_summary: str
    methodology: str
    answer: str  # CHAT
    chat_references: list[str]  # CHAT: ids the answer relies on, only known ones
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
    allowed_ports: list[int] = field(default_factory=list)  # empty: no limit on ports


def scope_to_dict(scope: ScopeLike) -> dict[str, Any]:
    data: dict[str, Any] = {
        name: [str(item) for item in getattr(scope, name)] for name in SCOPE_LISTS
    }
    data["allowed_tools"] = [str(tool).upper() for tool in scope.allowed_tools]
    data["max_risk"] = str(scope.max_risk).upper()
    data["window_start"] = scope.window_start.isoformat() if scope.window_start else None
    data["window_end"] = scope.window_end.isoformat() if scope.window_end else None
    data["allowed_ports"] = [int(port) for port in getattr(scope, "allowed_ports", None) or []]
    return data


def scope_from_dict(data: dict[str, Any]) -> AgentScope:
    return AgentScope(
        **{name: list(data[name]) for name in SCOPE_LISTS},
        allowed_tools=list(data["allowed_tools"]),
        max_risk=data["max_risk"],
        window_start=parse_time(data["window_start"]),
        window_end=parse_time(data["window_end"]),
        allowed_ports=list(data.get("allowed_ports", [])),  # a checkpoint from before ports
    )


def parse_time(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None


def masked_report(report: Any) -> tuple[dict[str, Any], int]:
    """The locked copy as plain JSON values, every text masked. The counts stay as
    the API made them; graph.check_report() has already checked them."""
    findings, in_findings = masked_findings(list(report.findings))
    tool_runs, in_runs = masked_findings(list(report.tool_runs))
    counts = {str(level): int(n) for level, n in dict(report.severity_counts).items()}
    copy = {"findings": findings, "severity_counts": counts, "tool_runs": tool_runs}
    return copy, in_findings + in_runs


def masked_findings(findings: list[Any]) -> tuple[list[dict[str, Any]], int]:
    """Rows (findings or tool runs) as plain dicts: every text masked then cut, however
    deep, and dates as ISO 8601 text."""
    kept, total = [], 0
    for finding in findings:
        row = asdict(finding) if is_dataclass(finding) else dict(finding)
        value, count = masked_value(row)
        kept.append(value)
        total += count
    return kept, total


def masked_value(value: Any) -> tuple[Any, int]:
    if isinstance(value, datetime):
        return value.isoformat(), 0
    if isinstance(value, str):  # a StrEnum is a str too, and becomes its plain value
        return masked_cut(str(value))
    if isinstance(value, dict):
        pairs = [(str(key), masked_value(item)) for key, item in value.items()]
        return {key: item for key, (item, _) in pairs}, sum(n for _, (_, n) in pairs)
    if isinstance(value, list | tuple):
        items = [masked_value(item) for item in value]
        return [item for item, _ in items], sum(n for _, n in items)
    return value, 0


def masked_cut(text: str) -> tuple[str, int]:
    masked, count = mask_secrets(text)
    return masked[:MAX_INPUT_CHARS], count


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
