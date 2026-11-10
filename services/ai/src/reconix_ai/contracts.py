"""The shapes passed between the API and the agent.

Out of the agent: PlanStep, ProposedAction and AgentAnswer. The field names
match the shared PlanStep and Action in
services/api/src/reconix_api/core/interfaces.py, and AgentAnswer matches the
proposed AgentResponse field for field, so the API builds it with
AgentResponse(**dataclasses.asdict(answer)).

Into the agent for ANALYZE, REPORT and CHAT: ChatMessage, FindingInput,
ToolRunInput and ReportInput, and ResumeInput to hand a waiting run the
person's decision. Their field names are the ERD V3 column names, so the API
fills them straight from its rows. The API masks them first, and the agent
masks every string again before it enters the state, because finding text and
tool arguments come from the target and may hold a secret the API missed.

The matching change to the shared AgentRequest and AgentResponse is proposed
to the API owner; until it is merged, the agent does only PLAN and SUGGEST.
"""

from dataclasses import dataclass, field
from typing import Any, Literal

# findings.severity_status, worst first.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN")

# findings.confidence, most trustworthy first (the report ranks a confirmed finding above
# an unverified one of the same severity).
CONFIDENCE_ORDER = ("CONFIRMED", "FIRM", "TENTATIVE", "INFORMATIONAL")


def severity_rank(finding: dict[str, Any]) -> int:
    """For sorting worst first; an unknown value goes last."""
    level = finding.get("severity_status")
    return SEVERITY_ORDER.index(level) if level in SEVERITY_ORDER else len(SEVERITY_ORDER)


def confidence_rank(finding: dict[str, Any]) -> int:
    """For sorting most trustworthy first; an unknown value goes last."""
    tier = finding.get("confidence")
    return CONFIDENCE_ORDER.index(tier) if tier in CONFIDENCE_ORDER else len(CONFIDENCE_ORDER)


def finding_rank(finding: dict[str, Any]) -> tuple[int, int]:
    """Sort key: worst severity first, then most trustworthy first within a severity."""
    return (severity_rank(finding), confidence_rank(finding))


@dataclass(frozen=True)
class ProposedAction:
    """One tool run the agent suggests. The API checks it again before it runs."""

    tool: str  # a Kali catalog tool, UPPERCASE, e.g. NMAP, MASSCAN, SQLMAP
    target: str
    arguments: list[str] = field(default_factory=list)  # always a list, never one string
    is_validation: bool = False


@dataclass(frozen=True)
class PlanStep:
    order: int
    title: str
    action: ProposedAction | None = None
    phase: str | None = None  # discovery, scan or validation; None if the model gave none
    reason: str = ""  # why the agent wants this step, for the person who approves it


@dataclass(frozen=True)
class BlockedStep:
    """A planned step the harness refused, and why."""

    order: int
    blocked_by: str  # INPUT, SCOPE, COMMAND, RISK or LOOP
    reason: str | None  # UPPERCASE code, e.g. TARGET_OUT_OF_SCOPE


@dataclass(frozen=True)
class ChatMessage:
    """One row of messages. The role says whose words they are, so an earlier
    answer of the agent is never read as something the person wrote.

    Every role is shown to the model as fenced chat data and goes through the
    input check; a row is never sent as a model system message.
    """

    role: Literal["user", "assistant", "system"]  # messages.role
    content_masked: str


@dataclass(frozen=True)
class FindingInput:
    """One finding as the parsers saved it. The agent reads it and never changes it."""

    code: str  # e.g. RCX-001; the key the analysis answers with
    title: str
    target: str
    description: str
    severity_status: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN or NONE
    finding_status: str  # OPEN, FALSE_POSITIVE or FIXED
    cvss_score: float | None = None
    cwe_ids: list[str] = field(default_factory=list)
    owasp_id: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    # Derived trust tier: CONFIRMED, FIRM, TENTATIVE or INFORMATIONAL.
    confidence: str = "TENTATIVE"


@dataclass(frozen=True)
class ToolRunInput:
    """One tool run, with how it was approved, for the report's methodology."""

    tool: str  # a Kali catalog tool, UPPERCASE, e.g. NMAP, MASSCAN, SQLMAP
    target: str
    args: list[str]
    risk_level: str  # LOW, MEDIUM or HIGH
    tool_run_status: str  # tool_runs.tool_run_status, e.g. COMPLETED or TIMED_OUT
    # Not a column: the API works it out from risk_level and the approval row.
    # MISSING is a MEDIUM or HIGH run with no approval, which the report must name.
    approval_check: Literal["NOT_REQUIRED", "APPROVED", "MISSING"]
    started_at: str | None = None  # ISO 8601; empty for a run that never started
    finished_at: str | None = None


@dataclass(frozen=True)
class ReportInput:
    """The locked copy a report is written from.

    The API leaves out FALSE_POSITIVE findings and counts the rest by severity
    itself, so the model never counts and never decides what the report keeps.
    Finding codes are unique in it: for a combined report the API puts the
    assessment code in front, e.g. RCX-2026-0001/RCX-001.
    """

    findings: list[FindingInput]
    severity_counts: dict[str, int]  # severity_status -> number of findings
    tool_runs: list[ToolRunInput]


@dataclass(frozen=True)
class ResumeInput:
    """A person's decision on the action a run is waiting for.

    The API fills it only from its own approval row: decided by an OPERATOR,
    for this run, never from a request body. The agent resumes only if the run
    belongs to assessment_id and action is exactly the action it is waiting on,
    so no hash has to be shared between the two parts. This only tells the
    agent what happened; the API's approval and check() still decide whether a
    tool runs.
    """

    agent_run_id: str
    assessment_id: str
    approval_id: str
    action: ProposedAction  # the action the approval is for
    decision: Literal["APPROVED", "REJECTED"]  # EXPIRED is sent as REJECTED


@dataclass(frozen=True)
class FindingAnalysis:
    """The agent's suggestions for one finding: the 8 parts of workflow v5.

    Only severity_status, cvss_score, the id lists, impact and remediation map to
    findings columns, and only as suggestions a person accepts. evidence is kept
    only if it is an exact part of the masked tool output that was sent.

    next_step is never run on its own, whatever its risk. It is shown to the
    person, and only when an operator picks it does it become a normal action:
    a new actions row, check(), and an approval when MEDIUM or HIGH. It has no
    finding_id; the API sets that from code.
    """

    code: str
    explanation: str  # part 1; not findings.description, which the parsers own
    related: list[str]  # codes of related findings
    severity_status: str  # suggested
    cvss_score: float | None
    evidence: str  # copied from the tool output
    evidence_summary: str  # plain-language reading of the evidence; the AI's words
    impact: str
    remediation: str
    cwe_ids: list[str]
    owasp_id: list[str]
    cve_ids: list[str]
    next_step: ProposedAction | None
    unsure: str  # what the agent is not sure about; not empty means a person decides


@dataclass(frozen=True)
class AgentAnswer:
    """The agent's answer. It only suggests.

    risk and decision are for information. The API never runs a tool because of
    them: it keeps its own approval (action hash, expiry, single use) and runs
    check() again right before the tool runs. Only proposed_action may be
    approved, never another step of the plan.
    """

    text: str
    plan: list[PlanStep] = field(default_factory=list)
    proposed_action: ProposedAction | None = None
    risk: str | None = None  # the harness risk of proposed_action: LOW, MEDIUM or HIGH
    blocked: list[BlockedStep] = field(default_factory=list)
    references: list[str] = field(default_factory=list)  # knowledge ids used, e.g. CWE-89
    analysis_summary: str = ""  # ANALYZE
    analysis: list[FindingAnalysis] = field(default_factory=list)  # ANALYZE
    # VALIDATE: the verdict on one finding, read from the real (masked) PoC tool output.
    validation_status: str | None = None  # CONFIRMED, UNCONFIRMED or INCONCLUSIVE
    validation_reason: str = ""  # one masked line on why
    executive_summary: str | None = None  # REPORT: reports.executive_summary
    methodology: str | None = None  # REPORT: reports.methodology
    agent_run_id: str = ""  # agent_runs.agent_run_id; the LangGraph thread
    checkpoint_id: str | None = None  # agent_runs.checkpoint_id
    waiting: bool = False  # True: paused until a person approves or rejects proposed_action
    decision: str | None = None  # APPROVED or REJECTED, once a person decided
    prompt_tokens: int = 0
    completion_tokens: int = 0
    masked_count: int = 0
