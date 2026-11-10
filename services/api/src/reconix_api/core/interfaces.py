"""The 6 shared functions agreed on day one.

Every part of Reconix-Core connects to the others only through these functions
(and docs/openapi.json). Each one has a fake in services/api/tests/fakes/, so a
part can be built before the real one is ready. On merge day we swap the fake
for the real one in `Interfaces`; no caller changes.

| Function           | Real one lives in                          |
|--------------------|--------------------------------------------|
| get_operator       | services/api (session token)               |
| check              | services/ai/src/reconix_ai/harness         |
| get_approved_scope | services/api (database)                    |
| write_audit        | services/ai/src/reconix_ai/harness/audit   |
| ask_agent          | services/ai (LangGraph agent)              |
| call_tool          | services/api/src/reconix_api/clients (MCP) |
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal, Protocol, Self
from uuid import UUID

from pydantic import BaseModel, Field, field_validator, model_validator

# ---------------------------------------------------------------------------
# Shared values (UPPERCASE everywhere, as in ERD V3)
# ---------------------------------------------------------------------------


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


RISK_ORDER = {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3}


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCKED = "BLOCKED"


class CheckName(StrEnum):
    """The 5 checks, in the order the pipeline runs them."""

    INPUT = "INPUT"
    SCOPE = "SCOPE"
    COMMAND = "COMMAND"
    RISK = "RISK"
    LOOP = "LOOP"


class ToolName(StrEnum):
    """Tools Core names in its own code (the code scan, the parsers). Not the full list:
    any tool in the Kali catalog (tool_specs.json) may be allowed and run, written as an
    UPPERCASE name such as "MASSCAN"."""

    NMAP = "NMAP"
    NUCLEI = "NUCLEI"
    ZAP = "ZAP"
    SEMGREP = "SEMGREP"
    GITLEAKS = "GITLEAKS"
    TRIVY = "TRIVY"
    GRYPE = "GRYPE"
    OSV_SCANNER = "OSV_SCANNER"
    SYFT = "SYFT"
    SONAR_SCAN = "SONAR_SCAN"


class ToolRunStatus(StrEnum):
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"


class AgentTask(StrEnum):
    PLAN = "PLAN"
    SUGGEST = "SUGGEST"
    ANALYZE = "ANALYZE"
    REPORT = "REPORT"
    CHAT = "CHAT"
    VALIDATE = "VALIDATE"  # judge whether a PoC tool run confirms one finding


# ---------------------------------------------------------------------------
# Shapes passed between parts
# ---------------------------------------------------------------------------


class Operator(BaseModel):
    """Who is calling. There are no roles: anyone with a session token may do everything."""

    session_id: UUID
    actor: str


def upper_tools(tools: list[str]) -> list[str]:
    """Tool names in one form: UPPERCASE, like every enum value ("nmap" -> "NMAP")."""
    return [str(tool).strip().upper() for tool in tools]


class ApprovedScope(BaseModel):
    """The approved scope of one assessment. Checks read this; they never read the database."""

    assessment_id: UUID
    ip_ranges: list[str] = Field(default_factory=list)  # CIDR, e.g. "172.20.0.0/24"
    domains: list[str] = Field(default_factory=list)  # exact, or "*.example.lab"
    url_prefixes: list[str] = Field(default_factory=list)  # e.g. "http://juice-shop:3000/"
    repo_paths: list[str] = Field(default_factory=list)  # folders the source tools may read
    excluded_targets: list[str] = Field(default_factory=list)  # always blocked
    allowed_tools: list[str] = Field(default_factory=list)  # Kali catalog names, UPPERCASE
    max_risk: RiskLevel = RiskLevel.LOW
    window_start: datetime | None = None
    window_end: datetime | None = None
    allowed_ports: list[int] = Field(default_factory=list)  # ports tools may reach; empty: no limit

    @field_validator("allowed_tools")
    @classmethod
    def tools_upper(cls, tools: list[str]) -> list[str]:
        return upper_tools(tools)


class ChatScope(BaseModel):
    """The scope a CHAT talks about: approved, or still a draft. Only the chat reads it.
    It is not an ApprovedScope, so it can never be passed to check() by mistake and a
    draft can never let a tool run."""

    assessment_id: UUID | None = None  # a draft has no assessment until it is submitted
    status: Literal["APPROVED", "DRAFT"]
    ip_ranges: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    url_prefixes: list[str] = Field(default_factory=list)
    repo_paths: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    allowed_tools: list[str] = Field(default_factory=list)  # Kali catalog names, UPPERCASE
    max_risk: RiskLevel = RiskLevel.LOW
    window_start: datetime | None = None
    window_end: datetime | None = None
    allowed_ports: list[int] = Field(default_factory=list)

    @field_validator("allowed_tools")
    @classmethod
    def tools_upper(cls, tools: list[str]) -> list[str]:
        return upper_tools(tools)


class Action(BaseModel):
    """One tool run that someone (the agent or a person) wants to do.

    Arguments are always a list, never one shell string.
    """

    tool: str
    target: str
    arguments: list[str] = Field(default_factory=list)
    is_validation: bool = False  # a PoC check of an existing finding
    finding_id: UUID | None = None


class RecentRun(BaseModel):
    """A past action, given to the loop check."""

    tool: str
    target: str
    arguments: list[str]
    started_at: datetime


class LoopLimitSettings(BaseModel):
    """The loop check's limits, once a `configuration` approval changed them."""

    max_same_command: int
    same_command_window_minutes: int
    max_actions_per_minute: int
    max_runs_per_assessment: int


class CheckContext(BaseModel):
    """Everything the checks need. The API builds it from the database."""

    operator: Operator
    scope: ApprovedScope
    now: datetime
    recent_runs: list[RecentRun] = Field(default_factory=list)  # at least the last 10 minutes
    runs_in_assessment: int = 0
    input_text: str | None = None  # the chat text that led to this action, if any
    loop_limits: LoopLimitSettings | None = None  # None: the plan's limits (3, 10, 20, 200)


class CheckResult(BaseModel):
    decision: Decision
    risk: RiskLevel
    blocked_by: CheckName | None = None
    reason: str | None = None  # short UPPERCASE code, e.g. "TARGET_OUT_OF_SCOPE"


class AuditEvent(BaseModel):
    """One JSON line in the audit log. The web timeline reads these."""

    event_type: str  # UPPERCASE, e.g. "ACTION_BLOCKED", "APPROVAL_GRANTED"
    assessment_id: UUID | None
    session_id: UUID
    actor: str
    at: datetime
    details: dict[str, Any] = Field(default_factory=dict)  # already masked


class PlanStep(BaseModel):
    order: int
    title: str
    action: Action | None = None
    phase: Literal["discovery", "scan", "validation"] | None = None
    reason: str = ""  # why the agent wants this step; masked, shown on the approval card


class ChatMessage(BaseModel):
    """One messages row. The role is kept, so an earlier agent answer is never read
    as something the person wrote."""

    role: Literal["user", "assistant", "system"]  # messages.role
    content_masked: str


class FindingInput(BaseModel):
    """One finding as the parsers saved it, for ANALYZE and REPORT. ERD V3 column names."""

    code: str  # e.g. RCX-001
    title: str
    target: str
    description: str
    severity_status: str  # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN or NONE
    finding_status: str  # OPEN, FALSE_POSITIVE or FIXED
    cvss_score: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_id: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    # How trustworthy the signal is, derived (never guessed): CONFIRMED, FIRM, TENTATIVE
    # or INFORMATIONAL. The report ranks trustworthy findings above unverified ones.
    confidence: str = "TENTATIVE"


class ToolRunInput(BaseModel):
    """One tool run and how it was approved, for the report's methodology."""

    tool: str
    target: str
    args: list[str]
    risk_level: RiskLevel
    tool_run_status: str  # tool_runs.tool_run_status, e.g. COMPLETED or TIMED_OUT
    # Not a column: worked out from risk_level and the approval row.
    # MISSING is a MEDIUM or HIGH run with no approval, which the report must name.
    approval_check: Literal["NOT_REQUIRED", "APPROVED", "MISSING"]
    started_at: datetime | None = None
    finished_at: datetime | None = None


class ReportInput(BaseModel):
    """The locked copy a report is written from. The API leaves out FALSE_POSITIVE
    findings and counts by severity itself, so the model never counts."""

    findings: list[FindingInput]
    severity_counts: dict[str, int]  # severity_status -> number of findings
    tool_runs: list[ToolRunInput]


class ResumeInput(BaseModel):
    """A person's decision on the action a waiting run proposed.

    Filled only from the API's own approval row, never from a request body. It only
    tells the agent what happened: the approval and check() still decide what runs.
    """

    agent_run_id: UUID
    assessment_id: UUID
    approval_id: UUID
    action: Action  # the action the approval is for
    decision: Literal["APPROVED", "REJECTED"]  # EXPIRED is sent as REJECTED


class BlockedStep(BaseModel):
    """A planned step the harness refused, and why."""

    order: int
    blocked_by: CheckName
    reason: str | None = None  # UPPERCASE code, e.g. TARGET_OUT_OF_SCOPE


class FindingAnalysis(BaseModel):
    """The agent's suggestions for one finding (the 8 parts of workflow v5).

    Suggestions only: a person accepts them. next_step is never run on its own; an
    operator picks it and it becomes a normal action, with check() and an approval.
    """

    code: str
    explanation: str
    related: list[str]  # codes of related findings
    severity_status: str  # suggested
    cvss_score: float | None
    evidence: str  # copied from the masked tool output
    evidence_summary: str = ""  # plain-language reading of the evidence; the AI's words
    impact: str
    remediation: str
    cwe_ids: list[str]
    owasp_id: list[str]
    cve_ids: list[str]
    next_step: Action | None
    unsure: str  # not empty means a person decides


class AgentRequest(BaseModel):
    """What the backend sends to the AI Service. Everything in it is already masked.

    With resume set, the waiting run gets the person's decision instead of a new task.
    CHAT may come before there is an assessment or an approved scope: it reads
    chat_scope and plan instead, and only answers.
    """

    task: AgentTask
    assessment_id: UUID | None = None  # every task but CHAT needs it
    agent_run_id: UUID  # agent_runs.agent_run_id; the LangGraph thread
    scope: ApprovedScope | None = None  # every task but CHAT needs it
    provider: str = "RECONIX"
    model: str | None = None
    messages: list[ChatMessage] = Field(default_factory=list)  # oldest first
    tool_results: list[str] = Field(default_factory=list)  # raw output
    findings: list[FindingInput] = Field(default_factory=list)  # ANALYZE
    report: ReportInput | None = None  # REPORT
    resume: ResumeInput | None = None
    chat_scope: ChatScope | None = None  # CHAT: the scope the person talks about
    plan: list[str] = Field(default_factory=list)  # CHAT: the current plan, one line a step
    # The agent's own earlier per-step reasoning this assessment (masked), oldest first, so a
    # PLAN or SUGGEST step builds on what it already decided instead of re-deriving it.
    recent_reasoning: list[str] = Field(default_factory=list)
    # The tools that have already completed in this assessment: a technique counts as covered
    # when one of its tools is here, so the planner covers what remains and does not re-run a
    # tool. Facts from the tool_runs table, never the model's claim; tool names, not secret.
    tools_run: list[str] = Field(default_factory=list)
    # The agent's own earlier ReflAct observations this assessment (masked), oldest first, so a
    # SUGGEST step keeps following the leads earlier steps spotted instead of re-reading output.
    recent_observations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def scope_unless_chat(self) -> Self:
        if self.task != AgentTask.CHAT and (self.assessment_id is None or self.scope is None):
            raise ValueError(f"{self.task} needs the assessment and its approved scope")
        if self.task == AgentTask.CHAT and self.resume is not None:
            raise ValueError("a CHAT only answers: it never waits, so it is never resumed")
        return self


class AgentResponse(BaseModel):
    """What the AI Service sends back. It only suggests; the backend decides.

    risk and decision are for information. The API keeps its own approval and runs
    check() again before any tool runs, and only proposed_action may be approved.
    """

    text: str = ""
    plan: list[PlanStep] = Field(default_factory=list)
    proposed_action: Action | None = None
    risk: RiskLevel | None = None  # the harness risk of proposed_action
    blocked: list[BlockedStep] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)  # knowledge ids, e.g. CWE-89
    reflections: list[str] = Field(default_factory=list)  # the run's own ReflAct observations
    analysis_summary: str = ""  # ANALYZE
    analysis: list[FindingAnalysis] = Field(default_factory=list)  # ANALYZE
    # VALIDATE: the AI's verdict on a finding, read from the real (masked) PoC tool output.
    validation_status: Literal["CONFIRMED", "UNCONFIRMED", "INCONCLUSIVE"] | None = None
    validation_reason: str = ""  # VALIDATE: one masked line on why
    executive_summary: str | None = None  # REPORT: reports.executive_summary
    methodology: str | None = None  # REPORT: reports.methodology
    agent_run_id: UUID
    checkpoint_id: str | None = None  # agent_runs.checkpoint_id
    waiting: bool = False  # paused until a person decides on proposed_action
    decision: Literal["APPROVED", "REJECTED"] | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    masked_count: int = 0


class ToolJob(BaseModel):
    """One call to the Kali MCP server."""

    tool_run_id: UUID
    tool: str
    target: str
    arguments: list[str]
    job_token: str  # signed by the backend, single use, short-lived
    timeout_seconds: int = 600


class ToolResult(BaseModel):
    """The raw result from the Kali MCP server. Parsing happens in the backend."""

    status: ToolRunStatus
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    output_file: str | None = None  # the tool's own result file (XML, JSON, JSONL)
    duration_ms: int = 0
    truncated: bool = False


# ---------------------------------------------------------------------------
# The 6 functions
# ---------------------------------------------------------------------------

GetOperator = Callable[[str], Operator]
"""Token from the request -> who is calling. Raises PermissionError for an unknown token."""

Check = Callable[[Action, CheckContext], CheckResult]
"""Runs input -> scope -> command -> risk -> loop. The first block stops."""

GetApprovedScope = Callable[[UUID], ApprovedScope]
"""Assessment id -> its approved scope. Raises LookupError if there is none."""

WriteAudit = Callable[[AuditEvent], None]
"""Writes exactly one audit line."""

OnPiece = Callable[[str], Awaitable[None]]
"""Gets a CHAT answer in masked pieces while the model writes it. Only for showing: the
answer in AgentResponse is the one that is saved, and it may differ from the pieces."""


class AskAgent(Protocol):
    """Asks the AI agent to plan, suggest, analyze, report or chat. With on_piece, a CHAT
    answer is also streamed to it in masked pieces; the other tasks ignore it."""

    def __call__(
        self, request: AgentRequest, on_piece: OnPiece | None = None
    ) -> Awaitable[AgentResponse]: ...


CallTool = Callable[[ToolJob], Awaitable[ToolResult]]
"""Runs one tool in the Kali container through MCP."""


@dataclass(frozen=True)
class Interfaces:
    """The 6 functions the API uses. main.py wires the real ones; tests wire the fakes."""

    get_operator: GetOperator
    check: Check
    get_approved_scope: GetApprovedScope
    write_audit: WriteAudit
    ask_agent: AskAgent
    call_tool: CallTool
