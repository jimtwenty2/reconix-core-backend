"""The 6 shared functions agreed on day one.

Every part of Reconix-Core connects to the others only through these functions
(and docs/openapi.json). Each one has a fake in services/api/tests/fakes/, so a
part can be built before the real one is ready. On merge day we swap the fake
for the real one in `Interfaces`; no caller changes.

| Function           | Real one lives in                          |
|--------------------|--------------------------------------------|
| get_operator       | services/api (web token, session role)     |
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
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Shared values (UPPERCASE everywhere, as in ERD V3)
# ---------------------------------------------------------------------------


class Role(StrEnum):
    OPERATOR = "OPERATOR"
    VIEWER = "VIEWER"


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
    """The only 5 tools. The MCP client maps these to the Kali tool names."""

    NMAP = "NMAP"
    NUCLEI = "NUCLEI"
    ZAP = "ZAP"
    SEMGREP = "SEMGREP"
    GITLEAKS = "GITLEAKS"


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


# ---------------------------------------------------------------------------
# Shapes passed between parts
# ---------------------------------------------------------------------------


class Operator(BaseModel):
    """Who is calling. A VIEWER may only read."""

    session_id: UUID
    role: Role
    actor: str


class ApprovedScope(BaseModel):
    """The approved scope of one assessment. Checks read this; they never read the database."""

    assessment_id: UUID
    ip_ranges: list[str] = Field(default_factory=list)  # CIDR, e.g. "172.20.0.0/24"
    domains: list[str] = Field(default_factory=list)  # exact, or "*.example.lab"
    url_prefixes: list[str] = Field(default_factory=list)  # e.g. "http://juice-shop:3000/"
    repo_paths: list[str] = Field(default_factory=list)  # folders the source tools may read
    excluded_targets: list[str] = Field(default_factory=list)  # always blocked
    allowed_tools: list[ToolName] = Field(default_factory=list)
    max_risk: RiskLevel = RiskLevel.LOW
    window_start: datetime | None = None
    window_end: datetime | None = None


class Action(BaseModel):
    """One tool run that someone (the agent or a person) wants to do.

    Arguments are always a list, never one shell string.
    """

    tool: ToolName
    target: str
    arguments: list[str] = Field(default_factory=list)
    is_validation: bool = False  # a PoC check of an existing finding
    finding_id: UUID | None = None


class RecentRun(BaseModel):
    """A past action, given to the loop check."""

    tool: ToolName
    target: str
    arguments: list[str]
    started_at: datetime


class CheckContext(BaseModel):
    """Everything the checks need. The API builds it from the database."""

    operator: Operator
    scope: ApprovedScope
    now: datetime
    recent_runs: list[RecentRun] = Field(default_factory=list)  # at least the last 10 minutes
    runs_in_assessment: int = 0
    input_text: str | None = None  # the chat text that led to this action, if any


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
    role: Role
    actor: str
    at: datetime
    details: dict[str, Any] = Field(default_factory=dict)  # already masked


class PlanStep(BaseModel):
    order: int
    title: str
    action: Action | None = None


class AgentRequest(BaseModel):
    """What the backend sends to the AI Service.

    Draft: to be confirmed with the AI Service owner. Change it here, then in both fakes.
    """

    task: AgentTask
    assessment_id: UUID
    scope: ApprovedScope
    provider: str = "RECONIX"
    model: str | None = None
    messages: list[str] = Field(default_factory=list)  # masked chat history
    tool_results: list[str] = Field(default_factory=list)  # masked raw output


class AgentResponse(BaseModel):
    """What the AI Service sends back. It only suggests; the backend decides."""

    text: str = ""
    plan: list[PlanStep] = Field(default_factory=list)
    proposed_action: Action | None = None


class ToolJob(BaseModel):
    """One call to the Kali MCP server."""

    tool_run_id: UUID
    tool: ToolName
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

AskAgent = Callable[[AgentRequest], Awaitable[AgentResponse]]
"""Asks the AI agent to plan, suggest, analyze, report or chat."""

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
