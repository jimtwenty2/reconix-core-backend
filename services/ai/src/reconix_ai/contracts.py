"""Plan, ProposedAction: the shapes the API receives from the agent.

The field names match the shared AgentResponse, PlanStep and Action in
services/api/src/reconix_api/core/interfaces.py, so the API can build those
from these with dataclasses.asdict(). The extra fields (risk, run_id, ...) are
for the agent_runs row and are ignored by the shared shapes.
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ProposedAction:
    """One tool run the agent suggests. The API checks it again before it runs."""

    tool: str  # NMAP, NUCLEI, ZAP, SEMGREP or GITLEAKS
    target: str
    arguments: list[str] = field(default_factory=list)  # always a list, never one string
    is_validation: bool = False


@dataclass(frozen=True)
class PlanStep:
    order: int
    title: str
    action: ProposedAction | None = None


@dataclass(frozen=True)
class BlockedStep:
    """A planned step the harness refused, and why."""

    order: int
    blocked_by: str  # INPUT, SCOPE, COMMAND, RISK or LOOP
    reason: str | None  # UPPERCASE code, e.g. TARGET_OUT_OF_SCOPE


@dataclass(frozen=True)
class AgentAnswer:
    text: str
    plan: list[PlanStep] = field(default_factory=list)
    proposed_action: ProposedAction | None = None
    risk: str | None = None  # the harness risk of proposed_action: LOW, MEDIUM or HIGH
    blocked: list[BlockedStep] = field(default_factory=list)
    references: list[str] = field(default_factory=list)  # knowledge ids used, e.g. CWE-89
    run_id: str = ""  # agent_runs.agent_run_id; the LangGraph thread
    checkpoint_id: str | None = None  # agent_runs.checkpoint_id
    waiting: bool = False  # True: paused until a person approves or rejects proposed_action
    decision: str | None = None  # APPROVED or REJECTED, once a person decided
    prompt_tokens: int = 0
    completion_tokens: int = 0
    masked_count: int = 0
