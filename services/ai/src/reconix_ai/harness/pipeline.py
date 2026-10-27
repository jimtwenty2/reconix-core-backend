"""Runs the checks in order; the first block stops.

Order: input -> scope -> command -> risk -> loop.

`check(action, context)` is the real version of the shared `check` function in
services/api/src/reconix_api/core/interfaces.py. It takes the shared Action and
CheckContext as they are, and its result has the same fields as the shared
CheckResult, so the API can build one from it:

    result = check(action, context)
    CheckResult(**dataclasses.asdict(result))

The agent runs it on every step it suggests, and the API runs it again right
before any tool runs.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol

from reconix_ai.harness.checks.command import check_command
from reconix_ai.harness.checks.input import check_input
from reconix_ai.harness.checks.loop import (
    DEFAULT_LIMITS,
    LoopLimits,
    PastRun,
    check_loop,
)
from reconix_ai.harness.checks.result import CheckOutcome, Decision, RiskLevel
from reconix_ai.harness.checks.risk import check_risk
from reconix_ai.harness.checks.scope import ScopeRules, check_scope


class CheckName(StrEnum):
    INPUT = "INPUT"
    SCOPE = "SCOPE"
    COMMAND = "COMMAND"
    RISK = "RISK"
    LOOP = "LOOP"


class ActionLike(Protocol):
    """The fields of the shared Action the checks need."""

    @property
    def tool(self) -> str: ...
    @property
    def target(self) -> str: ...
    @property
    def arguments(self) -> Sequence[str]: ...
    @property
    def is_validation(self) -> bool: ...


class PipelineScope(ScopeRules, Protocol):
    @property
    def max_risk(self) -> str: ...


class ContextLike(Protocol):
    """The fields of the shared CheckContext the checks need."""

    @property
    def scope(self) -> PipelineScope: ...
    @property
    def now(self) -> datetime: ...
    @property
    def recent_runs(self) -> Sequence[PastRun]: ...
    @property
    def runs_in_assessment(self) -> int: ...
    @property
    def input_text(self) -> str | None: ...


@dataclass(frozen=True)
class PipelineResult:
    """Same fields as the shared CheckResult."""

    decision: Decision
    risk: RiskLevel
    blocked_by: CheckName | None = None
    reason: str | None = None


def check(
    action: ActionLike, context: ContextLike, limits: LoopLimits = DEFAULT_LIMITS
) -> PipelineResult:
    tool = str(action.tool)
    arguments = action.arguments

    outcome = check_input(context.input_text)
    if outcome.decision == Decision.BLOCKED:
        return blocked_result(CheckName.INPUT, outcome)

    outcome = check_scope(tool, action.target, context.scope, context.now)
    if outcome.decision == Decision.BLOCKED:
        return blocked_result(CheckName.SCOPE, outcome)

    outcome = check_command(tool, action.target, arguments)
    if outcome.decision == Decision.BLOCKED:
        return blocked_result(CheckName.COMMAND, outcome)

    risk_outcome = check_risk(tool, arguments, action.is_validation, context.scope.max_risk)
    if risk_outcome.decision == Decision.BLOCKED:
        return blocked_result(CheckName.RISK, risk_outcome)
    risk = risk_outcome.risk

    outcome = check_loop(
        tool,
        action.target,
        arguments,
        context.recent_runs,
        context.runs_in_assessment,
        context.now,
        limits,
    )
    if outcome.decision == Decision.BLOCKED:
        return blocked_result(CheckName.LOOP, outcome, risk)

    return PipelineResult(decision=Decision.ALLOW, risk=risk)


def blocked_result(
    check_name: CheckName, outcome: CheckOutcome, risk: RiskLevel | None = None
) -> PipelineResult:
    # Before the risk is known, a blocked action counts as HIGH.
    return PipelineResult(
        decision=Decision.BLOCKED,
        risk=risk or outcome.risk or RiskLevel.HIGH,
        blocked_by=check_name,
        reason=outcome.reason,
    )
