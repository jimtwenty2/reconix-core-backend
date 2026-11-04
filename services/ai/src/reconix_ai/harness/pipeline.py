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

from collections.abc import Callable, Sequence
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
from reconix_ai.harness.checks.result import CheckOutcome, Decision, RiskLevel, blocked
from reconix_ai.harness.checks.risk import check_risk
from reconix_ai.harness.checks.scope import ScopeRules, check_ports, check_scope


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
    # A check that breaks (bad input, a bug) blocks; it never lets an action through.
    try:
        steps = check_steps(action, context, limits)
    except Exception:
        return blocked_result(CheckName.INPUT, blocked("CHECK_ERROR"))

    risk = None
    for check_name, run in steps:
        try:
            outcome = run()
        except Exception:
            outcome = blocked("CHECK_ERROR")
        if outcome.decision == Decision.BLOCKED:
            return blocked_result(check_name, outcome, risk)
        if check_name == CheckName.RISK:
            risk = outcome.risk
    return PipelineResult(decision=Decision.ALLOW, risk=risk)


Step = tuple[CheckName, Callable[[], CheckOutcome]]


def check_steps(action: ActionLike, context: ContextLike, limits: LoopLimits) -> list[Step]:
    """The 5 checks in their fixed order. Each runs only when the one before allowed."""
    tool = str(action.tool)
    target = action.target
    arguments = action.arguments
    scope = context.scope
    return [
        (CheckName.INPUT, lambda: check_input(context.input_text)),
        (CheckName.SCOPE, lambda: scope_and_ports(tool, target, arguments, scope, context.now)),
        (CheckName.COMMAND, lambda: check_command(tool, target, arguments)),
        (CheckName.RISK, lambda: check_risk(tool, arguments, action.is_validation, scope.max_risk)),
        (
            CheckName.LOOP,
            lambda: check_loop(
                tool,
                target,
                arguments,
                context.recent_runs,
                context.runs_in_assessment,
                context.now,
                limits,
            ),
        ),
    ]


def scope_and_ports(
    tool: str, target: str, arguments: Sequence[str], scope: PipelineScope, now: datetime
) -> CheckOutcome:
    """The scope check: the target first, then the ports it may scan."""
    outcome = check_scope(tool, target, scope, now)
    if outcome.decision == Decision.BLOCKED:
        return outcome
    return check_ports(tool, target, arguments, scope)


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
