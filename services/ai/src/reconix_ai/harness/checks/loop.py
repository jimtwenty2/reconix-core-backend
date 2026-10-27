"""Loop check: the last of the 5 checks.

Stops the agent (or a person) from hammering a target:
- the same command on the same target more than 3 times in 10 minutes,
- more than 20 actions in one minute,
- more than 200 runs in one assessment.

The API passes in the recent runs and the run count; this check never reads
the database.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from reconix_ai.harness.checks.result import ALLOWED, CheckOutcome, blocked


@dataclass(frozen=True)
class LoopLimits:
    """Default limits. Changing them needs a configuration approval (week 2)."""

    max_same_command: int = 3
    same_command_window: timedelta = timedelta(minutes=10)
    max_actions_per_minute: int = 20
    max_runs_per_assessment: int = 200


DEFAULT_LIMITS = LoopLimits()


class PastRun(Protocol):
    """The fields of the shared RecentRun this check needs."""

    @property
    def tool(self) -> str: ...
    @property
    def target(self) -> str: ...
    @property
    def arguments(self) -> Sequence[str]: ...
    @property
    def started_at(self) -> datetime: ...


def check_loop(
    tool: str,
    target: str,
    arguments: Sequence[str],
    recent_runs: Sequence[PastRun],
    runs_in_assessment: int,
    now: datetime,
    limits: LoopLimits = DEFAULT_LIMITS,
) -> CheckOutcome:
    if runs_in_assessment >= limits.max_runs_per_assessment:
        return blocked("RUN_LIMIT_REACHED")

    last_minute = [run for run in recent_runs if run.started_at >= now - timedelta(minutes=1)]
    if len(last_minute) >= limits.max_actions_per_minute:
        return blocked("TOO_MANY_ACTIONS")

    command = command_key(tool, target, arguments)
    same_command = [
        run
        for run in recent_runs
        if run.started_at >= now - limits.same_command_window
        and command_key(run.tool, run.target, run.arguments) == command
    ]
    if len(same_command) >= limits.max_same_command:
        return blocked("REPEATED_COMMAND")

    return ALLOWED


def command_key(tool: str, target: str, arguments: Sequence[str]) -> tuple:
    """Two commands count as the same even if the case, spacing or argument order differ."""
    return (
        tool.upper(),
        target.strip().lower(),
        tuple(sorted(argument.strip() for argument in arguments)),
    )
