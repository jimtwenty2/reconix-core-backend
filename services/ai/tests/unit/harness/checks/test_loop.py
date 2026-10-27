from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from reconix_ai.harness.checks.loop import LoopLimits, check_loop
from reconix_ai.harness.checks.result import Decision

NOW = datetime(2026, 10, 26, 14, 0, tzinfo=UTC)
TARGET = "172.20.0.5"
ARGUMENTS = ["-sV", "-p", "80,443"]


@dataclass(frozen=True)
class Run:
    """Same fields as the shared RecentRun."""

    started_at: datetime
    tool: str = "NMAP"
    target: str = TARGET
    arguments: list[str] = field(default_factory=lambda: list(ARGUMENTS))


def minutes_ago(minutes: float) -> datetime:
    return NOW - timedelta(minutes=minutes)


def check(recent_runs: list[Run], runs_in_assessment: int = 0, **changes) -> str | None:
    """Run the loop check for the default nmap action and return the block reason, or None."""
    action = {"tool": "NMAP", "target": TARGET, "arguments": ARGUMENTS} | changes
    outcome = check_loop(
        recent_runs=recent_runs,
        runs_in_assessment=runs_in_assessment,
        now=NOW,
        **action,
    )
    if outcome.decision == Decision.ALLOW:
        return None
    return outcome.reason


# --- allowed ---------------------------------------------------------------


def test_first_run_is_allowed() -> None:
    assert check([]) is None


def test_third_run_of_the_same_command_is_allowed() -> None:
    assert check([Run(minutes_ago(1)), Run(minutes_ago(5))]) is None


# --- same command on the same target ---------------------------------------


def test_fourth_run_in_ten_minutes_is_blocked() -> None:
    runs = [Run(minutes_ago(1)), Run(minutes_ago(4)), Run(minutes_ago(9))]
    assert check(runs) == "REPEATED_COMMAND"


def test_runs_older_than_ten_minutes_do_not_count() -> None:
    runs = [Run(minutes_ago(1)), Run(minutes_ago(4)), Run(minutes_ago(11))]
    assert check(runs) is None


def test_run_exactly_ten_minutes_ago_still_counts() -> None:
    runs = [Run(minutes_ago(1)), Run(minutes_ago(4)), Run(minutes_ago(10))]
    assert check(runs) == "REPEATED_COMMAND"


def test_case_spacing_and_argument_order_do_not_hide_a_repeat() -> None:
    runs = [
        Run(minutes_ago(1), tool="nmap"),
        Run(minutes_ago(2), target=" 172.20.0.5 "),
        Run(minutes_ago(3), arguments=["80,443", "-p", "-sV"]),
    ]
    assert check(runs) == "REPEATED_COMMAND"


def test_domain_case_does_not_hide_a_repeat() -> None:
    runs = [Run(minutes_ago(m), target="Juice-Shop.LAB") for m in (1, 2, 3)]
    assert check(runs, target="juice-shop.lab") == "REPEATED_COMMAND"


def test_different_target_is_not_a_repeat() -> None:
    runs = [Run(minutes_ago(m), target="172.20.0.6") for m in (1, 2, 3)]
    assert check(runs) is None


def test_different_arguments_are_not_a_repeat() -> None:
    runs = [Run(minutes_ago(m), arguments=["-sV"]) for m in (1, 2, 3)]
    assert check(runs) is None


def test_different_tool_is_not_a_repeat() -> None:
    runs = [Run(minutes_ago(m), tool="NUCLEI") for m in (1, 2, 3)]
    assert check(runs) is None


# --- actions per minute ----------------------------------------------------


def different_runs(count: int, minutes: float) -> list[Run]:
    """`count` runs on different targets, so only the per-minute limit applies."""
    return [Run(minutes_ago(minutes), target=f"172.20.0.{i}") for i in range(10, 10 + count)]


def test_twentieth_action_in_a_minute_is_allowed() -> None:
    assert check(different_runs(19, minutes=0.5)) is None


def test_twenty_first_action_in_a_minute_is_blocked() -> None:
    assert check(different_runs(20, minutes=0.5)) == "TOO_MANY_ACTIONS"


def test_actions_older_than_a_minute_do_not_count() -> None:
    assert check(different_runs(20, minutes=2)) is None


# --- runs per assessment ---------------------------------------------------


def test_two_hundredth_run_is_allowed() -> None:
    assert check([], runs_in_assessment=199) is None


def test_two_hundred_first_run_is_blocked() -> None:
    assert check([], runs_in_assessment=200) == "RUN_LIMIT_REACHED"


def test_assessment_limit_is_checked_first() -> None:
    runs = [Run(minutes_ago(m)) for m in (1, 2, 3)]
    assert check(runs, runs_in_assessment=200) == "RUN_LIMIT_REACHED"


# --- custom limits ---------------------------------------------------------


def test_limits_can_be_changed() -> None:
    strict = LoopLimits(max_same_command=1, max_actions_per_minute=5, max_runs_per_assessment=10)
    outcome = check_loop("NMAP", TARGET, ARGUMENTS, [Run(minutes_ago(1))], 0, NOW, strict)
    assert outcome.reason == "REPEATED_COMMAND"
    outcome = check_loop("NMAP", TARGET, ARGUMENTS, [], 10, NOW, strict)
    assert outcome.reason == "RUN_LIMIT_REACHED"
