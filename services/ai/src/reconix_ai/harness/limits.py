"""Limit settings: changing a loop limit needs a `configuration` approval.

The loop check uses LoopLimits. A person may change them, but only inside fixed
bounds, so no approval can switch the check off. The API uses this file like this:

    change = plan_limit_change(current, {"max_runs_per_assessment": 300})
    # save a configuration approval: config_change = change.as_json()
    ...
    # after it is approved, and before saving the new limits:
    new_limits = apply_limit_change(current, approval.config_change)
    check(action, context, new_limits)

apply_limit_change() refuses when the limits changed after the request was made,
so an old approval can never undo a newer change. Until a change is approved,
the old limits stay in use.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from reconix_ai.harness.checks.loop import DEFAULT_LIMITS, LoopLimits


@dataclass(frozen=True)
class LimitRule:
    lowest: int
    highest: int


# The names as they appear in JSON (the window in whole minutes) and their bounds.
# The defaults (3, 10, 20, 200) are the plan's limits.
LIMIT_RULES: dict[str, LimitRule] = {
    "max_same_command": LimitRule(1, 10),
    "same_command_window_minutes": LimitRule(1, 60),
    "max_actions_per_minute": LimitRule(1, 60),
    "max_runs_per_assessment": LimitRule(1, 1000),
}


class LimitError(Exception):
    """code: UNKNOWN_LIMIT, NOT_A_NUMBER, OUT_OF_RANGE, NO_CHANGE, BAD_CHANGE or
    LIMITS_CHANGED. name: the limit it is about, if any."""

    def __init__(self, code: str, name: str | None = None) -> None:
        super().__init__(f"{code}: {name}" if name else code)
        self.code = code
        self.name = name


@dataclass(frozen=True)
class LimitChange:
    before: dict[str, int]  # every limit, as it was when the change was asked for
    after: dict[str, int]  # every limit, as it will be once approved

    def as_json(self) -> dict[str, Any]:
        """For the approval's config_change and subject_snapshot; no secrets in it."""
        changed = {
            name: {"from": self.before[name], "to": self.after[name]}
            for name in LIMIT_RULES
            if self.before[name] != self.after[name]
        }
        return {
            "setting": "loop_limits",
            "before": self.before,
            "after": self.after,
            "changed": changed,
        }


def limits_to_json(limits: LoopLimits) -> dict[str, int]:
    return {
        "max_same_command": limits.max_same_command,
        "same_command_window_minutes": int(limits.same_command_window.total_seconds() // 60),
        "max_actions_per_minute": limits.max_actions_per_minute,
        "max_runs_per_assessment": limits.max_runs_per_assessment,
    }


def limits_from_json(data: Mapping[str, Any]) -> LoopLimits:
    """Every limit, checked against its bounds. Use it to load saved limits too."""
    if not isinstance(data, Mapping):
        raise LimitError("BAD_CHANGE")
    for name in data:
        if name not in LIMIT_RULES:
            raise LimitError("UNKNOWN_LIMIT", str(name))
    values = {name: checked_value(name, data.get(name)) for name in LIMIT_RULES}
    return LoopLimits(
        max_same_command=values["max_same_command"],
        same_command_window=timedelta(minutes=values["same_command_window_minutes"]),
        max_actions_per_minute=values["max_actions_per_minute"],
        max_runs_per_assessment=values["max_runs_per_assessment"],
    )


def plan_limit_change(current: LoopLimits, wanted: Mapping[str, Any]) -> LimitChange:
    """Check a requested change. `wanted` holds only the limits to change."""
    if not isinstance(wanted, Mapping):
        raise LimitError("BAD_CHANGE")
    before = limits_to_json(current)
    after = limits_to_json(limits_from_json({**before, **wanted}))
    if after == before:
        raise LimitError("NO_CHANGE")
    return LimitChange(before=before, after=after)


def apply_limit_change(current: LoopLimits, config_change: Mapping[str, Any]) -> LoopLimits:
    """The new limits from an approved change. Refused if the limits moved since."""
    if not isinstance(config_change, Mapping) or config_change.get("setting") != "loop_limits":
        raise LimitError("BAD_CHANGE")
    before, after = config_change.get("before"), config_change.get("after")
    if not isinstance(before, Mapping) or not isinstance(after, Mapping):
        raise LimitError("BAD_CHANGE")
    if limits_to_json(limits_from_json(before)) != limits_to_json(current):
        raise LimitError("LIMITS_CHANGED")
    return limits_from_json(after)


def checked_value(name: str, value: Any) -> int:
    # bool is an int in Python; True must not mean 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise LimitError("NOT_A_NUMBER", name)
    rule = LIMIT_RULES[name]
    if not rule.lowest <= value <= rule.highest:
        raise LimitError("OUT_OF_RANGE", name)
    return value


DEFAULT_LIMITS_JSON = limits_to_json(DEFAULT_LIMITS)
