import json
from datetime import timedelta

import pytest

from reconix_ai.harness.checks.loop import DEFAULT_LIMITS, LoopLimits
from reconix_ai.harness.limits import (
    DEFAULT_LIMITS_JSON,
    LIMIT_RULES,
    LimitError,
    apply_limit_change,
    limits_from_json,
    limits_to_json,
    plan_limit_change,
)


def test_the_defaults_are_the_plan_limits() -> None:
    assert DEFAULT_LIMITS_JSON == {
        "max_same_command": 3,
        "same_command_window_minutes": 10,
        "max_actions_per_minute": 20,
        "max_runs_per_assessment": 200,
    }


def test_the_defaults_are_inside_the_bounds() -> None:
    assert limits_from_json(DEFAULT_LIMITS_JSON) == DEFAULT_LIMITS


def test_json_round_trip() -> None:
    limits = LoopLimits(
        max_same_command=5,
        same_command_window=timedelta(minutes=30),
        max_actions_per_minute=10,
        max_runs_per_assessment=500,
    )
    assert limits_from_json(limits_to_json(limits)) == limits


def test_a_change_lists_before_after_and_what_changed() -> None:
    change = plan_limit_change(DEFAULT_LIMITS, {"max_runs_per_assessment": 300})
    assert change.before == DEFAULT_LIMITS_JSON
    assert change.after == {**DEFAULT_LIMITS_JSON, "max_runs_per_assessment": 300}
    assert change.as_json() == {
        "setting": "loop_limits",
        "before": DEFAULT_LIMITS_JSON,
        "after": change.after,
        "changed": {"max_runs_per_assessment": {"from": 200, "to": 300}},
    }
    json.dumps(change.as_json())  # plain JSON, ready for config_change


def test_several_limits_at_once() -> None:
    change = plan_limit_change(
        DEFAULT_LIMITS, {"max_same_command": 1, "same_command_window_minutes": 60}
    )
    assert set(change.as_json()["changed"]) == {"max_same_command", "same_command_window_minutes"}


@pytest.mark.parametrize("name", list(LIMIT_RULES))
def test_the_bounds_themselves_are_allowed(name: str) -> None:
    rule = LIMIT_RULES[name]
    for value in (rule.lowest, rule.highest):
        if DEFAULT_LIMITS_JSON[name] != value:
            assert plan_limit_change(DEFAULT_LIMITS, {name: value}).after[name] == value


@pytest.mark.parametrize("name", list(LIMIT_RULES))
def test_outside_the_bounds_is_refused(name: str) -> None:
    rule = LIMIT_RULES[name]
    for value in (0, -1, rule.lowest - 1, rule.highest + 1, 10**9):
        with pytest.raises(LimitError) as error:
            plan_limit_change(DEFAULT_LIMITS, {name: value})
        assert (error.value.code, error.value.name) == ("OUT_OF_RANGE", name)


@pytest.mark.parametrize("value", [True, False, 3.0, "5", None, [5], {"n": 5}])
def test_only_whole_numbers_are_allowed(value) -> None:
    with pytest.raises(LimitError) as error:
        plan_limit_change(DEFAULT_LIMITS, {"max_same_command": value})
    assert error.value.code == "NOT_A_NUMBER"


@pytest.mark.parametrize("name", ["max_risk", "role", "same_command_window", ""])
def test_unknown_names_are_refused(name: str) -> None:
    with pytest.raises(LimitError) as error:
        plan_limit_change(DEFAULT_LIMITS, {name: 5})
    assert (error.value.code, error.value.name) == ("UNKNOWN_LIMIT", name)


@pytest.mark.parametrize("wanted", [{}, {"max_same_command": 3}])
def test_asking_for_the_same_limits_is_refused(wanted) -> None:
    with pytest.raises(LimitError) as error:
        plan_limit_change(DEFAULT_LIMITS, wanted)
    assert error.value.code == "NO_CHANGE"


@pytest.mark.parametrize("wanted", [None, [("max_same_command", 5)], "max_same_command=5"])
def test_a_change_that_is_not_a_dict_is_refused(wanted) -> None:
    with pytest.raises(LimitError) as error:
        plan_limit_change(DEFAULT_LIMITS, wanted)
    assert error.value.code == "BAD_CHANGE"


def test_an_approved_change_gives_the_new_limits() -> None:
    change = plan_limit_change(DEFAULT_LIMITS, {"max_actions_per_minute": 5})
    stored = json.loads(json.dumps(change.as_json()))  # as the database gives it back
    new_limits = apply_limit_change(DEFAULT_LIMITS, stored)
    assert new_limits == LoopLimits(max_actions_per_minute=5)


def test_an_old_approval_cannot_undo_a_newer_change() -> None:
    first = plan_limit_change(DEFAULT_LIMITS, {"max_runs_per_assessment": 300})
    second = plan_limit_change(DEFAULT_LIMITS, {"max_runs_per_assessment": 50})
    now = apply_limit_change(DEFAULT_LIMITS, second.as_json())
    with pytest.raises(LimitError) as error:
        apply_limit_change(now, first.as_json())
    assert error.value.code == "LIMITS_CHANGED"


def test_an_approved_change_is_checked_again() -> None:
    change = plan_limit_change(DEFAULT_LIMITS, {"max_runs_per_assessment": 300}).as_json()
    change["after"] = {**change["after"], "max_runs_per_assessment": 999_999}  # edited by hand
    with pytest.raises(LimitError) as error:
        apply_limit_change(DEFAULT_LIMITS, change)
    assert error.value.code == "OUT_OF_RANGE"


@pytest.mark.parametrize(
    "config_change",
    [
        None,
        {},
        {"setting": "llm_provider", "before": DEFAULT_LIMITS_JSON, "after": DEFAULT_LIMITS_JSON},
        {"setting": "loop_limits", "after": DEFAULT_LIMITS_JSON},
        {"setting": "loop_limits", "before": DEFAULT_LIMITS_JSON, "after": "300"},
    ],
)
def test_a_broken_config_change_is_refused(config_change) -> None:
    with pytest.raises(LimitError) as error:
        apply_limit_change(DEFAULT_LIMITS, config_change)
    assert error.value.code == "BAD_CHANGE"


def test_saved_limits_with_a_missing_name_are_refused() -> None:
    saved = {key: value for key, value in DEFAULT_LIMITS_JSON.items() if key != "max_same_command"}
    with pytest.raises(LimitError) as error:
        limits_from_json(saved)
    assert (error.value.code, error.value.name) == ("NOT_A_NUMBER", "max_same_command")
