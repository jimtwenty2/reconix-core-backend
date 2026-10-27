import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    CheckName,
    CheckResult,
    Decision,
    RiskLevel,
    ToolName,
)
from reconix_api.services.actions import NextStep, action_hash, ensure_unchanged, next_step

ACTION = Action(tool=ToolName.NMAP, target="172.20.0.5", arguments=["-sV"])


def test_hash_is_stable():
    same = Action(tool=ToolName.NMAP, target="172.20.0.5", arguments=["-sV"])
    assert action_hash(ACTION) == action_hash(same)
    assert len(action_hash(ACTION)) == 64


@pytest.mark.parametrize(
    "changed",
    [
        ACTION.model_copy(update={"target": "172.20.0.6"}),
        ACTION.model_copy(update={"arguments": ["-sV", "-p-"]}),
        ACTION.model_copy(update={"tool": ToolName.NUCLEI}),
    ],
)
def test_any_change_changes_the_hash(changed):
    assert action_hash(changed) != action_hash(ACTION)
    with pytest.raises(ApiError) as error:
        ensure_unchanged(action_hash(ACTION), changed)
    assert error.value.code == "ACTION_CHANGED"


def test_unchanged_action_passes():
    ensure_unchanged(action_hash(ACTION), ACTION)


def test_blocked_action_is_422():
    result = CheckResult(
        decision=Decision.BLOCKED, risk=RiskLevel.HIGH, blocked_by=CheckName.SCOPE, reason="X"
    )
    with pytest.raises(ApiError) as error:
        next_step(result)
    assert error.value.status == 422
    assert error.value.details["blocked_by"] == CheckName.SCOPE


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (RiskLevel.LOW, NextStep.RUN_NOW),
        (RiskLevel.MEDIUM, NextStep.NEEDS_APPROVAL),
        (RiskLevel.HIGH, NextStep.NEEDS_APPROVAL),
    ],
)
def test_allowed_action_next_step(risk, expected):
    assert next_step(CheckResult(decision=Decision.ALLOW, risk=risk)) == expected
