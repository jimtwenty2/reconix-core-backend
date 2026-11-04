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
from reconix_api.models import Action as ActionRow
from reconix_api.schemas.actions import ActionIn
from reconix_api.services.actions import (
    NextStep,
    action_hash,
    ensure_unchanged,
    masked_snapshot,
    next_step,
    to_action,
)
from tests.fakes import fake_mask_secrets

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


def test_the_masked_copy_hides_secrets_in_target_and_arguments():
    """A blocked action is saved as this copy, so a pasted secret never reaches the database."""
    action = Action(
        tool=ToolName.GITLEAKS, target="password=hunter22", arguments=["--log-opts", "token=abc123"]
    )
    snapshot = masked_snapshot(action, fake_mask_secrets)
    assert "hunter22" not in snapshot["target"]
    assert snapshot["arguments"][0] == "--log-opts"
    assert "abc123" not in snapshot["arguments"][1]


def test_a_saved_catalog_tool_becomes_an_action():
    row = ActionRow(tool="MASSCAN", target="172.20.0.0/24", args=["--rate", "100"], purpose="scan")
    assert to_action(row).tool == "MASSCAN"


@pytest.mark.parametrize(("sent", "saved"), [("masscan", "MASSCAN"), ("NMAP", "NMAP")])
def test_action_in_saves_the_tool_uppercase(sent, saved):
    assert ActionIn(tool=sent, target="172.20.0.5").tool == saved
