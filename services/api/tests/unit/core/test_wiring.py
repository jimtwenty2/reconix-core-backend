import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    ApprovedScope,
    AuditEvent,
    CheckContext,
    CheckName,
    Decision,
    LoopLimitSettings,
    Operator,
    RiskLevel,
    ToolName,
)
from reconix_api.core.wiring import build_interfaces, build_mask_secrets


def _context(scope: ApprovedScope) -> CheckContext:
    operator = Operator(session_id=uuid4(), actor="operator")
    return CheckContext(operator=operator, scope=scope, now=datetime.now(UTC))


def test_parts_not_merged_yet_say_so():
    interfaces = build_interfaces()
    with pytest.raises(ApiError) as error:
        interfaces.write_audit(None)
    assert error.value.status == 503
    assert error.value.details == {"part": "write_audit"}


async def test_the_agent_needs_settings_to_read_provider_keys():
    interfaces = build_interfaces(session_factory=object(), database_url="postgresql://unused")
    with pytest.raises(ApiError) as error:
        await interfaces.ask_agent(None)
    assert error.value.details == {"part": "ask_agent"}


def test_check_is_the_real_harness():
    scope = ApprovedScope(
        assessment_id=uuid4(),
        ip_ranges=["172.20.0.0/24"],
        allowed_tools=[ToolName.NMAP],
        max_risk=RiskLevel.HIGH,
    )
    action = Action(tool=ToolName.NMAP, target="10.9.9.9", arguments=["-sV"])

    result = build_interfaces().check(action, _context(scope))

    assert result.decision == Decision.BLOCKED
    assert result.blocked_by == CheckName.SCOPE


def test_write_audit_appends_one_masked_line(tmp_path):
    path = tmp_path / "audit.jsonl"
    interfaces = build_interfaces(audit_log_path=str(path))
    event = AuditEvent(
        event_type="SESSION_OPENED",
        assessment_id=None,
        session_id=uuid4(),
        actor="operator",
        at=datetime.now(UTC),
        details={"note": "password=hunter2"},
    )

    interfaces.write_audit(event)

    lines = path.read_text().splitlines()
    assert len(lines) == 1
    assert "hunter2" not in lines[0]
    assert json.loads(lines[0])["event_type"] == "SESSION_OPENED"


def test_mask_secrets_hides_a_password():
    masked, hidden = build_mask_secrets()("password=hunter2")
    assert "hunter2" not in masked
    assert hidden == 1


def test_check_uses_the_approved_loop_limits():
    scope = ApprovedScope(
        assessment_id=uuid4(),
        ip_ranges=["172.20.0.0/24"],
        allowed_tools=[ToolName.NMAP],
        max_risk=RiskLevel.HIGH,
    )
    action = Action(tool=ToolName.NMAP, target="172.20.0.5", arguments=["-sV"])
    context = _context(scope).model_copy(update={"runs_in_assessment": 5})
    limits = LoopLimitSettings(
        max_same_command=3,
        same_command_window_minutes=10,
        max_actions_per_minute=20,
        max_runs_per_assessment=5,
    )

    default = build_interfaces().check(action, context)
    limited = build_interfaces().check(action, context.model_copy(update={"loop_limits": limits}))

    assert default.decision != Decision.BLOCKED  # 5 runs is under the default 200
    assert (limited.decision, limited.blocked_by) == (Decision.BLOCKED, CheckName.LOOP)
    assert limited.reason == "RUN_LIMIT_REACHED"
