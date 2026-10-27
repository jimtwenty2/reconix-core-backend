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
    Operator,
    RiskLevel,
    Role,
    ToolName,
)
from reconix_api.core.wiring import build_interfaces, build_mask_secrets


def _context(scope: ApprovedScope) -> CheckContext:
    operator = Operator(session_id=uuid4(), role=Role.OPERATOR, actor="operator")
    return CheckContext(operator=operator, scope=scope, now=datetime.now(UTC))


def test_parts_not_merged_yet_say_so():
    interfaces = build_interfaces()
    with pytest.raises(ApiError) as error:
        interfaces.write_audit(None)
    assert error.value.status == 503
    assert error.value.details == {"part": "write_audit"}


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
        role=Role.OPERATOR,
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
