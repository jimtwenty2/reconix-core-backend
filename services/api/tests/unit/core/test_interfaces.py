"""The fakes must behave like the real parts will, so the API tests mean something."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentTask,
    ApprovedScope,
    CheckContext,
    CheckName,
    Decision,
    ResumeInput,
    RiskLevel,
    ToolJob,
    ToolName,
    ToolRunStatus,
)
from tests.fakes import OPERATOR_TOKEN, build_fake_interfaces


def make_scope(**overrides) -> ApprovedScope:
    values = {
        "assessment_id": uuid4(),
        "ip_ranges": ["172.20.0.0/24"],
        "domains": ["juice-shop.lab"],
        "excluded_targets": ["172.20.0.1"],
        "allowed_tools": [ToolName.NMAP, ToolName.NUCLEI],
        "max_risk": RiskLevel.MEDIUM,
    }
    values.update(overrides)
    return ApprovedScope(**values)


def make_context(scope: ApprovedScope) -> CheckContext:
    interfaces, _ = build_fake_interfaces()
    operator = interfaces.get_operator(OPERATOR_TOKEN)
    return CheckContext(operator=operator, scope=scope, now=datetime.now(UTC))


def test_get_operator_refuses_unknown_token():
    interfaces, _ = build_fake_interfaces()
    with pytest.raises(PermissionError):
        interfaces.get_operator("nope")


def test_get_approved_scope_needs_an_approved_scope():
    interfaces, parts = build_fake_interfaces()
    scope = make_scope()
    with pytest.raises(LookupError):
        interfaces.get_approved_scope(scope.assessment_id)
    parts["scopes"].add(scope)
    assert interfaces.get_approved_scope(scope.assessment_id) == scope


@pytest.mark.parametrize(
    ("action", "blocked_by", "reason"),
    [
        (Action(tool=ToolName.NMAP, target="10.0.0.5"), CheckName.SCOPE, "TARGET_OUT_OF_SCOPE"),
        (Action(tool=ToolName.NMAP, target="172.20.0.1"), CheckName.SCOPE, "TARGET_OUT_OF_SCOPE"),
        (Action(tool=ToolName.ZAP, target="172.20.0.5"), CheckName.SCOPE, "TOOL_NOT_ALLOWED"),
        (
            Action(tool=ToolName.NMAP, target="172.20.0.5", arguments=["-sV;id"]),
            CheckName.COMMAND,
            "SHELL_CHARACTERS",
        ),
    ],
)
def test_check_blocks(action, blocked_by, reason):
    interfaces, _ = build_fake_interfaces()
    result = interfaces.check(action, make_context(make_scope()))
    assert result.decision == Decision.BLOCKED
    assert result.blocked_by == blocked_by
    assert result.reason == reason


def test_check_blocks_risk_above_scope_max():
    interfaces, _ = build_fake_interfaces()
    scope = make_scope(max_risk=RiskLevel.LOW)
    result = interfaces.check(
        Action(tool=ToolName.NUCLEI, target="172.20.0.5"), make_context(scope)
    )
    assert result.blocked_by == CheckName.RISK


def test_check_allows_and_rates_risk():
    interfaces, _ = build_fake_interfaces()
    context = make_context(make_scope())
    assert interfaces.check(Action(tool=ToolName.NMAP, target="172.20.0.5"), context).risk == (
        RiskLevel.LOW
    )
    validation = Action(tool=ToolName.NMAP, target="172.20.0.5", is_validation=True)
    result = interfaces.check(validation, context)
    assert result.decision == Decision.ALLOW
    assert result.risk == RiskLevel.MEDIUM  # a validation is at least MEDIUM


async def test_ask_agent_suggests_one_step():
    interfaces, _ = build_fake_interfaces()
    scope = make_scope()
    run_id = uuid4()
    response = await interfaces.ask_agent(
        AgentRequest(
            task=AgentTask.PLAN,
            assessment_id=scope.assessment_id,
            agent_run_id=run_id,
            scope=scope,
        )
    )
    assert response.proposed_action is not None
    assert response.proposed_action.tool == ToolName.NMAP
    assert response.waiting
    assert response.agent_run_id == run_id


async def test_ask_agent_resume_gives_the_decision_and_no_new_step():
    interfaces, _ = build_fake_interfaces()
    scope = make_scope()
    request = AgentRequest(
        task=AgentTask.SUGGEST,
        assessment_id=scope.assessment_id,
        agent_run_id=uuid4(),
        scope=scope,
    )
    planned = await interfaces.ask_agent(request)
    resume = ResumeInput(
        agent_run_id=request.agent_run_id,
        assessment_id=scope.assessment_id,
        approval_id=uuid4(),
        action=planned.proposed_action,
        decision="REJECTED",
    )
    response = await interfaces.ask_agent(request.model_copy(update={"resume": resume}))
    assert response.decision == "REJECTED"
    assert response.proposed_action is None
    assert not response.waiting


async def test_call_tool_accepts_a_token_once():
    interfaces, parts = build_fake_interfaces()
    job = ToolJob(
        tool_run_id=uuid4(), tool=ToolName.NMAP, target="172.20.0.5", arguments=[], job_token="t1"
    )
    with pytest.raises(PermissionError):
        await interfaces.call_tool(job)  # never issued

    parts["mcp"].expect_token("t1")
    result = await interfaces.call_tool(job)
    assert result.status == ToolRunStatus.COMPLETED
    assert "172.20.0.5" in result.stdout

    with pytest.raises(PermissionError):
        await interfaces.call_tool(job)  # already used


async def test_call_tool_reports_container_down():
    interfaces, parts = build_fake_interfaces()
    parts["mcp"].down = True
    job = ToolJob(
        tool_run_id=uuid4(), tool=ToolName.NMAP, target="172.20.0.5", arguments=[], job_token="t"
    )
    with pytest.raises(ConnectionError):
        await interfaces.call_tool(job)
