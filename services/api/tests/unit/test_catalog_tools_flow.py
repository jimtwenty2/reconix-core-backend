"""Any Kali catalog tool goes through every step, not only the original five
(NMAP, NUCLEI, ZAP, SEMGREP, GITLEAKS): scope, action, saved row, harness check,
MCP call and the findings filter. No database, no network."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from reconix_api.clients.mcp import McpError, tool_call
from reconix_api.core.interfaces import (
    ApprovedScope,
    ChatScope,
    CheckContext,
    Decision,
    Operator,
    ToolJob,
)
from reconix_api.core.wiring import check
from reconix_api.models import Action as ActionRow
from reconix_api.schemas.actions import ActionIn
from reconix_api.schemas.findings import FindingFilters
from reconix_api.schemas.scopes import ScopeDraft, ScopeTargetIn
from reconix_api.services.actions import to_action

# tool as a person might write it, target, arguments
CASES = [
    ("NMAP", "172.20.0.5", ["-sV", "-Pn"]),
    ("masscan", "172.20.0.0/24", []),
    ("rustscan", "172.20.0.5", []),
    ("sqlmap", "http://172.20.0.5:3000/?id=1", ["--batch"]),
    ("whatweb", "http://172.20.0.5:3000/", []),
    ("nikto", "http://172.20.0.5:3000/", []),
    ("hydra", "172.20.0.5", []),
    ("trivy", "/workspace/code/s1", []),
]
TOOLS = [tool for tool, _, _ in CASES]
UPPER = [tool.upper() for tool in TOOLS]


def approved_scope() -> ApprovedScope:
    now = datetime.now(UTC)
    return ApprovedScope(
        assessment_id=uuid4(),
        ip_ranges=["172.20.0.0/24"],
        url_prefixes=["http://172.20.0.5:3000/"],
        repo_paths=["/workspace/code/s1"],
        allowed_tools=TOOLS,
        max_risk="HIGH",
        window_start=now - timedelta(hours=1),
        window_end=now + timedelta(hours=1),
    )


def test_scope_draft_takes_catalog_tools_and_saves_them_uppercase():
    draft = ScopeDraft(allowed_tools=TOOLS, targets=[ScopeTargetIn(type="ip", value="172.20.0.5")])
    assert draft.allowed_tools == UPPER


def test_shared_scopes_take_catalog_tools():
    assert approved_scope().allowed_tools == UPPER
    assert ChatScope(status="DRAFT", allowed_tools=TOOLS).allowed_tools == UPPER


@pytest.mark.parametrize(("tool", "target", "arguments"), CASES)
def test_a_catalog_tool_goes_through_every_step(tool, target, arguments):
    saved = ActionIn(tool=tool, target=target, arguments=arguments).tool
    assert saved == tool.upper()

    action = to_action(ActionRow(tool=saved, target=target, args=arguments, purpose="scan"))
    assert action.tool == saved

    scope = approved_scope()
    context = CheckContext(
        operator=Operator(session_id=uuid4(), actor="t"),
        scope=scope,
        now=scope.window_start + timedelta(minutes=30),
    )
    result = check(action, context)
    assert result.decision == Decision.ALLOW, result.reason

    name, args = tool_call(
        ToolJob(tool_run_id=uuid4(), tool=saved, target=target, arguments=arguments, job_token="x")
    )
    assert name == tool.lower()
    assert target in args.values()

    assert FindingFilters(tool=saved).tool == saved


def test_a_tool_outside_the_scope_is_still_blocked():
    scope = approved_scope().model_copy(update={"allowed_tools": ["NMAP"]})
    action = to_action(ActionRow(tool="MASSCAN", target="172.20.0.5", args=[], purpose="scan"))
    context = CheckContext(
        operator=Operator(session_id=uuid4(), actor="t"), scope=scope, now=datetime.now(UTC)
    )
    result = check(action, context)
    assert result.decision == Decision.BLOCKED
    assert result.reason == "TOOL_NOT_ALLOWED"


def test_a_tool_outside_the_catalog_is_refused():
    with pytest.raises(ValueError, match="Kali catalog"):
        ActionIn(tool="not_a_tool", target="172.20.0.5")


def test_arguments_for_a_tool_without_options_are_refused_not_dropped():
    job = ToolJob(
        tool_run_id=uuid4(),
        tool="MASSCAN",
        target="172.20.0.5",
        arguments=["--rate", "100"],
        job_token="x",
    )
    with pytest.raises(McpError, match="TOOL_TAKES_NO_OPTIONS"):
        tool_call(job)
