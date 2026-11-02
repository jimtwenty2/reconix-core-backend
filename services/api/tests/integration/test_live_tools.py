"""Each of the 5 tools, one by one, through the real Kali MCP server and the real parsers:
scope -> action -> harness check -> approval -> call_tool -> masking -> findings.

Opt-in, like test_live_mcp.py. Besides RECONIX_TEST_DATABASE_URL, RECONIX_TEST_MCP_URL and
RECONIX_TEST_MCP_ACCESS_KEY, set:

    RECONIX_TEST_LEAK_TARGET   a lab host that answers on port 80 with a fake cookie
                               (FAKEcookie...) and a fake password (FAKEpass...)
    RECONIX_TEST_CODE_PATH     a folder under /workspace/code in the Kali container that
                               holds code with fake secrets (FAKE...)

Run one tool with -k, e.g. -k nmap. Every test prints what the tool found.
"""

import os
import re

import pytest

from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_live_mcp import live_client  # noqa: F401 - the fixture
from tests.integration.test_scope_flow import open_session

HOST = os.environ.get("RECONIX_TEST_LEAK_TARGET", "")
CODE_PATH = os.environ.get("RECONIX_TEST_CODE_PATH", "")
FAKE_SECRET = re.compile(r"FAKE[A-Za-z0-9_]*")

pytestmark = pytest.mark.skipif(
    not (HOST and os.environ.get("RECONIX_TEST_MCP_ACCESS_KEY")),
    reason="RECONIX_TEST_LEAK_TARGET or the MCP key is not set",
)


def run_tool(client, tool: str, target: str, scope_target: dict, arguments: list[str]):
    """One approved action; returns its tool run and the findings with their evidence."""
    headers = open_session(client)
    scope = {"max_risk": "HIGH", "allowed_tools": [tool], "targets": [scope_target]}
    assessment_id = active_assessment(client, headers, scope)
    response = send(client, headers, assessment_id, tool=tool, target=target, arguments=arguments)
    action = response.json()
    assert response.status_code == 201, action
    if action["action_status"] == "PENDING":
        decision = {"typed_target": target} if action["risk_level"] == "HIGH" else {}
        approved = client.post(
            f"/approvals/{action['approval_id']}/approve", json=decision, headers=headers
        )
        assert approved.status_code == 200, approved.json()
    action = client.get(f"/actions/{action['action_id']}", headers=headers).json()
    [run] = action["tool_runs"]
    found = client.get("/findings", params={"assessment_id": assessment_id}, headers=headers)
    findings = [
        client.get(f"/findings/{finding['finding_id']}", headers=headers).json()
        for finding in found.json()
    ]
    report(tool, run, findings)
    return run, findings


def report(tool: str, run: dict, findings: list[dict]) -> None:
    print(f"\n=== {tool}: {run['tool_run_status']}, error={run['error']!r}")
    print(f"    output: {len(run['output_masked'] or '')} chars, masked={run['masked_count']}")
    for finding in findings:
        print(f"    - [{finding['severity_status']}] {finding['title']}")


def assert_no_leak(run: dict, findings: list[dict]) -> None:
    evidence = " ".join(e["content"] for f in findings for e in f["evidence"])
    leaks = {
        "output_masked": sorted(set(FAKE_SECRET.findall(run["output_masked"] or ""))),
        "evidence": sorted(set(FAKE_SECRET.findall(evidence))),
    }
    print(f"    leaks: {leaks}")
    assert leaks == {"output_masked": [], "evidence": []}


def test_nmap(live_client):  # noqa: F811
    run, findings = run_tool(
        live_client,
        "NMAP",
        HOST,
        {"type": "ip", "value": HOST},
        ["-Pn", "-sT", "-sV", "-sC", "-p", "80"],
    )
    assert run["tool_run_status"] == "COMPLETED"
    assert [f["title"].split(" (")[0] for f in findings] == ["Open port 80/tcp"]
    assert_no_leak(run, findings)


def test_nuclei(live_client):  # noqa: F811
    url = f"http://{HOST}/"
    arguments = ["-severity", "info,low,medium,high,critical", "-tags", "tech,misconfig"]
    run, findings = run_tool(live_client, "NUCLEI", url, {"type": "url", "value": url}, arguments)
    assert run["tool_run_status"] == "COMPLETED"
    assert_no_leak(run, findings)


def test_zap(live_client):  # noqa: F811
    url = f"http://{HOST}/"
    run, findings = run_tool(live_client, "ZAP", url, {"type": "url", "value": url}, [])
    assert run["tool_run_status"] == "COMPLETED"
    assert_no_leak(run, findings)


@pytest.mark.skipif(not CODE_PATH, reason="RECONIX_TEST_CODE_PATH is not set")
def test_semgrep(live_client):  # noqa: F811
    run, findings = run_tool(
        live_client, "SEMGREP", CODE_PATH, {"type": "path", "value": CODE_PATH}, []
    )
    assert run["tool_run_status"] == "COMPLETED"
    assert_no_leak(run, findings)


@pytest.mark.skipif(not CODE_PATH, reason="RECONIX_TEST_CODE_PATH is not set")
def test_gitleaks(live_client):  # noqa: F811
    run, findings = run_tool(
        live_client, "GITLEAKS", CODE_PATH, {"type": "path", "value": CODE_PATH}, []
    )
    assert run["tool_run_status"] == "COMPLETED"
    assert findings, "gitleaks found none of the fake secrets"
    assert_no_leak(run, findings)
