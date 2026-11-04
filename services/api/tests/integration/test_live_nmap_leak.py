"""Leak check against the real Kali MCP server: secrets a scanned host sends back must not
be saved in the tool run's output or in the evidence.

Opt-in, like test_live_mcp.py. Besides RECONIX_TEST_DATABASE_URL, RECONIX_TEST_MCP_URL and
RECONIX_TEST_MCP_ACCESS_KEY, set RECONIX_TEST_LEAK_TARGET to a lab host that answers on
port 80 with a fake cookie (FAKEcookie...) and a fake password (FAKEpass...).
"""

import os
import re

import pytest

from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_live_mcp import live_client  # noqa: F401 - the fixture
from tests.integration.test_scope_flow import open_session

TARGET = os.environ.get("RECONIX_TEST_LEAK_TARGET")
FAKE_SECRET = re.compile(r"FAKE(?:cookie|pass)\w*")

pytestmark = pytest.mark.skipif(
    not (TARGET and os.environ.get("RECONIX_TEST_MCP_ACCESS_KEY")),
    reason="RECONIX_TEST_LEAK_TARGET or the MCP key is not set",
)


def test_secrets_from_the_scanned_host_are_not_saved(live_client):  # noqa: F811
    headers = open_session(live_client)
    scope = {
        "max_risk": "HIGH",
        "allowed_tools": ["NMAP"],
        "targets": [{"type": "ip", "value": TARGET}],
    }
    assessment_id = active_assessment(live_client, headers, scope)

    action = send(
        live_client,
        headers,
        assessment_id,
        tool="NMAP",
        target=TARGET,
        arguments=["-Pn", "-sT", "-sV", "-sC", "-p", "80"],
    ).json()
    if action.get("action_status") == "PENDING":
        approved = live_client.post(
            f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
        )
        assert approved.status_code == 200, approved.json()
    action = live_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    [run] = action["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED", run["error"] or run

    findings = live_client.get(
        "/findings", params={"assessment_id": assessment_id}, headers=headers
    ).json()
    evidence = [
        proof["content"]
        for finding in findings
        for proof in live_client.get(f"/findings/{finding['finding_id']}", headers=headers).json()[
            "evidence"
        ]
    ]
    print(f"\nfindings: {[f['title'] for f in findings]}")
    leaks = {
        "output_masked": sorted(set(FAKE_SECRET.findall(run["output_masked"] or ""))),
        "evidence": sorted(set(FAKE_SECRET.findall(" ".join(evidence)))),
    }
    print(f"leaks: {leaks}")
    assert leaks == {"output_masked": [], "evidence": []}
