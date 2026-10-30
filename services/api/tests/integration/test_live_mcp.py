"""The action flow against a running Kali MCP server: real harness, real call_tool.

Opt-in. Besides RECONIX_TEST_DATABASE_URL, set:

    RECONIX_TEST_MCP_URL=http://127.0.0.1:8096/mcp
    RECONIX_TEST_MCP_ACCESS_KEY=<the server's KALI_MCP_AUTH_TOKEN>

The container needs NET_RAW and NET_ADMIN, or nmap cannot start.
"""

import dataclasses
import os

import pytest
from fastapi.testclient import TestClient

from reconix_api.core.wiring import build_interfaces, build_mask_secrets
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_scope_flow import open_session

MCP_URL = os.environ.get("RECONIX_TEST_MCP_URL")
MCP_ACCESS_KEY = os.environ.get("RECONIX_TEST_MCP_ACCESS_KEY", "")

pytestmark = pytest.mark.skipif(
    not (MCP_URL and MCP_ACCESS_KEY), reason="RECONIX_TEST_MCP_URL is not set"
)


@pytest.fixture
def live_client(db_app, tmp_path):
    real = build_interfaces(
        audit_log_path=str(tmp_path / "audit.jsonl"), mcp_url=MCP_URL, mcp_access_key=MCP_ACCESS_KEY
    )
    db_app.state.interfaces = dataclasses.replace(
        db_app.state.interfaces,
        check=real.check,
        write_audit=real.write_audit,
        call_tool=real.call_tool,
    )
    db_app.state.mask_secrets = build_mask_secrets()
    return TestClient(db_app, base_url="http://127.0.0.1/api/v1")


KALI_ITSELF = "172.20.0.2"  # the only host on the dev network; its MCP port is open
LIVE_SCOPE = {
    "max_risk": "HIGH",
    "allowed_tools": ["NMAP"],
    "targets": [{"type": "ip", "value": KALI_ITSELF}],
}


def test_approved_nmap_runs_in_kali_and_saves_findings(live_client):
    headers = open_session(live_client)
    assessment_id = active_assessment(live_client, headers, LIVE_SCOPE)
    arguments = ["-Pn", "-sT", "-sV", "-p", "22,8096"]

    action = send(
        live_client, headers, assessment_id, tool="NMAP", target=KALI_ITSELF, arguments=arguments
    ).json()
    assert action["action_status"] == "PENDING", action
    approved = live_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )
    assert approved.status_code == 200, approved.json()

    action = live_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    [run] = action["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED", run["error"] or run
    assert "<nmaprun" in run["output_masked"]
    assert run["request_count"] == 2

    findings = live_client.get(
        "/findings", params={"assessment_id": assessment_id}, headers=headers
    ).json()
    assert [f["title"].split(" (")[0] for f in findings] == ["Open port 8096/tcp"]
    assert findings[0]["severity_status"] == "NONE"
