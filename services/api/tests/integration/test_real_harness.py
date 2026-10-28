"""The action flow with the real harness: check(), masking and the audit log. MCP is still fake."""

import dataclasses
import json

import pytest
from fastapi.testclient import TestClient

from reconix_api.core.wiring import build_interfaces, build_mask_secrets
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_scope_flow import open_session


@pytest.fixture
def harness_app(db_app, tmp_path):
    """db_app, with the real check, mask_secrets and write_audit swapped in."""
    audit_log = tmp_path / "audit.jsonl"
    real = build_interfaces(audit_log_path=str(audit_log))
    db_app.state.interfaces = dataclasses.replace(
        db_app.state.interfaces, check=real.check, write_audit=real.write_audit
    )
    db_app.state.mask_secrets = build_mask_secrets()
    db_app.state.audit_log = audit_log
    return db_app


@pytest.fixture
def harness_client(harness_app):
    return TestClient(harness_app, base_url="http://127.0.0.1/api/v1")


def audit_lines(app) -> list[dict]:
    return [json.loads(line) for line in app.state.audit_log.read_text().splitlines()]


def test_nmap_waits_for_approval_then_runs(harness_client, harness_app):
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers)

    action = send(
        harness_client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    ).json()
    assert action["risk_level"] == "MEDIUM"  # nmap's base level in the harness
    assert action["action_status"] == "PENDING"

    path = f"/approvals/{action['approval_id']}/approve"
    approved = harness_client.post(path, json={}, headers=headers)
    assert approved.status_code == 200, approved.json()

    action = harness_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert action["action_status"] == "COMPLETED"
    [run] = action["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED"

    events = [line["event_type"] for line in audit_lines(harness_app)]
    assert "TOOL_RUN_FINISHED" in events


def test_out_of_scope_target_is_blocked_by_the_scope_check(harness_client, harness_app):
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers)

    response = send(harness_client, headers, assessment_id, tool="NMAP", target="10.0.0.1")
    assert response.status_code == 422
    assert response.json()["details"]["reason"] == "TARGET_OUT_OF_SCOPE"
    assert harness_app.state.parts["mcp"].jobs == []


def test_option_not_on_the_allow_list_is_blocked(harness_client, harness_app):
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers)

    response = send(
        harness_client,
        headers,
        assessment_id,
        tool="NMAP",
        target="172.20.0.5",
        arguments=["--script", "x;rm -rf /"],
    )
    assert response.status_code == 422
    assert harness_app.state.parts["mcp"].jobs == []
