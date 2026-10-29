"""A completed nmap run -> findings, sources and masked evidence, through the API and a database."""

import dataclasses
import json
from pathlib import Path

from reconix_api.core.interfaces import ToolResult, ToolRunStatus
from reconix_api.core.wiring import build_mask_secrets
from reconix_api.services import findings as findings_service
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_scope_flow import open_session

FIXTURES = Path(__file__).parents[1] / "fixtures"


def run_nmap(client, headers, assessment_id) -> dict:
    response = send(
        client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    )
    assert response.status_code == 201, response.json()
    return response.json()


def findings(client, headers, assessment_id) -> list[dict]:
    response = client.get("/findings", params={"assessment_id": assessment_id}, headers=headers)
    assert response.status_code == 200, response.json()
    return response.json()


def test_nmap_run_saves_one_finding_per_open_port(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = run_nmap(db_client, headers, assessment_id)
    [run] = action["tool_runs"]

    saved = findings(db_client, headers, assessment_id)
    assert [f["title"] for f in saved] == [
        "Open port 22/tcp (ssh, OpenSSH 9.6)",
        "Open port 3000/tcp (http, Node.js Express)",
    ]
    assert [f["code"] for f in saved] == ["RCX-001", "RCX-002"]
    assert {f["severity_status"] for f in saved} == {"NONE"}
    assert saved[0]["source_tool_run_ids"] == [run["tool_run_id"]]
    [evidence] = saved[0]["evidence"]
    assert evidence["location"] == "172.20.0.5:22/tcp"
    assert evidence["tool_run_id"] == run["tool_run_id"]


def test_same_port_found_again_is_one_finding_with_two_sources(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    first = run_nmap(db_client, headers, assessment_id)["tool_runs"][0]
    second = run_nmap(db_client, headers, assessment_id)["tool_runs"][0]

    saved = findings(db_client, headers, assessment_id)
    assert len(saved) == 2
    for finding in saved:
        assert set(finding["source_tool_run_ids"]) == {first["tool_run_id"], second["tool_run_id"]}
        assert len(finding["evidence"]) == 2


def test_unreadable_output_keeps_the_run_and_says_why(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    mcp = db_app.state.parts["mcp"]

    async def cut_off(job):
        mcp.jobs.append(job)
        return ToolResult(status=ToolRunStatus.COMPLETED, exit_code=0, stdout="<nmaprun><host>")

    db_app.state.interfaces = dataclasses.replace(db_app.state.interfaces, call_tool=cut_off)

    [run] = run_nmap(db_client, headers, assessment_id)["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED"
    assert "OUTPUT_UNREADABLE" in run["error"]
    assert findings(db_client, headers, assessment_id) == []


def test_parser_bug_keeps_the_run(db_client, monkeypatch):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    def broken_reader(output):
        raise RuntimeError("parser bug")

    monkeypatch.setitem(findings_service.READERS, "nmap", broken_reader)

    [run] = run_nmap(db_client, headers, assessment_id)["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED"
    assert "FINDINGS_NOT_SAVED: RuntimeError" in run["error"]
    assert findings(db_client, headers, assessment_id) == []


def test_findings_of_an_unknown_assessment_is_404(db_client):
    headers = open_session(db_client)
    response = db_client.get(
        "/findings",
        params={"assessment_id": "00000000-0000-0000-0000-000000000000"},
        headers=headers,
    )
    assert response.status_code == 404
    assert response.json()["code"] == "ASSESSMENT_NOT_FOUND"


def run_nuclei(client, headers, app, output: str) -> tuple[str, dict]:
    """A MEDIUM nuclei action with this output, approved and run, with the real masking."""
    assessment_id = active_assessment(client, headers)
    mcp = app.state.parts["mcp"]

    async def nuclei(job):
        mcp.jobs.append(job)
        return ToolResult(status=ToolRunStatus.COMPLETED, exit_code=0, stdout=output)

    app.state.interfaces = dataclasses.replace(app.state.interfaces, call_tool=nuclei)
    app.state.mask_secrets = build_mask_secrets()  # the real harness masking
    action = send(client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/")
    approval_id = action.json()["approval_id"]
    approved = client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    assert approved.status_code == 200, approved.json()
    action = client.get(f"/actions/{action.json()['action_id']}", headers=headers).json()
    [run] = action["tool_runs"]
    return assessment_id, run


def test_real_nuclei_output_saves_one_finding_per_match(db_client, db_app):
    headers = open_session(db_client)
    output = (FIXTURES / "nuclei" / "kali_self_scan.jsonl").read_text()
    assessment_id, run = run_nuclei(db_client, headers, db_app, output)
    assert run["tool_run_status"] == "COMPLETED"
    assert run["error"] is None

    saved = findings(db_client, headers, assessment_id)
    assert len(saved) == 11
    assert len({f["title"] for f in saved}) == 11
    assert {f["severity_status"] for f in saved} == {"NONE"}


def test_control_characters_never_reach_a_finding(db_client, db_app):
    headers = open_session(db_client)
    hostile = {
        "template-id": "banner",
        "info": {"name": "Banner \u001b[2J\u001b[31mred", "severity": "low"},
        "host": "juice-shop",
        "matched-at": "http://juice-shop:3000/",
    }
    assessment_id, _ = run_nuclei(db_client, headers, db_app, json.dumps(hostile))

    [finding] = findings(db_client, headers, assessment_id)
    assert finding["title"] == "Banner [2J[31mred"
    assert "\x1b" not in finding["evidence"][0]["content"]
