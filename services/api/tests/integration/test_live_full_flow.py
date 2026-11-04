"""The whole flow against the real Kali MCP server: scope -> plan -> approve -> run ->
analyze -> validate -> report -> download.

Real: the database, the harness checks, masking, the audit log, call_tool (MCP), the tool
and the parsers. Fake: the AI agent (fast and repeatable); its plan suggests one nmap step
on the lab host.

Opt-in, like test_live_tools.py: set RECONIX_TEST_DATABASE_URL, RECONIX_TEST_MCP_URL,
RECONIX_TEST_MCP_ACCESS_KEY and RECONIX_TEST_LEAK_TARGET (a lab host with port 80 open
that sends fake secrets, FAKE...).
"""

import os
import re

import pytest

from reconix_api.core.config import get_settings
from reconix_api.core.interfaces import Action, ToolName
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_live_mcp import live_client  # noqa: F401 - the fixture
from tests.integration.test_report_flow import reports_dir, sign_off  # noqa: F401
from tests.integration.test_scope_flow import open_session

HOST = os.environ.get("RECONIX_TEST_LEAK_TARGET", "")
FAKE_SECRET = re.compile(r"FAKE[A-Za-z0-9_]*")
NMAP_80 = ["-Pn", "-sT", "-sV", "-sC", "-p", "80"]

pytestmark = pytest.mark.skipif(
    not (HOST and os.environ.get("RECONIX_TEST_MCP_ACCESS_KEY")),
    reason="RECONIX_TEST_LEAK_TARGET or the MCP key is not set",
)


def step(name: str, detail: object = "") -> None:
    print(f"  ok  {name} {detail}")


def approve(client, headers, action: dict) -> dict:
    """Approves a waiting action (typing the target for HIGH) and returns it read again."""
    if action["action_status"] == "PENDING":
        body = {"typed_target": action["target"]} if action["risk_level"] == "HIGH" else {}
        approved = client.post(
            f"/approvals/{action['approval_id']}/approve", json=body, headers=headers
        )
        assert approved.status_code == 200, approved.json()
    return client.get(f"/actions/{action['action_id']}", headers=headers).json()


def test_the_full_flow_with_the_real_kali_tools(live_client, db_app, reports_dir, tmp_path):  # noqa: F811
    client = live_client
    # live_client's real audit writer saves here; the timeline must read the same file.
    db_app.dependency_overrides[get_settings]().audit_log_path = str(tmp_path / "audit.jsonl")
    print()

    # 1. Session
    headers = open_session(client)
    assert client.get("/operator").status_code == 401
    step("1 session", "(and 401 without the token)")

    # 2. Scope -> approval -> ACTIVE assessment
    scope = {
        "max_risk": "HIGH",
        "allowed_tools": ["NMAP"],
        "targets": [{"type": "ip", "value": HOST}],
    }
    assessment_id = active_assessment(client, headers, scope)
    assessment = client.get(f"/assessments/{assessment_id}", headers=headers).json()
    assert assessment["assessment_status"] == "ACTIVE"
    assert re.fullmatch(r"RCX-\d{4}-\d{4}", assessment["engagement_code"])
    step("2 scope approved", assessment["engagement_code"])

    # 3 + 4. Plan -> its nmap step -> approve when it waits
    db_app.state.parts["agent"].suggest = Action(tool=ToolName.NMAP, target=HOST, arguments=NMAP_80)
    planned = client.post(f"/assessments/{assessment_id}/plan", headers=headers)
    assert planned.status_code == 201, planned.json()
    body = planned.json()
    action = approve(client, headers, body["action"])
    step(
        "3 plan",
        f"run {body['agent_run']['agent_runs_status']}, step {body['action']['risk_level']}",
    )

    # 5. The tool ran in Kali; output masked; findings and evidence saved
    [run] = action["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED", run["error"] or run
    found = client.get("/findings", params={"assessment_id": assessment_id}, headers=headers).json()
    assert [f["title"].split(" (")[0] for f in found] == ["Open port 80/tcp"]
    finding = client.get(f"/findings/{found[0]['finding_id']}", headers=headers).json()
    evidence = " ".join(e["content"] for e in finding["evidence"])
    assert FAKE_SECRET.findall((run["output_masked"] or "") + evidence) == []
    step("4-5 nmap ran in Kali", f"-> {finding['code']} {finding['title']}, no leak")

    # 6. Analysis
    analyzed = client.post(f"/assessments/{assessment_id}/analyze", headers=headers)
    assert analyzed.status_code == 201, analyzed.json()
    assert analyzed.json()["agent_run"]["agent_runs_status"] == "COMPLETED"
    step("6 analysis", f"{len(analyzed.json()['analysis'])} finding(s)")

    # 7. Validation: a PoC action (always waits for a person), then the AI judges its output
    poc = send(
        client,
        headers,
        assessment_id,
        tool="NMAP",
        target=HOST,
        arguments=NMAP_80,
        purpose="validation",
    ).json()
    assert poc["action_status"] == "PENDING" and poc["risk_level"] in ("MEDIUM", "HIGH"), poc
    poc = approve(client, headers, poc)
    assert poc["tool_runs"][0]["tool_run_status"] == "COMPLETED"
    checked = client.post(
        f"/findings/{finding['finding_id']}/validation-runs",
        json={"tool_run_id": poc["tool_runs"][0]["tool_run_id"]},
        headers=headers,
    )
    assert checked.status_code == 201, checked.json()
    assert checked.json()["method"] == "poc"
    latest = client.get(f"/findings/{finding['finding_id']}", headers=headers).json()
    assert latest["latest_validation"]["validation_status"] == "CONFIRMED"
    step("7 validated", f"PoC {poc['risk_level']} approved, CONFIRMED by the AI")

    # 8. Report -> READY -> review sign-off -> download the 3 files
    made = client.post(f"/assessments/{assessment_id}/reports", headers=headers)
    assert made.status_code == 201, made.json()
    report = made.json()
    assert report["report_status"] == "READY"
    locked = client.get(f"/reports/{report['report_id']}/download", headers=headers)
    assert locked.status_code != 200  # not signed off yet
    sign_off(client, headers, report["report_id"])
    sizes = {}
    for fmt in ("PDF", "DOCX", "JSON"):
        file = client.get(f"/reports/{report['report_id']}/download?format={fmt}", headers=headers)
        assert file.status_code == 200, (fmt, file.text[:200])
        assert b"FAKE" not in file.content
        sizes[fmt] = len(file.content)
    step("8 report signed off and downloaded", sizes)

    # The timeline: the decisions were written to the real audit log
    events = client.get(f"/assessments/{assessment_id}/timeline", headers=headers).json()["events"]
    types = [event["event_type"] for event in events]
    for wanted in ("SCOPE_APPROVED", "TOOL_RUN_FINISHED", "APPROVAL_GRANTED", "REPORT_READY"):
        assert wanted in types, (wanted, types)
    step("timeline", f"{len(types)} audit lines")
