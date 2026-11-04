"""Disclosure: a masked value is shown once, after a `disclosure` approval, and nowhere else."""

import json
from datetime import timedelta
from uuid import uuid4

from sqlalchemy import text, update

from reconix_api.core.interfaces import ToolName
from reconix_api.core.wiring import build_mask_secrets
from reconix_api.models import Approval
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_findings_flow import run_nuclei
from tests.integration.test_scope_flow import open_session

SECRET = "canaryTOKEN0123456789abcdef"  # a fake bearer token, planted on purpose
NMAP_WITH_SECRET = f"""<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sV">
  <host><status state="up"/><address addr="172.20.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx"/>
        <script id="http-headers" output="Authorization: Bearer {SECRET}"/></port>
    </ports>
  </host>
</nmaprun>
"""


def evidence_with_secret(client, headers, db_app) -> dict:
    db_app.state.mask_secrets = build_mask_secrets()  # the real masking, not the test fake
    db_app.state.parts["mcp"].outputs[ToolName.NMAP] = NMAP_WITH_SECRET
    assessment_id = active_assessment(client, headers)
    response = send(
        client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    )
    assert response.status_code == 201, response.json()
    [finding] = client.get(
        "/findings", params={"assessment_id": assessment_id}, headers=headers
    ).json()
    [evidence] = finding["evidence"]
    return evidence


def ask(client, headers, evidence_id, index=0):
    return client.post(
        f"/evidence/{evidence_id}/disclosures", json={"index": index}, headers=headers
    )


def reveal(client, headers, evidence_id, approval_id):
    return client.post(f"/evidence/{evidence_id}/disclosures/{approval_id}/reveal", headers=headers)


def test_evidence_is_masked_and_lists_what_can_be_shown(db_client, db_app):
    headers = open_session(db_client)
    evidence = evidence_with_secret(db_client, headers, db_app)
    assert SECRET not in evidence["content"]
    assert "[MASKED:token]" in evidence["content"]

    hidden = db_client.get(f"/evidence/{evidence['evidence_id']}/hidden-values", headers=headers)
    assert hidden.json() == [{"index": 0, "kind": "token"}]


def test_value_is_shown_once_after_approval(db_client, db_app, session_factory):
    headers = open_session(db_client)
    evidence_id = evidence_with_secret(db_client, headers, db_app)["evidence_id"]
    asked = ask(db_client, headers, evidence_id)
    assert asked.status_code == 202, asked.json()
    approval = asked.json()
    assert (approval["kind"], approval["evidence_id"]) == ("disclosure", evidence_id)
    assert SECRET not in str(approval)

    early = reveal(db_client, headers, evidence_id, approval["approval_id"])
    assert (early.status_code, early.json()["code"]) == (409, "APPROVAL_NOT_GRANTED")

    db_client.post(f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers)
    shown = reveal(db_client, headers, evidence_id, approval["approval_id"])
    assert shown.status_code == 200, shown.json()
    assert shown.json()["value"] == SECRET
    assert shown.json()["kind"] == "token"
    assert shown.headers["cache-control"] == "no-store"

    again = reveal(db_client, headers, evidence_id, approval["approval_id"])
    assert (again.status_code, again.json()["code"]) == (409, "APPROVAL_ALREADY_USED")
    refused = [
        e for e in db_app.state.parts["audit"].events if e.event_type == "DISCLOSURE_REFUSED"
    ]
    assert [e.details["reason"] for e in refused] == [
        "APPROVAL_NOT_GRANTED",
        "APPROVAL_ALREADY_USED",
    ]

    # The value went only into that one answer: not the audit log, not the database.
    events = db_app.state.parts["audit"].events
    assert "DISCLOSURE_SHOWN" in [event.event_type for event in events]
    assert SECRET not in str([event.model_dump() for event in events])
    with session_factory() as db:
        for table in ("evidences", "tool_runs", "approvals", "findings"):
            rows = db.execute(text(f"SELECT * FROM {table}")).all()  # noqa: S608 - fixed names
            assert SECRET not in str(rows), table


def test_a_rejected_disclosure_shows_nothing(db_client, db_app):
    headers = open_session(db_client)
    evidence_id = evidence_with_secret(db_client, headers, db_app)["evidence_id"]
    approval = ask(db_client, headers, evidence_id).json()
    db_client.post(f"/approvals/{approval['approval_id']}/reject", json={}, headers=headers)

    response = reveal(db_client, headers, evidence_id, approval["approval_id"])
    assert (response.status_code, response.json()["code"]) == (409, "APPROVAL_NOT_GRANTED")


def test_an_expired_approval_shows_nothing(db_client, db_app, session_factory):
    headers = open_session(db_client)
    evidence_id = evidence_with_secret(db_client, headers, db_app)["evidence_id"]
    approval = ask(db_client, headers, evidence_id).json()
    db_client.post(f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers)
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == approval["approval_id"])
            .values(requested_at=Approval.requested_at - timedelta(minutes=31))
        )
        db.commit()

    response = reveal(db_client, headers, evidence_id, approval["approval_id"])
    assert (response.status_code, response.json()["code"]) == (409, "APPROVAL_EXPIRED")


def test_an_approval_works_only_for_its_own_evidence(db_client, db_app):
    headers = open_session(db_client)
    evidence_id = evidence_with_secret(db_client, headers, db_app)["evidence_id"]
    approval = ask(db_client, headers, evidence_id).json()
    db_client.post(f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers)

    response = reveal(db_client, headers, uuid4(), approval["approval_id"])
    assert (response.status_code, response.json()["code"]) == (404, "APPROVAL_NOT_FOUND")


def test_an_unknown_index_or_evidence_is_404(db_client, db_app):
    headers = open_session(db_client)
    evidence_id = evidence_with_secret(db_client, headers, db_app)["evidence_id"]
    assert ask(db_client, headers, evidence_id, index=5).json()["code"] == "HIDDEN_VALUE_NOT_FOUND"
    assert ask(db_client, headers, uuid4()).json()["code"] == "EVIDENCE_NOT_FOUND"


def test_evidence_with_nothing_hidden_lists_nothing(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    send(db_client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"])
    [finding, _] = db_client.get(
        "/findings", params={"assessment_id": assessment_id}, headers=headers
    ).json()
    evidence_id = finding["evidence"][0]["evidence_id"]
    assert db_client.get(f"/evidence/{evidence_id}/hidden-values", headers=headers).json() == []


def test_a_secret_named_by_its_key_is_masked_wherever_it_repeats(db_client, db_app):
    """The masking reads JSON value by value: a value under a secret-named key is hidden in
    every other place it appears too, and the vault keeps one value per label."""
    repeated = "RepeatedHunter2Value"
    row = {
        "template-id": "exposed-config",
        "info": {"name": "Exposed config", "severity": "high"},
        "matched-at": "http://juice-shop:3000/config",
        "host": "juice-shop:3000",
        "password": repeated,
        "extracted-results": [f"value {repeated} repeated"],
    }
    headers = open_session(db_client)
    assessment_id, _ = run_nuclei(db_client, headers, db_app, json.dumps(row))

    found = db_client.get(
        "/findings", params={"assessment_id": assessment_id}, headers=headers
    ).json()
    assert len(found) == 1
    assert repeated not in json.dumps(found)
    [evidence] = found[0]["evidence"]
    labels = evidence["content"].count("[MASKED:")
    assert labels >= 2
    hidden = db_client.get(f"/evidence/{evidence['evidence_id']}/hidden-values", headers=headers)
    assert len(hidden.json()) == labels
