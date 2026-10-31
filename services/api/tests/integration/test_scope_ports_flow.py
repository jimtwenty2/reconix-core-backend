"""Allowed ports in the scope: saved, approved as part of the scope, and enforced by the
real scope check before nmap runs."""

from tests.integration.test_action_flow import SCOPE, active_assessment, send
from tests.integration.test_real_harness import harness_app, harness_client  # noqa: F401
from tests.integration.test_scope_flow import DRAFT, SUBMIT, open_session, scopes_path

WITH_PORTS = {**SCOPE, "allowed_ports": [443, 22, 80, 22]}


def new_draft(client, headers, body: dict):
    return client.post(scopes_path(client, headers), json=body, headers=headers)


def test_ports_are_saved_sorted_once_each(db_client):
    headers = open_session(db_client)

    scope = new_draft(db_client, headers, WITH_PORTS).json()

    assert scope["allowed_ports"] == [22, 80, 443]


def test_ports_can_be_changed_while_a_draft(db_client):
    headers = open_session(db_client)
    scope = new_draft(db_client, headers, WITH_PORTS).json()

    response = db_client.patch(
        f"/scope-manifests/{scope['manifest_id']}", json={"allowed_ports": [3389]}, headers=headers
    )

    assert response.status_code == 200, response.json()
    assert response.json()["allowed_ports"] == [3389]
    assert response.json()["allowed_tools"] == scope["allowed_tools"]  # the rest is kept


def test_a_port_outside_1_to_65535_is_refused(db_client):
    headers = open_session(db_client)

    response = new_draft(db_client, headers, {**DRAFT, "allowed_ports": [70000]})

    assert response.status_code == 422


def test_the_approval_shows_the_ports(db_client):
    headers = open_session(db_client)
    scope = new_draft(db_client, headers, WITH_PORTS).json()

    submitted = db_client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit", json=SUBMIT, headers=headers
    ).json()

    approval = db_client.get(f"/approvals/{submitted['approval_id']}", headers=headers).json()
    assert approval["subject_snapshot"]["allowed_ports"] == [22, 80, 443]


def test_a_scope_without_ports_keeps_its_old_snapshot(db_client):
    headers = open_session(db_client)
    scope = new_draft(db_client, headers, DRAFT).json()

    submitted = db_client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit", json=SUBMIT, headers=headers
    ).json()

    approval = db_client.get(f"/approvals/{submitted['approval_id']}", headers=headers).json()
    assert "allowed_ports" not in approval["subject_snapshot"]


def test_nmap_on_an_allowed_port_waits_for_approval(harness_client, harness_app):  # noqa: F811
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers, WITH_PORTS)

    response = send(
        harness_client,
        headers,
        assessment_id,
        tool="NMAP",
        target="172.20.0.5",
        arguments=["-Pn", "-sV", "-p", "22,443"],
    )

    assert response.status_code == 201, response.json()
    assert response.json()["action_status"] == "PENDING"


def test_nmap_on_another_port_is_blocked_by_the_scope_check(harness_client, harness_app):  # noqa: F811
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers, WITH_PORTS)

    response = send(
        harness_client,
        headers,
        assessment_id,
        tool="NMAP",
        target="172.20.0.5",
        arguments=["-sV", "-p", "3389"],
    )

    assert response.status_code == 422
    assert response.json()["details"]["reason"] == "PORTS_OUT_OF_SCOPE"
    assert harness_app.state.parts["mcp"].jobs == []


def test_nmap_without_ports_is_blocked_when_the_scope_lists_them(harness_client, harness_app):  # noqa: F811
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers, WITH_PORTS)

    response = send(harness_client, headers, assessment_id, tool="NMAP", target="172.20.0.5")

    assert response.json()["details"]["reason"] == "PORTS_NOT_GIVEN"
