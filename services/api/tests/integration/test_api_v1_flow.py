"""The endpoints from the API sheet: sessions, scope manifests, assessments, approvals,
findings and evidence, through the API and a database."""

import threading

from reconix_api.core.config import get_settings
from reconix_api.services import sessions as sessions_service
from tests.integration.test_action_flow import active_assessment
from tests.integration.test_findings_flow import run_nmap
from tests.integration.test_scope_flow import DRAFT, draft_and_submit, open_session, scopes_path

MISSING = "00000000-0000-0000-0000-000000000001"


def session_id_of(client, headers) -> str:
    return client.get("/operator", headers=headers).json()["session_id"]


# Sessions


def test_sessions_can_be_listed_and_read(db_client):
    headers = open_session(db_client)
    session_id = session_id_of(db_client, headers)

    listed = db_client.get("/sessions", headers=headers).json()
    assert session_id in [s["session_id"] for s in listed]
    one = db_client.get(f"/sessions/{session_id}", headers=headers).json()
    assert (one["interface"], one["session_status"], one["closed_at"]) == ("cli", "ACTIVE", None)
    assert db_client.get(f"/sessions/{MISSING}", headers=headers).status_code == 404


def test_operator_is_the_os_user_at_this_computer(db_client):
    headers = open_session(db_client)
    me = db_client.get("/operator", headers=headers).json()
    assert "role" not in me  # there are no roles
    actor = me["actor"]
    assert actor == sessions_service.local_actor()
    assert "@" in actor


def test_closing_a_session_ends_its_token(db_client, db_app):
    headers = open_session(db_client)
    session_id = session_id_of(db_client, headers)

    closed = db_client.post(f"/sessions/{session_id}/close", headers=headers)
    assert closed.status_code == 200, closed.json()
    assert closed.json()["session_status"] == "CLOSED"
    assert closed.json()["closed_at"] is not None
    assert db_client.get("/operator", headers=headers).status_code == 401
    events = [e.event_type for e in db_app.state.parts["audit"].events]
    assert "SESSION_CLOSED" in events


def test_cannot_close_another_session(db_client):
    other = session_id_of(db_client, open_session(db_client))
    response = db_client.post(f"/sessions/{other}/close", headers=open_session(db_client))
    assert response.status_code == 403
    assert response.json()["code"] == "NOT_YOUR_SESSION"


# Scope manifests


def test_scopes_are_drafted_in_your_own_session_and_listed(db_client):
    headers = open_session(db_client)
    path = scopes_path(db_client, headers)
    first = db_client.post(path, json=DRAFT, headers=headers).json()
    second = db_client.post(path, json=DRAFT, headers=headers).json()

    listed = db_client.get(path, headers=headers).json()
    assert [s["manifest_id"] for s in listed] == [first["manifest_id"], second["manifest_id"]]
    assert [s["version"] for s in listed] == [1, 2]

    other = f"/sessions/{session_id_of(db_client, open_session(db_client))}/scope-manifests"
    response = db_client.post(other, json=DRAFT, headers=headers)
    assert response.json()["code"] == "NOT_YOUR_SESSION"


def test_patch_changes_only_the_fields_sent(db_client):
    headers = open_session(db_client)
    scope = db_client.post(scopes_path(db_client, headers), json=DRAFT, headers=headers).json()

    patched = db_client.patch(
        f"/scope-manifests/{scope['manifest_id']}", json={"max_risk": "HIGH"}, headers=headers
    )
    assert patched.status_code == 200, patched.json()
    assert patched.json()["max_risk"] == "HIGH"
    assert patched.json()["allowed_tools"] == scope["allowed_tools"]
    assert len(patched.json()["targets"]) == len(scope["targets"])


def test_patch_that_breaks_the_scope_is_refused(db_client):
    headers = open_session(db_client)
    scope = db_client.post(scopes_path(db_client, headers), json=DRAFT, headers=headers).json()
    response = db_client.patch(
        f"/scope-manifests/{scope['manifest_id']}", json={"allowed_tools": []}, headers=headers
    )
    assert response.status_code == 422
    assert response.json()["code"] == "VALIDATION_ERROR"


# Assessments


def test_assessments_can_be_listed_renamed_completed_and_cancelled(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    path = f"/assessments/{assessment_id}"

    active = db_client.get("/assessments", params={"status": "ACTIVE"}, headers=headers).json()
    assert assessment_id in [a["assessment_id"] for a in active]

    renamed = db_client.patch(path, json={"name": "Juice Shop retest"}, headers=headers).json()
    assert renamed["name"] == "Juice Shop retest"

    done = db_client.patch(path, json={"assessment_status": "COMPLETED"}, headers=headers)
    assert done.json()["assessment_status"] == "COMPLETED"
    assert db_client.delete(path, headers=headers).json()["code"] == "ASSESSMENT_FINISHED"

    events = [e.event_type for e in db_app.state.parts["audit"].events]
    assert events.count("ASSESSMENT_UPDATED") == 2


def test_deleting_an_assessment_cancels_it(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    cancelled = db_client.delete(f"/assessments/{assessment_id}", headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["assessment_status"] == "CANCELLED"
    assert db_client.get(f"/assessments/{assessment_id}", headers=headers).status_code == 200


def test_only_an_active_assessment_can_be_completed(db_client):
    headers = open_session(db_client)
    assessment_id = draft_and_submit(db_client, headers)["assessment"]["assessment_id"]
    response = db_client.patch(
        f"/assessments/{assessment_id}", json={"assessment_status": "COMPLETED"}, headers=headers
    )
    assert response.json()["code"] == "ASSESSMENT_NOT_ACTIVE"


def test_completing_with_another_status_names_only_the_value(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    response = db_client.patch(
        f"/assessments/{assessment_id}", json={"assessment_status": "ACTIVE"}, headers=headers
    )
    assert response.status_code == 422
    assert response.json()["details"]["fields"][0]["message"] == "Input should be 'COMPLETED'"


# Text checks


def test_text_with_a_nul_byte_is_rejected_not_a_server_error(db_client):
    headers = open_session(db_client)
    session_id = session_id_of(db_client, headers)
    assessment_id = active_assessment(db_client, headers)
    nul = "Juice\x00Shop"
    action = {"tool": "NMAP", "target": "172.20.0.5", "arguments": [nul]}
    responses = [
        db_client.patch(f"/assessments/{assessment_id}", json={"name": nul}, headers=headers),
        db_client.post(f"/sessions/{session_id}/messages", json={"content": nul}, headers=headers),
        db_client.get("/findings", params={"q": nul}, headers=headers),
        db_client.post(f"/assessments/{assessment_id}/actions", json=action, headers=headers),
    ]
    assert [r.status_code for r in responses] == [422, 422, 422, 422]
    assert {r.json()["code"] for r in responses} == {"VALIDATION_ERROR"}


def test_blank_text_is_rejected(db_client):
    headers = open_session(db_client)
    session_id = session_id_of(db_client, headers)
    scope = db_client.post(scopes_path(db_client, headers), json=DRAFT, headers=headers).json()
    submit = {"name": "   ", "type": "web_url"}
    responses = [
        db_client.post(f"/sessions/{session_id}/messages", json={"content": "  "}, headers=headers),
        db_client.post(
            f"/scope-manifests/{scope['manifest_id']}/submit", json=submit, headers=headers
        ),
    ]
    assessment_id = active_assessment(db_client, open_session(db_client))
    responses.append(
        db_client.patch(f"/assessments/{assessment_id}", json={"type": " "}, headers=headers)
    )
    assert [r.status_code for r in responses] == [422, 422, 422]


def test_the_stream_of_an_unknown_assessment_answers_404(db_client, db_app):
    settings = db_app.dependency_overrides[get_settings]()
    quick = settings.model_copy(update={"stream_heartbeat_seconds": 0.05})
    db_app.dependency_overrides[get_settings] = lambda: quick
    headers = open_session(db_client)
    session_id = session_id_of(db_client, headers)
    # Without the check the stream stays open; closing the session ends it so the test cannot hang.
    closer = threading.Timer(
        2, lambda: db_client.post(f"/sessions/{session_id}/close", headers=headers)
    )
    closer.start()
    response = db_client.get("/stream", params={"assessment_id": MISSING}, headers=headers)
    closer.cancel()
    assert response.status_code == 404
    assert response.json()["code"] == "ASSESSMENT_NOT_FOUND"


# Approvals


def test_approvals_filter_by_status_and_kind(db_client):
    headers = open_session(db_client)
    approval_id = draft_and_submit(db_client, headers)["approval_id"]

    pending = db_client.get("/approvals", params={"kind": "scope"}, headers=headers).json()
    assert approval_id in [a["approval_id"] for a in pending]
    actions = db_client.get("/approvals", params={"kind": "action"}, headers=headers).json()
    assert approval_id not in [a["approval_id"] for a in actions]

    db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    approved = db_client.get("/approvals", params={"status": "APPROVED"}, headers=headers).json()
    assert approval_id in [a["approval_id"] for a in approved]


# Findings and evidence


def test_findings_can_be_listed_read_and_reviewed(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)

    every = db_client.get("/findings", headers=headers).json()
    mine = db_client.get("/findings", params={"assessment_id": assessment_id}, headers=headers)
    assert {f["finding_id"] for f in mine.json()} <= {f["finding_id"] for f in every}
    finding = mine.json()[0]

    one = db_client.get(f"/findings/{finding['finding_id']}", headers=headers).json()
    assert one["code"] == finding["code"]
    assert (one["reviewed_by"], one["reviewed_at"]) == (None, None)

    reviewed = db_client.patch(
        f"/findings/{finding['finding_id']}",
        json={"finding_status": "FALSE_POSITIVE"},
        headers=headers,
    ).json()
    assert reviewed["finding_status"] == "FALSE_POSITIVE"
    assert reviewed["reviewed_by"] is not None
    assert reviewed["reviewed_at"] is not None
    [event] = [e for e in db_app.state.parts["audit"].events if e.event_type == "FINDING_REVIEWED"]
    assert (event.details["from"], event.details["to"]) == ("OPEN", "FALSE_POSITIVE")
    assert db_app.state.parts["memory"].calls == [(finding["code"], False)]  # forgotten


def test_evidence_can_be_read_alone(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    [finding, *_] = db_client.get(
        "/findings", params={"assessment_id": assessment_id}, headers=headers
    ).json()
    evidence = finding["evidence"][0]

    one = db_client.get(f"/evidence/{evidence['evidence_id']}", headers=headers).json()
    assert one == evidence


def test_unknown_finding_and_evidence_are_404(db_client):
    headers = open_session(db_client)
    assert db_client.get(f"/findings/{MISSING}", headers=headers).json()["code"] == (
        "FINDING_NOT_FOUND"
    )
    assert db_client.get(f"/evidence/{MISSING}", headers=headers).json()["code"] == (
        "EVIDENCE_NOT_FOUND"
    )


def test_blank_provider_names_and_keys_are_rejected(db_client):
    headers = open_session(db_client)
    ollama = {"provider_type": "OLLAMA", "display_name": "Local", "model_name": "llama3.1:8b"}
    openai = {"provider_type": "OPENAI", "display_name": "Cloud", "model_name": "gpt-4o"}
    blank_name = db_client.post(
        "/llm-providers", json={**ollama, "display_name": "  "}, headers=headers
    )
    blank_key = db_client.post(
        "/llm-providers", json={**openai, "api_key": " " * 16}, headers=headers
    )
    provider = db_client.post("/llm-providers", json=ollama, headers=headers).json()
    renamed = db_client.patch(
        f"/llm-providers/{provider['llm_provider_id']}", json={"display_name": " "}, headers=headers
    )
    assert [r.status_code for r in (blank_name, blank_key, renamed)] == [422, 422, 422]


def test_action_arguments_and_target_have_limits(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    path = f"/assessments/{assessment_id}/actions"
    nmap = {"tool": "NMAP", "target": "172.20.0.5"}
    responses = [
        db_client.post(path, json={**nmap, "arguments": ["x" * 2049]}, headers=headers),
        db_client.post(path, json={**nmap, "arguments": [""]}, headers=headers),
        db_client.post(path, json={**nmap, "target": "   "}, headers=headers),
    ]
    assert [r.status_code for r in responses] == [422, 422, 422]
    assert {r.json()["code"] for r in responses} == {"VALIDATION_ERROR"}


def test_the_client_names_the_operator(db_client, db_app):
    # The client runs on the person's computer; in Docker the API's own OS names are the
    # container's, so the name the client sends wins.
    opened = db_client.post("/sessions", json={"interface": "cli", "operator": " vanneth@laptop\n"})
    assert opened.status_code == 201, opened.json()
    headers = {"Authorization": f"Bearer {opened.json()['token']}"}
    assert db_client.get("/operator", headers=headers).json()["actor"] == "vanneth@laptop"
    opened_event = [
        e for e in db_app.state.parts["audit"].events if e.event_type == "SESSION_OPENED"
    ][-1]
    assert opened_event.details["operator_from"] == "client"


def test_without_a_sent_name_the_server_names_the_operator(db_client):
    for body in ({"interface": "cli"}, {"interface": "cli", "operator": "   "}):
        token = db_client.post("/sessions", json=body).json()["token"]
        actor = db_client.get("/operator", headers={"Authorization": f"Bearer {token}"}).json()[
            "actor"
        ]
        assert actor == sessions_service.local_actor()


def test_an_operator_name_over_100_characters_is_refused(db_client):
    response = db_client.post("/sessions", json={"interface": "cli", "operator": "x" * 101})
    assert response.status_code == 422
