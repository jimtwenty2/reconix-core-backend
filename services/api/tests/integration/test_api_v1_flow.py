"""The endpoints from the API sheet: sessions, scope manifests, assessments, approvals,
findings and evidence, through the API and a database."""

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
