"""Session -> scope draft -> submit -> approve, through the API and a real database."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import update

from reconix_api.models import Approval

DRAFT = {
    "max_risk": "MEDIUM",
    "allowed_tools": ["NMAP", "NUCLEI"],
    "allowed_actions": ["discovery", "scan"],
    "targets": [
        {"type": "ip", "value": "172.20.0.5"},
        {"type": "url", "value": "http://juice-shop:3000/"},
        {"type": "ip", "value": "172.20.0.9", "excluded": True},
    ],
}
SUBMIT = {"name": "Juice Shop", "type": "web_url"}


def open_session(client) -> dict:
    response = client.post("/sessions", json={"interface": "cli"})
    assert response.status_code == 201
    body = response.json()
    assert "role" not in body  # the role is read from GET /operator
    return {"Authorization": f"Bearer {body['token']}"}


def scopes_path(client, headers) -> str:
    """Scopes are drafted in the caller's own session."""
    session_id = client.get("/operator", headers=headers).json()["session_id"]
    return f"/sessions/{session_id}/scope-manifests"


def draft_and_submit(client, headers) -> dict:
    scope = client.post(scopes_path(client, headers), json=DRAFT, headers=headers).json()
    response = client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit", json=SUBMIT, headers=headers
    )
    assert response.status_code == 201, response.json()
    return response.json()


def test_full_scope_flow(db_client, db_app):
    headers = open_session(db_client)

    created = db_client.post(scopes_path(db_client, headers), json=DRAFT, headers=headers)
    assert created.status_code == 201
    scope = created.json()
    assert scope["manifests_status"] == "DRAFT"
    assert scope["version"] == 1
    assert scope["assessment_id"] is None

    edited = {**DRAFT, "targets": DRAFT["targets"][:2]}
    response = db_client.patch(
        f"/scope-manifests/{scope['manifest_id']}", json=edited, headers=headers
    )
    assert response.status_code == 200
    assert len(response.json()["targets"]) == 2

    submitted = db_client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit", json=SUBMIT, headers=headers
    ).json()
    assessment = submitted["assessment"]
    assert assessment["assessment_status"] == "DRAFT"
    assert assessment["engagement_code"] == f"RCX-{datetime.now(UTC).year}-0001"

    pending = db_client.get("/approvals", headers=headers).json()
    assert [a["approval_id"] for a in pending] == [submitted["approval_id"]]
    assert pending[0]["kind"] == "scope"

    approved = db_client.post(
        f"/approvals/{submitted['approval_id']}/approve", json={}, headers=headers
    )
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "APPROVED"
    assert approved.json()["consumed_at"] is not None

    assessment = db_client.get(
        f"/assessments/{assessment['assessment_id']}", headers=headers
    ).json()
    assert assessment["assessment_status"] == "ACTIVE"
    scope = db_client.get(f"/scope-manifests/{scope['manifest_id']}", headers=headers).json()
    assert scope["manifests_status"] == "APPROVED"

    approved_scope = db_app.state.interfaces.get_approved_scope(assessment["assessment_id"])
    assert approved_scope.ip_ranges == ["172.20.0.5/32"]
    assert approved_scope.url_prefixes == ["http://juice-shop:3000/"]

    events = [e.event_type for e in db_app.state.parts["audit"].events]
    assert events == [
        "SESSION_OPENED",
        "SCOPE_DRAFTED",
        "SCOPE_EDITED",
        "SCOPE_SUBMITTED",
        "SCOPE_APPROVED",
    ]


def test_submitted_scope_cannot_be_edited(db_client):
    headers = open_session(db_client)
    submitted = draft_and_submit(db_client, headers)
    response = db_client.patch(
        f"/scope-manifests/{submitted['scope']['manifest_id']}", json=DRAFT, headers=headers
    )
    assert response.status_code == 409
    assert response.json()["code"] == "SCOPE_NOT_EDITABLE"


def test_approval_cannot_be_decided_twice(db_client):
    headers = open_session(db_client)
    approval_id = draft_and_submit(db_client, headers)["approval_id"]
    assert db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers).is_success
    again = db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    assert again.status_code == 409
    assert again.json()["code"] == "APPROVAL_ALREADY_DECIDED"


def test_rejected_scope_frees_the_assessment_for_a_new_version(db_client):
    headers = open_session(db_client)
    first = draft_and_submit(db_client, headers)
    rejected = db_client.post(
        f"/approvals/{first['approval_id']}/reject", json={"reason": "too wide"}, headers=headers
    )
    assert rejected.json()["approval_status"] == "REJECTED"
    scope = db_client.get(
        f"/scope-manifests/{first['scope']['manifest_id']}", headers=headers
    ).json()
    assert scope["manifests_status"] == "REJECTED"
    assert scope["reject_reason"] == "too wide"

    second = draft_and_submit(db_client, headers)
    assert second["scope"]["version"] == 2
    assert second["assessment"]["assessment_id"] == first["assessment"]["assessment_id"]


def test_expired_approval_is_refused_and_marked(db_client, session_factory):
    headers = open_session(db_client)
    approval_id = draft_and_submit(db_client, headers)["approval_id"]
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == approval_id)
            .values(requested_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        db.commit()

    response = db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    assert response.status_code == 409
    assert response.json()["code"] == "APPROVAL_EXPIRED"
    assert db_client.get(f"/approvals/{approval_id}", headers=headers).json()[
        "approval_status"
    ] == ("EXPIRED")


def test_scope_without_a_real_target_cannot_be_submitted(db_client):
    headers = open_session(db_client)
    only_excluded = {**DRAFT, "targets": [{"type": "ip", "value": "10.0.0.1", "excluded": True}]}
    scope = db_client.post(
        scopes_path(db_client, headers), json=only_excluded, headers=headers
    ).json()
    response = db_client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit", json=SUBMIT, headers=headers
    )
    assert response.status_code == 422
    assert response.json()["code"] == "SCOPE_HAS_NO_TARGETS"


def test_unknown_ids_answer_404(db_client):
    headers = open_session(db_client)
    missing = "00000000-0000-0000-0000-000000000001"
    assert (
        db_client.get(f"/scope-manifests/{missing}", headers=headers).json()["code"]
        == "SCOPE_NOT_FOUND"
    )
    assert db_client.get(f"/approvals/{missing}", headers=headers).status_code == 404
