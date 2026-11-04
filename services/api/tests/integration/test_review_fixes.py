"""Fixes from the endpoint logic review (group 1), through the API and a real database.

1. A cancelled assessment never comes back to ACTIVE through its old scope approval.
2. An action's target and arguments are shown masked; the tool still gets the real values.
3. A refused approve (no job token secret) leaves nothing stuck at APPROVED.
"""

from pydantic import SecretStr
from sqlalchemy import update

from reconix_api.core.config import get_settings
from reconix_api.models import Assessment
from reconix_api.models.enums import AssessmentStatus
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_scope_flow import DRAFT, open_session, scopes_path

SECRET = "Passw0rdSecret"


def submit_scope(client, headers) -> dict:
    scope = client.post(scopes_path(client, headers), json=DRAFT, headers=headers).json()
    submitted = client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit",
        json={"name": "Review fix", "type": "web_url"},
        headers=headers,
    )
    assert submitted.status_code == 201, submitted.json()
    return submitted.json()


def status_of(client, headers, assessment_id: str) -> str:
    return client.get(f"/assessments/{assessment_id}", headers=headers).json()["assessment_status"]


# --- 1. a cancelled assessment stays cancelled ------------------------------------------


def test_cancelling_expires_the_open_scope_approval(db_client):
    headers = open_session(db_client)
    submitted = submit_scope(db_client, headers)
    assessment_id = submitted["assessment"]["assessment_id"]

    assert db_client.delete(f"/assessments/{assessment_id}", headers=headers).status_code == 200
    approved = db_client.post(
        f"/approvals/{submitted['approval_id']}/approve", json={}, headers=headers
    )

    assert approved.status_code == 409, approved.json()
    assert status_of(db_client, headers, assessment_id) == "CANCELLED"
    approval = db_client.get(f"/approvals/{submitted['approval_id']}", headers=headers).json()
    assert approval["approval_status"] == "EXPIRED"


def test_a_scope_approval_never_reopens_an_assessment_that_is_not_draft(db_client, session_factory):
    """The guard in approve_scope, for any path that cancels without expiring."""
    headers = open_session(db_client)
    submitted = submit_scope(db_client, headers)
    assessment_id = submitted["assessment"]["assessment_id"]
    with session_factory() as db:
        db.execute(
            update(Assessment)
            .where(Assessment.assessment_id == assessment_id)
            .values(assessment_status=AssessmentStatus.CANCELLED)
        )
        db.commit()

    approved = db_client.post(
        f"/approvals/{submitted['approval_id']}/approve", json={}, headers=headers
    )

    assert approved.status_code == 409, approved.json()
    assert approved.json()["code"] == "ASSESSMENT_NOT_DRAFT"
    assert status_of(db_client, headers, assessment_id) == "CANCELLED"


# --- 2. action target and arguments are shown masked ------------------------------------


def test_action_arguments_are_shown_masked_but_run_with_the_real_values(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    sent = send(
        db_client,
        headers,
        assessment_id,
        tool="NMAP",
        target="172.20.0.5",
        arguments=["--script-args", f"password={SECRET}"],
    )

    assert sent.status_code == 201, sent.json()
    assert SECRET not in sent.text
    one = db_client.get(f"/actions/{sent.json()['action_id']}", headers=headers)
    listed = db_client.get(f"/assessments/{assessment_id}/actions", headers=headers)
    assert SECRET not in one.text
    assert SECRET not in listed.text
    assert "[MASKED:secret]" in one.text
    [job] = db_app.state.parts["mcp"].jobs  # the tool itself got the real value
    assert f"password={SECRET}" in job.arguments


# --- 3. a refused approve leaves nothing stuck ------------------------------------------


def test_approving_without_a_job_token_secret_changes_nothing(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    assert action["action_status"] == "PENDING"

    settings = db_app.dependency_overrides[get_settings]()
    no_secret = settings.model_copy(update={"job_token_secret": SecretStr("")})
    db_app.dependency_overrides[get_settings] = lambda: no_secret
    refused = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )
    db_app.dependency_overrides[get_settings] = lambda: settings

    assert refused.status_code == 503
    assert refused.json()["code"] == "NOT_READY"
    approval = db_client.get(f"/approvals/{action['approval_id']}", headers=headers).json()
    after = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert approval["approval_status"] == "PENDING"  # can be approved once .env is fixed
    assert after["action_status"] == "PENDING"
    assert db_app.state.parts["mcp"].jobs == []

    again = db_client.post(f"/approvals/{action['approval_id']}/approve", json={}, headers=headers)
    assert again.status_code == 200, again.json()
    assert len(db_app.state.parts["mcp"].jobs) == 1
