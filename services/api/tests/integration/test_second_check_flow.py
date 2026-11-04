"""S2: an approved action is checked again right before it runs. An approval does not
outlive its assessment or its scope's time window."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import update

from reconix_api.models import ScopeManifest
from tests.integration.test_action_flow import active_assessment, event_types, send
from tests.integration.test_real_harness import (  # noqa: F401
    audit_lines,
    harness_app,
    harness_client,
)
from tests.integration.test_scope_flow import open_session


def pending_nuclei(client, headers, assessment_id) -> dict:
    action = send(
        client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    assert action["action_status"] == "PENDING", action
    return action


def approve(client, headers, approval_id: str):
    return client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)


def test_an_approval_does_not_outlive_its_assessment(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = pending_nuclei(db_client, headers, assessment_id)
    assert db_client.delete(f"/assessments/{assessment_id}", headers=headers).status_code < 300

    response = approve(db_client, headers, action["approval_id"])

    assert (response.status_code, response.json()["code"]) == (409, "ASSESSMENT_NOT_ACTIVE")
    assert db_app.state.parts["mcp"].jobs == []
    # S9: the refused decision is audited once, and the action can't be approved again.
    assert event_types(db_app)[-1] == "ACTION_BLOCKED"
    saved = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert saved["action_status"] == "CANCELLED"  # it ends with its assessment
    again = approve(db_client, headers, action["approval_id"])
    assert again.status_code == 409 and db_app.state.parts["mcp"].jobs == []


def test_a_closed_time_window_blocks_an_approved_action(
    harness_client,  # noqa: F811
    harness_app,  # noqa: F811
    session_factory,
):
    headers = open_session(harness_client)
    assessment_id = active_assessment(harness_client, headers)
    action = pending_nuclei(harness_client, headers, assessment_id)
    with session_factory() as db:
        db.execute(
            update(ScopeManifest)
            .where(ScopeManifest.assessment_id == assessment_id)
            .values(ends_at=datetime.now(UTC) - timedelta(minutes=1))
        )
        db.commit()

    response = approve(harness_client, headers, action["approval_id"])

    assert (response.status_code, response.json()["code"]) == (422, "ACTION_BLOCKED")
    assert response.json()["details"]["reason"] == "OUTSIDE_TIME_WINDOW"
    assert harness_app.state.parts["mcp"].jobs == []
    saved = harness_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert saved["action_status"] == "BLOCKED"
    assert saved["guardrail_report"]["reason"] == "OUTSIDE_TIME_WINDOW"
    assert audit_lines(harness_app)[-1]["event_type"] == "ACTION_BLOCKED"
    approval = harness_client.get(f"/approvals/{action['approval_id']}", headers=headers).json()
    assert approval["consumed_at"] is None  # nothing ran, so the approval was not used
    # S5: the blocked approval is closed, so a later approve can never run it.
    assert approval["approval_status"] == "EXPIRED"
    with session_factory() as db:
        db.execute(
            update(ScopeManifest)
            .where(ScopeManifest.assessment_id == assessment_id)
            .values(ends_at=datetime.now(UTC) + timedelta(hours=1))
        )
        db.commit()
    again = approve(harness_client, headers, action["approval_id"])
    assert again.status_code == 409
    assert harness_app.state.parts["mcp"].jobs == []


def test_an_action_that_still_passes_runs_once_approved(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = pending_nuclei(db_client, headers, assessment_id)

    assert approve(db_client, headers, action["approval_id"]).status_code == 200

    assert len(db_app.state.parts["mcp"].jobs) == 1
