"""Limit settings: a change waits for a `configuration` approval, then the loop check uses it."""

from datetime import timedelta

import pytest
from sqlalchemy import update

from reconix_api.models import ToolRun
from tests.integration.test_action_flow import active_assessment, event_types, send
from tests.integration.test_real_harness import harness_app, harness_client  # noqa: F401
from tests.integration.test_scope_flow import open_session

DEFAULTS = {
    "max_same_command": 3,
    "same_command_window_minutes": 10,
    "max_actions_per_minute": 20,
    "max_runs_per_assessment": 200,
}


def ask(client, headers, **changes):
    return client.post("/limit-settings", json={"changes": changes}, headers=headers)


def limits(client, headers) -> dict:
    response = client.get("/limit-settings", headers=headers)
    assert response.status_code == 200, response.json()
    return response.json()


def test_defaults_are_the_plans_limits(db_client):
    headers = open_session(db_client)
    body = limits(db_client, headers)
    assert body["limits"] == DEFAULTS
    assert body["defaults"] == DEFAULTS
    assert body["bounds"]["max_runs_per_assessment"] == {"lowest": 1, "highest": 1000}
    assert body["pending_approval_ids"] == []


def test_a_change_waits_for_approval_then_is_used(db_client, db_app):
    headers = open_session(db_client)
    asked = ask(db_client, headers, max_runs_per_assessment=300)
    assert asked.status_code == 202, asked.json()
    approval = asked.json()
    assert (approval["kind"], approval["approval_status"]) == ("configuration", "PENDING")
    assert approval["config_change"]["changed"] == {
        "max_runs_per_assessment": {"from": 200, "to": 300}
    }
    # Nothing changes before the approval.
    before = limits(db_client, headers)
    assert before["limits"] == DEFAULTS
    assert before["pending_approval_ids"] == [approval["approval_id"]]

    approved = db_client.post(
        f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers
    )
    assert approved.status_code == 200, approved.json()
    assert approved.json()["approval_status"] == "APPROVED"
    assert approved.json()["consumed_at"] is not None
    after = limits(db_client, headers)
    assert after["limits"] == {**DEFAULTS, "max_runs_per_assessment": 300}
    assert after["pending_approval_ids"] == []
    assert event_types(db_app).count("APPROVAL_GRANTED") == 1


def test_a_rejected_change_changes_nothing(db_client):
    headers = open_session(db_client)
    approval = ask(db_client, headers, max_actions_per_minute=5).json()
    rejected = db_client.post(
        f"/approvals/{approval['approval_id']}/reject", json={"reason": "no"}, headers=headers
    )
    assert rejected.json()["approval_status"] == "REJECTED"
    assert limits(db_client, headers)["limits"] == DEFAULTS


def test_an_old_approval_cannot_undo_a_newer_change(db_client):
    headers = open_session(db_client)
    first = ask(db_client, headers, max_same_command=5).json()
    second = ask(db_client, headers, max_same_command=2).json()
    db_client.post(f"/approvals/{first['approval_id']}/approve", json={}, headers=headers)

    late = db_client.post(f"/approvals/{second['approval_id']}/approve", json={}, headers=headers)
    assert late.status_code == 409
    assert late.json()["code"] == "LIMITS_CHANGED"
    stale = db_client.get(f"/approvals/{second['approval_id']}", headers=headers).json()
    assert stale["approval_status"] == "EXPIRED"
    assert limits(db_client, headers)["limits"]["max_same_command"] == 5


@pytest.mark.parametrize(
    ("changes", "code"),
    [
        ({"max_runs_per_assessment": 0}, "OUT_OF_RANGE"),
        ({"max_runs_per_assessment": 5000}, "OUT_OF_RANGE"),
        ({"loop_off": 1}, "UNKNOWN_LIMIT"),
        ({"max_runs_per_assessment": 200}, "NO_CHANGE"),
    ],
)
def test_a_change_outside_the_rules_is_refused(db_client, changes, code):
    headers = open_session(db_client)
    response = ask(db_client, headers, **changes)
    assert response.status_code == 422
    assert response.json()["code"] == code
    assert limits(db_client, headers)["pending_approval_ids"] == []


def test_true_is_not_a_number(db_client):
    headers = open_session(db_client)
    assert ask(db_client, headers, max_runs_per_assessment=True).status_code == 422


def test_the_real_loop_check_uses_the_approved_limits(harness_client):  # noqa: F811
    headers = open_session(harness_client)
    approval = ask(harness_client, headers, max_runs_per_assessment=1).json()
    harness_client.post(f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers)
    assessment_id = active_assessment(harness_client, headers)
    nmap = {"tool": "NMAP", "target": "172.20.0.5", "arguments": ["-sV"]}

    first = send(harness_client, headers, assessment_id, **nmap).json()
    harness_client.post(f"/approvals/{first['approval_id']}/approve", json={}, headers=headers)
    second = send(harness_client, headers, assessment_id, **nmap)

    assert second.status_code == 422
    assert second.json()["details"]["reason"] == "RUN_LIMIT_REACHED"


def test_a_window_longer_than_10_minutes_counts_older_runs(harness_client, session_factory):  # noqa: F811
    headers = open_session(harness_client)
    approval = ask(
        harness_client, headers, same_command_window_minutes=30, max_same_command=1
    ).json()
    harness_client.post(f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers)
    assessment_id = active_assessment(harness_client, headers)
    nmap = {"tool": "NMAP", "target": "172.20.0.5", "arguments": ["-sV"]}
    first = send(harness_client, headers, assessment_id, **nmap).json()
    harness_client.post(f"/approvals/{first['approval_id']}/approve", json={}, headers=headers)
    with session_factory() as db:  # the run was 20 minutes ago: outside 10, inside 30
        db.execute(update(ToolRun).values(started_at=ToolRun.started_at - timedelta(minutes=20)))
        db.commit()

    second = send(harness_client, headers, assessment_id, **nmap)
    assert second.status_code == 422
    assert second.json()["details"]["reason"] == "REPEATED_COMMAND"
