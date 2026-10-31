"""A plan as a draft: the person reads it first, then sends or cancels it. Nothing is
sent or run until they send it, and then the step takes the same path as any step."""

from tests.integration.test_action_flow import active_assessment, event_types
from tests.integration.test_plan_flow import NUCLEI_STEP, runs
from tests.integration.test_scope_flow import open_session


def draft(client, headers, assessment_id):
    return client.post(f"/assessments/{assessment_id}/plan?draft=true", headers=headers)


def send(client, headers, run_id):
    return client.post(f"/agent-runs/{run_id}/send", headers=headers)


def cancel(client, headers, run_id):
    return client.post(f"/agent-runs/{run_id}/cancel", headers=headers)


def actions(client, headers, assessment_id) -> list[dict]:
    return client.get(f"/assessments/{assessment_id}/actions", headers=headers).json()


def test_a_draft_sends_and_runs_nothing(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    response = draft(db_client, headers, assessment_id)

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["draft"] is True
    assert body["action"] is None
    step = body["plan"][0]
    assert step["title"] == "Find open ports and services"
    assert (step["phase"], step["action"]["tool"]) == ("discovery", "NMAP")
    assert step["reason"] == "Start with what runs before looking for weaknesses."
    assert body["agent_run"]["agent_runs_status"] == "WAITING_APPROVAL"
    assert actions(db_client, headers, assessment_id) == []
    assert db_app.state.parts["mcp"].jobs == []


def test_a_sent_low_step_runs_through_the_apis_own_path(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_id = draft(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]

    response = send(db_client, headers, run_id)

    assert response.status_code == 200, response.json()
    body = response.json()
    assert body["draft"] is False
    assert (body["action"]["risk_level"], body["action"]["action_status"]) == ("LOW", "COMPLETED")
    assert body["agent_run"]["agent_runs_status"] == "COMPLETED"
    assert len(db_app.state.parts["mcp"].jobs) == 1
    assert "PLAN_SENT" in event_types(db_app)


def test_a_sent_medium_step_waits_for_its_approval(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    run_id = draft(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]

    body = send(db_client, headers, run_id).json()

    assert body["action"]["approval_id"] is not None
    assert body["agent_run"]["agent_runs_status"] == "WAITING_APPROVAL"
    assert db_app.state.parts["mcp"].jobs == []


def test_a_draft_is_sent_only_once(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_id = draft(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]
    send(db_client, headers, run_id)

    again = send(db_client, headers, run_id)

    assert (again.status_code, again.json()["code"]) == (409, "PLAN_NOT_DRAFT")
    assert len(actions(db_client, headers, assessment_id)) == 1


def test_a_cancelled_draft_never_runs(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_id = draft(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]

    assert cancel(db_client, headers, run_id).status_code == 200

    assert runs(db_client, headers)[0]["agent_runs_status"] == "CANCELLED"
    assert send(db_client, headers, run_id).status_code == 409
    assert actions(db_client, headers, assessment_id) == []
    assert db_app.state.parts["mcp"].jobs == []
    assert event_types(db_app)[-1] == "AGENT_RUN_CANCELLED"
    plan = db_client.get(f"/assessments/{assessment_id}/overview", headers=headers).json()
    assert plan["plan_step_count"] == 0  # a dropped draft is not the assessment's plan


def test_a_new_plan_replaces_an_unsent_draft(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    first = draft(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]

    second = draft(db_client, headers, assessment_id)

    assert second.status_code == 201, second.json()
    by_id = {run["agent_run_id"]: run["agent_runs_status"] for run in runs(db_client, headers)}
    assert by_id[first] == "CANCELLED"


def test_a_draft_of_a_cancelled_assessment_cannot_be_sent(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_id = draft(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]
    assert db_client.delete(f"/assessments/{assessment_id}", headers=headers).status_code < 300

    response = send(db_client, headers, run_id)

    assert response.status_code == 409
    assert db_app.state.parts["mcp"].jobs == []


def test_only_a_draft_can_be_sent(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    done = db_client.post(f"/assessments/{assessment_id}/plan", headers=headers).json()

    response = send(db_client, headers, done["agent_run"]["agent_run_id"])

    assert (response.status_code, response.json()["code"]) == (409, "PLAN_NOT_DRAFT")


def test_an_unknown_run_is_404(db_client):
    headers = open_session(db_client)

    response = send(db_client, headers, "00000000-0000-0000-0000-000000000000")

    assert (response.status_code, response.json()["code"]) == (404, "AGENT_RUN_NOT_FOUND")
