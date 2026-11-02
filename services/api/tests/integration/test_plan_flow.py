"""Plan -> the suggested step through the API's own check -> (approve) -> resume, through
the API and a real database. The agent is the fake; the check is the fake pipeline."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import update

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Action, ToolName
from reconix_api.models import Action as ActionRow
from reconix_api.models import AgentRun, Approval, ScopeManifest
from reconix_api.services import plans
from tests.integration.test_action_flow import active_assessment, event_types
from tests.integration.test_scope_flow import open_session

NUCLEI_STEP = Action(tool=ToolName.NUCLEI, target="http://juice-shop:3000/", arguments=[])


def plan(client, headers, assessment_id):
    return client.post(f"/assessments/{assessment_id}/plan", headers=headers)


def runs(client, headers):
    session_id = client.get("/operator", headers=headers).json()["session_id"]
    return client.get(f"/sessions/{session_id}/agent-runs", headers=headers).json()


def test_a_medium_step_waits_then_resumes_after_approval(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP

    response = plan(db_client, headers, assessment_id)

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["agent_run"]["agent_runs_status"] == "WAITING_APPROVAL"
    assert body["plan"][0]["title"] == "Find open ports and services"
    action = body["action"]
    assert action["source"] == "agent"
    assert action["risk_level"] == "MEDIUM"
    assert action["action_status"] == "PENDING"
    assert db_app.state.parts["mcp"].jobs == []  # nothing ran yet

    approved = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )

    assert approved.status_code == 200, approved.json()
    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "COMPLETED"
    assert run["finished_at"] is not None
    assert len(db_app.state.parts["mcp"].jobs) == 1
    resume = db_app.state.parts["agent"].requests[-1].resume
    assert resume.decision == "APPROVED"
    assert resume.approval_id.hex == action["approval_id"].replace("-", "")
    assert "AGENT_RUN_COMPLETED" in event_types(db_app)


def test_a_rejected_step_is_handed_back_and_never_runs(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    action = plan(db_client, headers, assessment_id).json()["action"]

    rejected = db_client.post(
        f"/approvals/{action['approval_id']}/reject", json={"reason": "not now"}, headers=headers
    )

    assert rejected.status_code == 200, rejected.json()
    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "COMPLETED"
    assert db_app.state.parts["agent"].requests[-1].resume.decision == "REJECTED"
    assert db_app.state.parts["mcp"].jobs == []


def test_a_low_step_runs_right_away(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    body = plan(db_client, headers, assessment_id).json()

    assert body["action"]["risk_level"] == "LOW"
    assert body["action"]["action_status"] == "COMPLETED"
    assert body["action"]["approval_id"] is None
    assert body["agent_run"]["agent_runs_status"] == "COMPLETED"
    assert len(db_app.state.parts["mcp"].jobs) == 1


def test_the_apis_own_check_still_blocks_the_agents_step(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = Action(tool=ToolName.NMAP, target="10.0.0.1")

    response = plan(db_client, headers, assessment_id)

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["action"]["action_status"] == "BLOCKED"
    assert body["action"]["guardrail_report"]["reason"] == "TARGET_OUT_OF_SCOPE"
    assert body["agent_run"]["agent_runs_status"] == "COMPLETED"
    assert db_app.state.parts["mcp"].jobs == []
    assert "ACTION_BLOCKED" in event_types(db_app)


def test_a_second_plan_waits_for_the_first_decision(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    plan(db_client, headers, assessment_id)

    again = plan(db_client, headers, assessment_id)

    assert again.status_code == 409
    assert again.json()["code"] == "RUN_IS_WAITING"


def test_an_expired_approval_lets_a_new_plan_start(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    first = plan(db_client, headers, assessment_id).json()
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == first["action"]["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        db.commit()

    again = plan(db_client, headers, assessment_id)

    assert again.status_code == 201, again.json()
    statuses = [run["agent_runs_status"] for run in runs(db_client, headers)]
    assert statuses == ["WAITING_APPROVAL", "COMPLETED"]  # newest first
    expired = db_client.get(f"/approvals/{first['action']['approval_id']}", headers=headers)
    assert expired.json()["approval_status"] == "EXPIRED"


def test_the_model_down_fails_the_run_with_a_503(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].down = True

    response = plan(db_client, headers, assessment_id)

    assert response.status_code == 503
    assert response.json()["code"] == "MODEL_UNAVAILABLE"
    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "FAILED"
    assert "AGENT_RUN_FAILED" in event_types(db_app)


def test_plan_needs_an_active_assessment(db_client):
    headers = open_session(db_client)
    response = db_client.post(
        "/assessments/00000000-0000-0000-0000-000000000000/plan", headers=headers
    )

    assert response.status_code == 404


def run_events(db_app) -> list[str]:
    return [e for e in event_types(db_app) if e.startswith("AGENT_RUN_")]


def test_each_run_ends_with_exactly_one_audit_line(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    plan(db_client, headers, assessment_id)  # LOW: completes inside the request
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    action = plan(db_client, headers, assessment_id).json()["action"]
    db_client.post(f"/approvals/{action['approval_id']}/approve", json={}, headers=headers)

    assert run_events(db_app) == ["AGENT_RUN_COMPLETED", "AGENT_RUN_COMPLETED"]


def test_an_expired_approval_is_audited(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    first = plan(db_client, headers, assessment_id).json()
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == first["action"]["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        db.commit()

    plan(db_client, headers, assessment_id)

    assert event_types(db_app).count("APPROVAL_EXPIRED") == 1
    assert db_app.state.parts["agent"].requests[-2].resume.decision == "REJECTED"


def test_a_persons_action_never_joins_a_plans_run(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    planned = plan(db_client, headers, assessment_id).json()

    own = db_client.post(
        f"/assessments/{assessment_id}/actions",
        json={"tool": "NUCLEI", "target": "http://juice-shop:3000/"},
        headers=headers,
    ).json()

    with session_factory() as db:
        plan_run = db.get(ActionRow, planned["action"]["action_id"]).agent_run_id
        own_run = db.get(ActionRow, own["action_id"]).agent_run_id
    assert own["source"] == "operator"
    assert own_run != plan_run
    db_client.post(f"/approvals/{own['approval_id']}/approve", json={}, headers=headers)
    statuses = {run["agent_run_id"]: run["agent_runs_status"] for run in runs(db_client, headers)}
    assert statuses[str(plan_run)] == "WAITING_APPROVAL"  # the person's decision is not the plan's


def test_a_plan_cut_off_while_running_does_not_block_the_next(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    first = plan(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]
    with session_factory() as db:  # as if the API stopped while asking the agent
        db.execute(
            update(AgentRun)
            .where(AgentRun.agent_run_id == first)
            .values(agent_runs_status="RUNNING", started_at=datetime.now(UTC) - timedelta(hours=1))
        )
        db.commit()

    again = plan(db_client, headers, assessment_id)

    assert again.status_code == 201, again.json()
    statuses = {run["agent_run_id"]: run["agent_runs_status"] for run in runs(db_client, headers)}
    assert statuses[first] == "FAILED"


def test_an_unexpected_error_never_leaves_a_run_running(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].error = RuntimeError("bug")

    with pytest.raises(RuntimeError):
        plan(db_client, headers, assessment_id)

    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "FAILED"


def test_a_step_blocked_at_approval_frees_the_plan(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP
    first = plan(db_client, headers, assessment_id).json()
    with session_factory() as db:  # the scope no longer allows the suggested tool
        db.execute(
            update(ScopeManifest)
            .where(ScopeManifest.assessment_id == assessment_id)
            .values(allowed_tools=["NMAP", "ZAP"])
        )
        db.commit()
    blocked = db_client.post(
        f"/approvals/{first['action']['approval_id']}/approve", json={}, headers=headers
    )
    assert blocked.json()["code"] == "ACTION_BLOCKED"

    again = plan(db_client, headers, assessment_id)  # not 409 RUN_IS_WAITING

    assert again.status_code == 201, again.json()
    first_id = first["agent_run"]["agent_run_id"]
    [first_run] = [r for r in runs(db_client, headers) if r["agent_run_id"] == first_id]
    assert first_run["agent_runs_status"] == "COMPLETED"
    resumes = [r.resume.decision for r in db_app.state.parts["agent"].requests if r.resume]
    assert resumes == ["REJECTED"]
    assert db_app.state.parts["mcp"].jobs == []


def test_an_answer_after_the_run_was_cut_off_saves_nothing(db_client, session_factory):
    """A slow model call can outlive the cut-off; a newer plan has started by then, so
    the old run's answer must not be saved or sent."""
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_id = plan(db_client, headers, assessment_id).json()["agent_run"]["agent_run_id"]
    with session_factory() as db:
        db.execute(
            update(AgentRun)
            .where(AgentRun.agent_run_id == run_id)
            .values(agent_runs_status="FAILED")
        )
        db.commit()
        run = db.get(AgentRun, run_id)

        with pytest.raises(ApiError) as error:
            plans.ensure_still_running(db, run)

    assert (error.value.status, error.value.code) == (409, "RUN_CUT_OFF")
