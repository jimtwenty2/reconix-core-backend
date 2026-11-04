"""Fixes from the endpoint logic review (group 2), through the API and a real database.

4. A refused chat saves nothing.
7. A time without a timezone in a scope window is a 422, never a 500.
9. Closing a session never overwrites a code scan that just finished.
12. Refused and expired decisions write one audit line that names their assessment.
"""

import threading
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from reconix_api.core.interfaces import Operator
from reconix_api.models import AgentRun, Approval, Report
from reconix_api.models.enums import AgentRunStatus
from reconix_api.services import agent_runs
from tests.integration.test_action_flow import SCOPE, active_assessment, send
from tests.integration.test_disclosure_flow import evidence_with_secret, reveal
from tests.integration.test_report_flow import (  # noqa: F401 - reports_dir is a fixture
    make_report,
    reports_dir,
    scanned_assessment,
)
from tests.integration.test_scope_flow import DRAFT, open_session, scopes_path


def session_id_of(client, headers) -> str:
    return client.get("/operator", headers=headers).json()["session_id"]


def events(db_app, event_type: str) -> list:
    return [e for e in db_app.state.parts["audit"].events if e.event_type == event_type]


# --- 4. a refused chat saves nothing ------------------------------------------------------


def test_a_chat_refused_while_another_answers_saves_no_message(db_client, db_app, session_factory):
    headers = open_session(db_client)
    session_id = session_id_of(db_client, headers)
    with session_factory() as db:  # a chat that is still answering
        operator = Operator(session_id=session_id, actor="tester@laptop")
        agent_runs.new_agent_run(db, operator, None, task="CHAT")
        db.commit()

    refused = db_client.post(
        f"/sessions/{session_id}/chat", json={"content": "Second question"}, headers=headers
    )

    assert refused.status_code == 409, refused.json()
    assert refused.json()["code"] == "CHAT_IN_PROGRESS"
    assert db_client.get(f"/sessions/{session_id}/messages", headers=headers).json() == []
    assert events(db_app, "MESSAGE_ADDED") == []


# --- 7. a time window needs timezones -----------------------------------------------------


def test_a_window_time_without_a_timezone_is_a_422(db_client):
    headers = open_session(db_client)
    body = {**DRAFT, "starts_at": "2026-11-04T10:00:00", "ends_at": "2026-11-04T12:00:00Z"}

    response = db_client.post(scopes_path(db_client, headers), json=body, headers=headers)

    assert response.status_code == 422, response.text


def test_a_patched_window_time_without_a_timezone_is_a_422(db_client):
    headers = open_session(db_client)
    body = {**DRAFT, "starts_at": "2026-11-04T10:00:00Z"}
    scope = db_client.post(scopes_path(db_client, headers), json=body, headers=headers).json()

    response = db_client.patch(
        f"/scope-manifests/{scope['manifest_id']}",
        json={"ends_at": "2026-11-04T12:00:00"},
        headers=headers,
    )

    assert response.status_code == 422, response.text


def test_window_times_with_timezones_still_work(db_client):
    headers = open_session(db_client)
    body = {**DRAFT, "starts_at": "2026-11-04T10:00:00Z", "ends_at": "2026-11-04T18:00:00+07:00"}

    response = db_client.post(scopes_path(db_client, headers), json=body, headers=headers)

    assert response.status_code == 201, response.json()


# --- 9. closing a session never overwrites a finished scan --------------------------------


def test_closing_a_session_keeps_a_scan_that_just_finished(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    session_id = session_id_of(db_client, headers)
    with session_factory() as db:
        operator = Operator(session_id=session_id, actor="tester@laptop")
        run_id = agent_runs.new_agent_run(
            db, operator, assessment_id, task="CODE_SCAN"
        ).agent_run_id
        db.commit()

    locked = threading.Event()

    def scan_finishes() -> None:
        """The background scan: holds its row lock, then saves COMPLETED."""
        with session_factory() as db:
            run = db.scalar(
                select(AgentRun).where(AgentRun.agent_run_id == run_id).with_for_update()
            )
            run.agent_runs_status = AgentRunStatus.COMPLETED
            run.finished_at = datetime.now(UTC)
            locked.set()
            time.sleep(1.0)
            db.commit()

    finisher = threading.Thread(target=scan_finishes)
    finisher.start()
    locked.wait(5)
    closed = db_client.post(f"/sessions/{session_id}/close", headers=headers)
    finisher.join()

    assert closed.status_code == 200, closed.json()
    with session_factory() as db:
        assert db.get(AgentRun, run_id).agent_runs_status == AgentRunStatus.COMPLETED
    assert events(db_app, "AGENT_RUN_CANCELLED") == []


# --- 12. refusals and expiries are audited with their assessment --------------------------


def pending_high_action(client, headers) -> tuple[str, dict]:
    assessment_id = active_assessment(client, headers)
    action = send(client, headers, assessment_id, tool="ZAP", target="http://juice-shop:3000/")
    assert action.json()["risk_level"] == "HIGH", action.json()
    return assessment_id, action.json()


def test_deciding_an_already_decided_approval_is_audited(db_client, db_app):
    headers = open_session(db_client)
    assessment_id, action = pending_high_action(db_client, headers)
    path = f"/approvals/{action['approval_id']}"
    assert db_client.post(f"{path}/reject", json={}, headers=headers).status_code == 200

    again = db_client.post(f"{path}/approve", json={}, headers=headers)

    assert again.status_code == 409
    [refused] = events(db_app, "APPROVAL_REFUSED")
    assert refused.details["reason"] == "APPROVAL_ALREADY_DECIDED"
    assert str(refused.assessment_id) == assessment_id


def test_a_wrong_typed_target_is_audited_with_its_assessment(db_client, db_app):
    headers = open_session(db_client)
    assessment_id, action = pending_high_action(db_client, headers)

    wrong = db_client.post(
        f"/approvals/{action['approval_id']}/approve",
        json={"typed_target": "http://other-host/"},
        headers=headers,
    )

    assert wrong.status_code in (403, 409, 422), wrong.json()
    [refused] = events(db_app, "APPROVAL_REFUSED")
    assert str(refused.assessment_id) == assessment_id


def test_an_expired_approval_is_audited_with_its_assessment(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id, action = pending_high_action(db_client, headers)
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == action["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(hours=1))
        )
        db.commit()

    expired = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )

    assert expired.json()["code"] == "APPROVAL_EXPIRED"
    [line] = events(db_app, "APPROVAL_EXPIRED")
    assert str(line.assessment_id) == assessment_id


def test_a_review_of_a_changed_report_is_expired_and_audited(
    db_client,
    db_app,
    reports_dir,  # noqa: F811
    session_factory,
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]
    review = db_client.post(f"/reports/{report_id}/review-requests", headers=headers).json()
    with session_factory() as db:
        db.execute(
            update(Report).where(Report.report_id == report_id).values(executive_summary="Edited.")
        )
        db.commit()

    approved = db_client.post(
        f"/approvals/{review['approval_id']}/approve", json={}, headers=headers
    )

    assert approved.json()["code"] == "REPORT_CHANGED"
    approval = db_client.get(f"/approvals/{review['approval_id']}", headers=headers).json()
    assert approval["approval_status"] == "EXPIRED"  # it can't be tried again
    [line] = events(db_app, "APPROVAL_EXPIRED")
    assert str(line.assessment_id) == assessment_id


def test_a_refused_reveal_names_its_assessment(db_client, db_app):
    headers = open_session(db_client)
    evidence = evidence_with_secret(db_client, headers, db_app)
    unknown = "00000000-0000-0000-0000-000000000099"

    refused = reveal(db_client, headers, evidence["evidence_id"], unknown)

    assert refused.status_code >= 400
    [line] = events(db_app, "DISCLOSURE_REFUSED")
    assert line.assessment_id is not None


def test_scope_fixture_is_high_enough_for_a_high_action():
    assert SCOPE["max_risk"] == "HIGH"
