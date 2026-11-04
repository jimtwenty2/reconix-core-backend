"""Requests that arrive at the same moment (group 3a of the endpoint logic review).

11. The loop limits hold when identical actions are sent at once.
6.  A report cut off as stuck stays FAILED; its late request never makes it READY.
13. Two review requests at once give one review, not two.
10. next-step never resumes a plan while its approved tool is still running.

The client is used without `with`, so each request has its own event loop, like two API
workers. A short sleep inside the request widens the gap the race needs, so the test
fails the same way every time on the old code.
"""

import threading
import time
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, update

from reconix_api.core import report_files
from reconix_api.models import Action as ActionRow
from reconix_api.models import Approval, Report
from reconix_api.models.enums import ActionStatus, ApprovalStatus, ReportStatus
from reconix_api.services import actions as actions_service
from reconix_api.services import reports as reports_service
from tests.integration.test_action_flow import active_assessment, send
from tests.integration.test_limit_settings_flow import ask
from tests.integration.test_plan_flow import NUCLEI_STEP, plan
from tests.integration.test_real_harness import harness_app, harness_client  # noqa: F401
from tests.integration.test_report_flow import (  # noqa: F401 - reports_dir is a fixture
    make_report,
    reports_dir,
    scanned_assessment,
)
from tests.integration.test_scope_flow import open_session

GAP = 0.5  # seconds a request waits at the racy point


def at_once(*calls) -> list:
    """Runs the calls in parallel threads and returns their results in order."""
    results: list = [None] * len(calls)

    def run(index: int, call) -> None:
        results[index] = call()

    threads = [threading.Thread(target=run, args=(i, call)) for i, call in enumerate(calls)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return results


def events(app, event_type: str) -> list:
    return [e for e in app.state.parts["audit"].events if e.event_type == event_type]


# --- 11. loop limits under parallel actions -----------------------------------------------


def test_identical_actions_sent_at_once_keep_the_same_command_limit(
    harness_client,  # noqa: F811
    monkeypatch,
):
    headers = open_session(harness_client)
    approval = ask(harness_client, headers, max_same_command=1).json()
    harness_client.post(f"/approvals/{approval['approval_id']}/approve", json={}, headers=headers)
    assessment_id = active_assessment(harness_client, headers)
    counted = actions_service._check_context

    def slow_count(*args, **kwargs):
        context = counted(*args, **kwargs)
        time.sleep(GAP)  # the runs are counted; the new one is not saved yet
        return context

    monkeypatch.setattr(actions_service, "_check_context", slow_count)
    nmap = {"tool": "NMAP", "target": "172.20.0.5", "arguments": []}

    answers = at_once(*[lambda: send(harness_client, headers, assessment_id, **nmap)] * 3)

    codes = sorted(answer.status_code for answer in answers)
    assert codes == [201, 422, 422], [answer.json() for answer in answers]
    refused = [answer.json() for answer in answers if answer.status_code == 422]
    assert {body["details"]["reason"] for body in refused} == {"REPEATED_COMMAND"}


# --- 6. a report cut off as stuck stays FAILED --------------------------------------------


def test_a_report_cut_off_while_it_renders_stays_failed(
    db_client,
    db_app,
    session_factory,
    reports_dir,  # noqa: F811
    monkeypatch,
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    render = report_files.render

    def cut_off_then_render(*args, **kwargs):
        # Meanwhile another request finds it GENERATING for too long and fails it.
        with session_factory() as db:
            db.execute(
                update(Report)
                .where(Report.report_status == ReportStatus.GENERATING)
                .values(report_status=ReportStatus.FAILED)
            )
            db.commit()
        return render(*args, **kwargs)

    monkeypatch.setattr(report_files, "render", cut_off_then_render)

    late = make_report(db_client, headers, assessment_id)

    assert late.status_code == 409, late.json()
    assert late.json()["code"] == "REPORT_CUT_OFF"
    with session_factory() as db:
        [report] = db.scalars(select(Report)).all()
        assert report.report_status == ReportStatus.FAILED
    assert events(db_app, "REPORT_READY") == []
    assert events(db_app, "REPORT_FAILED") == []  # the cut-off wrote its own; none here
    assert not any(reports_dir.rglob("*.pdf"))  # its files are removed


# --- 13. one review at a time -------------------------------------------------------------


def test_two_review_requests_at_once_give_one_review(
    db_client,
    session_factory,
    reports_dir,  # noqa: F811
    monkeypatch,
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]
    first = db_client.post(f"/reports/{report_id}/review-requests", headers=headers).json()
    with session_factory() as db:  # the first review lapsed
        db.execute(
            update(Approval)
            .where(Approval.approval_id == first["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(hours=1))
        )
        db.commit()
    expire = reports_service.expire_lapsed_review

    def slow_expire(*args, **kwargs):
        lapsed = expire(*args, **kwargs)
        time.sleep(GAP)  # the lapsed review is expired; the new one is not saved yet
        return lapsed

    monkeypatch.setattr(reports_service, "expire_lapsed_review", slow_expire)

    def request():
        return db_client.post(f"/reports/{report_id}/review-requests", headers=headers)

    answers = at_once(request, request)

    assert sorted(answer.status_code for answer in answers) == [201, 409]
    with session_factory() as db:
        pending = db.scalars(
            select(Approval).where(
                Approval.report_id == report_id,
                Approval.approval_status == ApprovalStatus.PENDING,
            )
        ).all()
    assert len(pending) == 1


# --- 10. next-step waits for a running step -----------------------------------------------


def waiting_plan_with_approved_step(client, app, session_factory, decided_at) -> tuple:
    """A plan waiting on its MEDIUM step, which a person approved at decided_at and whose
    tool has not finished: what next-step sees while the approve request runs the tool."""
    headers = open_session(client)
    assessment_id = active_assessment(client, headers)
    app.state.parts["agent"].suggest = NUCLEI_STEP
    action = plan(client, headers, assessment_id).json()["action"]
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == action["approval_id"])
            .values(approval_status=ApprovalStatus.APPROVED, decided_at=decided_at)
        )
        db.execute(
            update(ActionRow)
            .where(ActionRow.action_id == action["action_id"])
            .values(action_status=ActionStatus.APPROVED)
        )
        db.commit()
    return assessment_id, headers


def test_a_new_plan_waits_while_the_approved_step_still_runs(db_client, db_app, session_factory):
    assessment_id, headers = waiting_plan_with_approved_step(
        db_client, db_app, session_factory, datetime.now(UTC)
    )
    asked = len(db_app.state.parts["agent"].requests)

    again = plan(db_client, headers, assessment_id)

    assert again.status_code == 409, again.json()
    assert again.json()["code"] == "RUN_IS_WAITING"
    assert len(db_app.state.parts["agent"].requests) == asked  # the plan was not resumed


def test_a_step_approved_long_ago_no_longer_holds_the_plan(db_client, db_app, session_factory):
    long_ago = datetime.now(UTC) - timedelta(hours=1)  # e.g. the API stopped mid-run
    assessment_id, headers = waiting_plan_with_approved_step(
        db_client, db_app, session_factory, long_ago
    )

    again = plan(db_client, headers, assessment_id)

    assert again.status_code == 201, again.json()
