"""The dashboard's read-only views, through the API and a real database: findings filters
and tools, assessment list rows and the overview."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import update

from reconix_api.models import Approval
from tests.integration.test_action_flow import SCOPE, active_assessment, send
from tests.integration.test_analyze_flow import analyze
from tests.integration.test_findings_flow import findings, run_nmap
from tests.integration.test_plan_flow import plan
from tests.integration.test_scope_flow import open_session

UNKNOWN_ID = "00000000-0000-0000-0000-000000000099"


def get(client, headers, path, **params):
    response = client.get(path, params=params, headers=headers)
    assert response.status_code == 200, response.json()
    return response.json()


def wait_for_approval(client, headers, assessment_id) -> str:
    """A MEDIUM action: it waits for a person, so its approval is PENDING."""
    response = send(client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/")
    assert response.status_code == 201, response.json()
    return response.json()["approval_id"]


def test_findings_can_be_filtered(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    [first, second] = findings(db_client, headers, assessment_id)
    fixed = {"finding_status": "FIXED"}
    db_client.patch(f"/findings/{first['finding_id']}", json=fixed, headers=headers)

    def codes(**params) -> list[str]:
        return [f["code"] for f in get(db_client, headers, "/findings", **params)]

    assert codes(assessment_id=assessment_id, severity_status="NONE") == ["RCX-001", "RCX-002"]
    assert codes(assessment_id=assessment_id, severity_status="HIGH") == []
    assert codes(assessment_id=assessment_id, finding_status="FIXED") == [first["code"]]
    assert codes(finding_status="OPEN", validation_status="UNCONFIRMED") == [second["code"]]


def test_an_unknown_filter_value_is_422(db_client):
    headers = open_session(db_client)
    response = db_client.get("/findings", params={"severity_status": "high"}, headers=headers)
    assert response.status_code == 422


def test_a_finding_names_the_tools_that_found_it(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    run_nmap(db_client, headers, assessment_id)

    assert {tuple(f["tools"]) for f in findings(db_client, headers, assessment_id)} == {("NMAP",)}


def test_list_rows_carry_targets_counts_and_pending_approvals(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    wait_for_approval(db_client, headers, assessment_id)

    [row] = [
        r for r in get(db_client, headers, "/assessments") if r["assessment_id"] == assessment_id
    ]

    assert row["targets"] == ["172.20.0.5", "http://juice-shop:3000/"]
    assert row["finding_count"] == 2
    assert row["worst_severity"] == "NONE"
    assert row["pending_approval_count"] == 1
    assert row["engagement_code"].startswith("RCX-")  # still every AssessmentOut field


def test_a_new_assessment_row_has_no_findings_yet(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    [row] = [
        r for r in get(db_client, headers, "/assessments") if r["assessment_id"] == assessment_id
    ]

    assert row["finding_count"] == 0
    assert row["worst_severity"] is None
    assert row["pending_approval_count"] == 0


def test_an_expired_approval_is_not_counted(db_client, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    approval_id = wait_for_approval(db_client, headers, assessment_id)
    with session_factory() as db:
        long_ago = datetime.now(UTC) - timedelta(minutes=31)
        db.execute(
            update(Approval)
            .where(Approval.approval_id == approval_id)
            .values(requested_at=long_ago)
        )
        db.commit()

    overview = get(db_client, headers, f"/assessments/{assessment_id}/overview")
    assert overview["pending_approval_count"] == 0


def test_a_cancelled_assessments_approvals_are_not_counted(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    wait_for_approval(db_client, headers, assessment_id)
    db_client.delete(f"/assessments/{assessment_id}", headers=headers)

    overview = get(db_client, headers, f"/assessments/{assessment_id}/overview")
    assert overview["pending_approval_count"] == 0


def test_the_overview_counts_everything_in_one_call(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    first = run_nmap(db_client, headers, assessment_id)["tool_runs"][0]
    run_nmap(db_client, headers, assessment_id)
    wait_for_approval(db_client, headers, assessment_id)

    overview = get(db_client, headers, f"/assessments/{assessment_id}/overview")

    assert overview["assessment"]["assessment_id"] == assessment_id
    assert overview["targets"] == ["172.20.0.5", "http://juice-shop:3000/"]
    assert overview["finding_count"] == 2
    assert overview["findings_by_severity"] == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
        "NONE": 2,
    }
    assert overview["findings_by_validation"]["UNCONFIRMED"] == 2
    assert overview["findings_by_status"] == {"OPEN": 2, "FALSE_POSITIVE": 0, "FIXED": 0}
    assert overview["actions_by_status"]["COMPLETED"] == 2
    assert overview["actions_by_status"]["PENDING"] == 1
    assert overview["tool_run_count"] == 2
    assert overview["request_count"] == 2 * first["request_count"]
    assert overview["pending_approval_count"] == 1
    first_started_at = datetime.fromisoformat(overview["first_started_at"])
    assert first_started_at == datetime.fromisoformat(first["started_at"])
    assert overview["plan_step_count"] == 0  # no plan was asked for
    assert overview["plan_step_done_count"] == 0
    last_finished_at = datetime.fromisoformat(overview["last_finished_at"])
    assert overview["duration_seconds"] == int(
        (last_finished_at - first_started_at).total_seconds()
    )
    assert overview["time_window_seconds"] is None  # the scope has no time window
    assert overview["over_time_window"] is False


def test_the_overview_measures_the_time_against_the_scope_window(db_client):
    headers = open_session(db_client)
    now = datetime.now(UTC)
    window = {
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
    }
    assessment_id = active_assessment(db_client, headers, {**SCOPE, **window})

    before = get(db_client, headers, f"/assessments/{assessment_id}/overview")
    run_nmap(db_client, headers, assessment_id)
    after = get(db_client, headers, f"/assessments/{assessment_id}/overview")

    assert before["duration_seconds"] == 0  # no tool has run yet
    assert after["time_window_seconds"] == 2 * 60 * 60
    assert after["over_time_window"] is False


def test_the_overview_of_an_unknown_assessment_is_404(db_client):
    headers = open_session(db_client)
    response = db_client.get(f"/assessments/{UNKNOWN_ID}/overview", headers=headers)
    assert response.status_code == 404
    assert response.json()["code"] == "ASSESSMENT_NOT_FOUND"


def test_plan_progress_survives_an_analysis(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    assert plan(db_client, headers, assessment_id).status_code == 201
    run_nmap(db_client, headers, assessment_id)
    assert analyze(db_client, headers, assessment_id).status_code == 201

    overview = get(db_client, headers, f"/assessments/{assessment_id}/overview")

    assert overview["plan_step_count"] == 1
    assert overview["plan_step_done_count"] == 1


def test_false_positives_are_left_out_of_counts_and_severity(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    for finding in findings(db_client, headers, assessment_id):
        dismissed = {"finding_status": "FALSE_POSITIVE"}
        db_client.patch(f"/findings/{finding['finding_id']}", json=dismissed, headers=headers)

    [row] = [
        r for r in get(db_client, headers, "/assessments") if r["assessment_id"] == assessment_id
    ]
    overview = get(db_client, headers, f"/assessments/{assessment_id}/overview")

    assert row["finding_count"] == 0
    assert row["worst_severity"] is None
    assert overview["finding_count"] == 0
    assert overview["findings_by_severity"]["NONE"] == 0
    assert overview["findings_by_status"]["FALSE_POSITIVE"] == 2
