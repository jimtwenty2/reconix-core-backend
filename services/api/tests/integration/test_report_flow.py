"""Findings -> report (locked copy, agent text, 3 files) -> review sign-off -> download,
through the API and a real database. The agent is the fake; the files are real."""

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import update

from reconix_api.core.config import get_settings
from reconix_api.models import Approval, Report
from tests.integration.test_action_flow import active_assessment, event_types, send
from tests.integration.test_findings_flow import findings, run_nmap
from tests.integration.test_scope_flow import open_session


@pytest.fixture
def reports_dir(db_app, tmp_path) -> Path:
    settings = db_app.dependency_overrides[get_settings]()
    settings.reports_dir = str(tmp_path)
    return tmp_path


def make_report(client, headers, assessment_id):
    return client.post(f"/assessments/{assessment_id}/reports", headers=headers)


def sign_off(client, headers, report_id) -> dict:
    review = client.post(f"/reports/{report_id}/review-requests", headers=headers)
    assert review.status_code == 201, review.json()
    approved = client.post(
        f"/approvals/{review.json()['approval_id']}/approve", json={}, headers=headers
    )
    assert approved.status_code == 200, approved.json()
    return approved.json()


def scanned_assessment(client, headers) -> str:
    assessment_id = active_assessment(client, headers)
    run_nmap(client, headers, assessment_id)  # 2 findings, NONE
    return assessment_id


def test_a_report_is_ready_with_its_3_files(db_client, db_app, reports_dir):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)

    response = make_report(db_client, headers, assessment_id)

    assert response.status_code == 201, response.json()
    report = response.json()
    assert report["report_status"] == "READY"
    assert report["version"] == 1
    assert report["formats"] == ["PDF", "DOCX", "JSON"]
    assert report["executive_summary"] == "Fake summary: 2 NONE."
    assert report["signed_off"] is False
    files = sorted(path.name for path in reports_dir.rglob("report.*"))
    assert files == ["report.docx", "report.json", "report.pdf"]
    saved = json.loads(next(reports_dir.rglob("report.json")).read_text())
    assert [f["code"] for f in saved["findings"]] == ["RCX-001", "RCX-002"]
    assert saved["severity_counts"]["NONE"] == 2
    assert [run["approval_check"] for run in saved["tool_runs"]] == ["NOT_REQUIRED"]
    assert {"REPORT_REQUESTED", "REPORT_READY"} <= set(event_types(db_app))


def test_download_needs_the_review_sign_off(db_client, db_app, reports_dir):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]

    before = db_client.get(f"/reports/{report_id}/download", headers=headers)
    sign_off(db_client, headers, report_id)
    pdf = db_client.get(f"/reports/{report_id}/download", headers=headers)
    docx = db_client.get(f"/reports/{report_id}/download?format=DOCX", headers=headers)

    assert before.status_code == 409
    assert before.json()["code"] == "REPORT_NOT_SIGNED_OFF"
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-")
    assert docx.content.startswith(b"PK")  # a DOCX is a zip
    read = db_client.get(f"/reports/{report_id}", headers=headers).json()
    assert read["signed_off"] is True
    assert read["review_status"] == "APPROVED"


def test_a_rejected_review_keeps_the_files_locked_and_can_be_asked_again(
    db_client, db_app, reports_dir
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]
    review = db_client.post(f"/reports/{report_id}/review-requests", headers=headers).json()

    again = db_client.post(f"/reports/{report_id}/review-requests", headers=headers)
    db_client.post(f"/approvals/{review['approval_id']}/reject", json={}, headers=headers)
    download = db_client.get(f"/reports/{report_id}/download", headers=headers)
    after_reject = db_client.post(f"/reports/{report_id}/review-requests", headers=headers)

    assert again.status_code == 409
    assert again.json()["code"] == "REVIEW_EXISTS"
    assert download.json()["code"] == "REPORT_NOT_SIGNED_OFF"
    assert after_reject.status_code == 201
    assert "APPROVAL_REJECTED" in event_types(db_app)


def test_a_review_is_only_for_the_copy_that_was_reviewed(
    db_client, db_app, reports_dir, session_factory
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]
    review = db_client.post(f"/reports/{report_id}/review-requests", headers=headers).json()
    with session_factory() as db:
        db.execute(
            update(Report)
            .where(Report.report_id == report_id)
            .values(executive_summary="Nothing to worry about.")
        )
        db.commit()

    approved = db_client.post(
        f"/approvals/{review['approval_id']}/approve", json={}, headers=headers
    )

    assert approved.status_code == 409
    assert approved.json()["code"] == "REPORT_CHANGED"


def test_each_report_is_a_new_version_newest_first(db_client, db_app, reports_dir):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    make_report(db_client, headers, assessment_id)
    make_report(db_client, headers, assessment_id)

    listed = db_client.get(f"/assessments/{assessment_id}/reports", headers=headers).json()

    assert [r["version"] for r in listed] == [2, 1]
    assert sorted(p.parent.name for p in reports_dir.rglob("report.pdf")) == ["v1", "v2"]


def test_the_locked_copy_leaves_out_false_positives_and_names_approvals(
    db_client, db_app, reports_dir
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    first = findings(db_client, headers, assessment_id)[0]
    db_client.patch(
        f"/findings/{first['finding_id']}",
        json={"finding_status": "FALSE_POSITIVE"},
        headers=headers,
    )
    medium = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    db_client.post(f"/approvals/{medium['approval_id']}/approve", json={}, headers=headers)

    make_report(db_client, headers, assessment_id)

    saved = json.loads(next(reports_dir.rglob("report.json")).read_text())
    assert [f["code"] for f in saved["findings"]] == ["RCX-002"]
    assert saved["severity_counts"]["NONE"] == 1
    checks = {run["tool"]: run["approval_check"] for run in saved["tool_runs"]}
    assert checks == {"NMAP": "NOT_REQUIRED", "NUCLEI": "APPROVED"}


def test_the_model_down_fails_the_report(db_client, db_app, reports_dir):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    db_app.state.parts["agent"].down = True

    response = make_report(db_client, headers, assessment_id)

    assert response.status_code == 503
    [report] = db_client.get(f"/assessments/{assessment_id}/reports", headers=headers).json()
    assert report["report_status"] == "FAILED"
    review = db_client.post(f"/reports/{report['report_id']}/review-requests", headers=headers)
    assert review.json()["code"] == "REPORT_NOT_READY"
    assert "REPORT_FAILED" in event_types(db_app)
    assert list(reports_dir.rglob("report.*")) == []


def test_an_unknown_format_is_a_422(db_client, db_app, reports_dir):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]

    response = db_client.get(f"/reports/{report_id}/download?format=EXE", headers=headers)

    assert response.status_code == 422


def test_a_file_swapped_after_the_sign_off_is_refused(db_client, db_app, reports_dir):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]
    sign_off(db_client, headers, report_id)
    next(reports_dir.rglob("report.pdf")).write_bytes(b"%PDF-1.7 not the signed one")

    response = db_client.get(f"/reports/{report_id}/download", headers=headers)

    assert response.status_code == 409
    assert response.json()["code"] == "REPORT_FILE_CHANGED"


def test_an_expired_review_lets_a_new_one_be_asked(db_client, db_app, reports_dir, session_factory):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    report_id = make_report(db_client, headers, assessment_id).json()["report_id"]
    first = db_client.post(f"/reports/{report_id}/review-requests", headers=headers).json()
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == first["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        db.commit()

    again = db_client.post(f"/reports/{report_id}/review-requests", headers=headers)

    assert again.status_code == 201, again.json()
    old = db_client.get(f"/approvals/{first['approval_id']}", headers=headers).json()
    assert old["approval_status"] == "EXPIRED"
    assert "APPROVAL_EXPIRED" in event_types(db_app)


def test_a_report_cut_off_while_generating_is_failed(
    db_client, db_app, reports_dir, session_factory
):
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)
    stuck = make_report(db_client, headers, assessment_id).json()["report_id"]
    with session_factory() as db:  # as if the API stopped while writing it
        db.execute(
            update(Report)
            .where(Report.report_id == stuck)
            .values(report_status="GENERATING", created_at=datetime.now(UTC) - timedelta(hours=1))
        )
        db.commit()

    make_report(db_client, headers, assessment_id)

    assert db_client.get(f"/reports/{stuck}", headers=headers).json()["report_status"] == "FAILED"


def test_a_failed_report_leaves_no_files(db_client, db_app, reports_dir, monkeypatch):
    from reconix_api.core import report_files

    def broken(*args):
        raise RuntimeError("the PDF could not be drawn")

    monkeypatch.setattr(report_files, "render", broken)
    headers = open_session(db_client)
    assessment_id = scanned_assessment(db_client, headers)

    with pytest.raises(RuntimeError):
        make_report(db_client, headers, assessment_id)

    [report] = db_client.get(f"/assessments/{assessment_id}/reports", headers=headers).json()
    assert report["report_status"] == "FAILED"
    assert list(reports_dir.rglob("*")) == []
