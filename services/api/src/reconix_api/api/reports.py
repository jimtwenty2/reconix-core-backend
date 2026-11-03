"""Reports: make one, read them, ask for the review sign-off, download the files."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.approvals import ApprovalOut
from reconix_api.schemas.reports import CombinedReportIn, ReportFormat, ReportOut
from reconix_api.services import decisions, reports

router = APIRouter(tags=["reports"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/assessments/{assessment_id}/reports", status_code=status.HTTP_201_CREATED)
async def create_report(
    assessment_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> ReportOut:
    """Creates a new report version from a locked copy of the findings and tool runs. It answers
    READY with its files, or with an error and a FAILED report."""
    return await reports.create_report(db, interfaces, mask, settings, operator, assessment_id)


@router.post("/assessments/{assessment_id}/combined-reports", status_code=status.HTTP_201_CREATED)
async def create_combined_report(
    assessment_id: UUID,
    body: CombinedReportIn,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> ReportOut:
    """Creates one report that covers this assessment and 1 to 4 others (2 to 5 in all), each with
    an approved scope. The report is filed under this assessment and listed under each of them,
    and each finding code gets its assessment's code in front. It is signed off and downloaded
    like any other report."""
    return await reports.create_report(
        db, interfaces, mask, settings, operator, assessment_id, body.combined_with
    )


@router.get("/assessments/{assessment_id}/reports")
def list_reports(assessment_id: UUID, db: Db, _: CurrentOperator) -> list[ReportOut]:
    """Lists the assessment's own reports, newest first, followed by the combined reports that
    cover it."""
    return reports.list_reports(db, assessment_id)


@router.get("/reports/{report_id}")
def read_report(report_id: UUID, db: Db, _: CurrentOperator) -> ReportOut:
    """Returns one report version with its status, the file formats it can be downloaded in, and
    whether its review was approved. Returns 404 REPORT_NOT_FOUND if there is no report with
    this id."""
    return reports.read_report(db, report_id)


@router.post("/reports/{report_id}/review-requests", status_code=status.HTTP_201_CREATED)
def request_review(
    report_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> ApprovalOut:
    """Asks for the report to be reviewed. This creates a `review` approval, which a person
    approves or rejects with /approvals/{id}/approve or /reject."""
    ttl_minutes = settings.approval_ttl_minutes
    approval = reports.request_review(db, interfaces.write_audit, operator, report_id, ttl_minutes)
    return decisions.approval_out(approval, settings.approval_ttl_minutes)


@router.get("/reports/{report_id}/download")
def download(
    report_id: UUID,
    db: Db,
    _: CurrentOperator,
    settings: CurrentSettings,
    format: ReportFormat = "PDF",
) -> FileResponse:
    """Downloads the report file. It is available once the report is READY and its review has been
    approved."""
    path, media_type, name = reports.download(db, settings, report_id, format)
    return FileResponse(path, media_type=media_type, filename=name)
