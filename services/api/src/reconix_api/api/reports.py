"""Reports: make one, read them, ask for the review sign-off, download the files."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from fastapi.responses import FileResponse

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.schemas.approvals import ApprovalOut
from reconix_api.schemas.reports import ReportFormat, ReportOut
from reconix_api.services import decisions, reports

router = APIRouter(tags=["reports"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/assessments/{assessment_id}/reports", status_code=status.HTTP_201_CREATED)
async def create_report(
    assessment_id: UUID,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> ReportOut:
    """A new version from a locked copy of the findings and tool runs. Answers READY with
    its files, or an error and a FAILED report."""
    return await reports.create_report(db, interfaces, mask, settings, operator, assessment_id)


@router.get("/assessments/{assessment_id}/reports")
def list_reports(assessment_id: UUID, db: Db, _: CurrentOperator) -> list[ReportOut]:
    """Newest version first."""
    return reports.list_reports(db, assessment_id)


@router.get("/reports/{report_id}")
def read_report(report_id: UUID, db: Db, _: CurrentOperator) -> ReportOut:
    return reports.read_report(db, report_id)


@router.post("/reports/{report_id}/review-requests", status_code=status.HTTP_201_CREATED)
def request_review(
    report_id: UUID,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
) -> ApprovalOut:
    """A `review` approval; approve or reject it with /approvals/{id}/approve or /reject."""
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
    """The file, once the report is READY and its review is approved."""
    path, media_type, name = reports.download(db, settings, report_id, format)
    return FileResponse(path, media_type=media_type, filename=name)
