"""Response shapes for /assessments/{id}/reports and /reports."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.models.enums import ApprovalStatus, ReportStatus

ReportFormat = Literal["PDF", "DOCX", "JSON"]


class ReportOut(BaseModel):
    report_id: UUID
    version: int
    report_status: ReportStatus
    executive_summary: str | None
    methodology: str | None
    snapshot_hash: str  # SHA-256 of the locked copy the report was written from
    formats: list[ReportFormat]  # the files that can be downloaded once signed off
    generated_by: str
    generated_at: datetime | None
    created_at: datetime
    assessment_id: UUID  # the assessment it is filed under
    assessment_ids: list[UUID]  # all it covers: itself, or 2-5 for a combined report
    review_approval_id: UUID | None  # the newest review request
    review_status: ApprovalStatus | None
    signed_off: bool  # an approved review: the files can be downloaded


class CombinedReportIn(BaseModel):
    """1 to 4 more assessments, each with an approved scope, to cover in one report."""

    combined_with: list[UUID] = Field(min_length=1, max_length=4)
