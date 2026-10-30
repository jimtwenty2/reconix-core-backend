"""Response shapes for /assessments/{id}/reports and /reports."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel

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
    assessment_id: UUID
    review_approval_id: UUID | None  # the newest review request
    review_status: ApprovalStatus | None
    signed_off: bool  # an approved review: the files can be downloaded
