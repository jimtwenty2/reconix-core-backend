"""Response shapes for /assessments/{id}/findings."""

from datetime import datetime
from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus


class EvidenceOut(BaseModel):
    evidence_id: UUID
    kind: str
    content: str | None  # masked
    location: str | None
    created_at: datetime
    tool_run_id: UUID


class FindingOut(BaseModel):
    finding_id: UUID
    code: str
    title: str
    target: str
    description: str
    severity_status: SeverityStatus
    cvss_score: Decimal | None
    cwe_ids: list[str]
    owasp_id: list[str]
    cve_ids: list[str]
    impact: str | None
    remediation: str | None
    validation_status: ValidationStatus
    finding_status: FindingStatus
    created_at: datetime
    assessment_id: UUID
    source_tool_run_ids: list[UUID] = Field(default_factory=list)  # the runs that found it
    evidence: list[EvidenceOut] = Field(default_factory=list)
