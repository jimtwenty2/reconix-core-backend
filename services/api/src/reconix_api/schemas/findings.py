"""Request and response shapes for /findings and /evidence."""

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


class ValidationRunOut(BaseModel):
    validation_run_id: UUID
    method: str  # manual_review for a person's check
    validation_status: ValidationStatus
    reason: str | None  # masked
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    finding_id: UUID
    tool_run_id: UUID | None  # empty for a person's check


class ValidationRunIn(BaseModel):
    """Ask the AI to confirm a finding from a completed PoC tool run. The AI reads that
    run's real (masked) output and sets the verdict; a person cannot set it by hand."""

    tool_run_id: UUID  # the COMPLETED PoC run whose output the AI judges


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
    reviewed_by: str | None
    reviewed_at: datetime | None
    created_at: datetime
    assessment_id: UUID
    source_tool_run_ids: list[UUID] = Field(default_factory=list)  # the runs that found it
    tools: list[str] = Field(default_factory=list)  # their tools, e.g. ["NMAP"]
    evidence: list[EvidenceOut] = Field(default_factory=list)
    latest_validation: ValidationRunOut | None = None  # the newest check, if any


class FindingReview(BaseModel):
    """A person's review of a finding."""

    finding_status: FindingStatus


class FindingFilters(BaseModel):
    """GET /findings filters; each one given must match."""

    assessment_id: UUID | None = None
    severity_status: SeverityStatus | None = None
    validation_status: ValidationStatus | None = None
    finding_status: FindingStatus | None = None
    tool: str | None = Field(default=None, max_length=100)  # one of the tools that found it
    target: str | None = Field(default=None, max_length=200)  # part of the target
    q: str | None = Field(default=None, max_length=200)  # part of the code, title, target,
    # description or a CWE id
