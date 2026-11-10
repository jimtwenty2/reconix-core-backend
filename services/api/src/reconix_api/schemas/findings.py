"""Request and response shapes for /findings and /evidence."""

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, computed_field

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


class Confidence(StrEnum):
    """How trustworthy a finding is, derived at read time (never stored, like the code
    Verdict). It ranks a report so confirmed and firm findings sit above tentative guesses.

    - CONFIRMED:     a validation run confirmed it (an OOB callback, sqlmap, a dalfox verify).
    - FIRM:          strong deterministic signal with no validation yet — a verifying tool
                     (sqlmap/dalfox/commix/schemathesis/nuclei -dast), or two or more tools agree.
    - TENTATIVE:     a single scanner's unvalidated match.
    - INFORMATIONAL: a fact, not a weakness (NONE severity: ports, stack, paths, hidden
                     parameters), or a finding a person marked a false positive.
    """

    CONFIRMED = "CONFIRMED"
    FIRM = "FIRM"
    TENTATIVE = "TENTATIVE"
    INFORMATIONAL = "INFORMATIONAL"


# Tools whose own output is a confirmation/exploitation attempt, not a passive match.
VERIFIER_TOOLS = frozenset({"SQLMAP", "DALFOX", "COMMIX", "SCHEMATHESIS", "NUCLEI_DAST"})


def confidence_of(
    validation_status: ValidationStatus,
    finding_status: FindingStatus,
    severity_status: SeverityStatus,
    tools: list[str],
) -> Confidence:
    """Derive the confidence tier. A validation and a person's verdict count first; then
    deterministic evidence (a verifier tool or agreement between tools); a bare fact or a
    dismissed finding is informational."""
    if validation_status == ValidationStatus.CONFIRMED:
        return Confidence.CONFIRMED
    if finding_status == FindingStatus.FALSE_POSITIVE or severity_status == SeverityStatus.NONE:
        return Confidence.INFORMATIONAL
    upper = {tool.upper() for tool in tools}
    if upper & VERIFIER_TOOLS or len(upper) >= 2:
        return Confidence.FIRM
    return Confidence.TENTATIVE


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

    @computed_field  # derived, not stored
    @property
    def confidence(self) -> Confidence:
        return confidence_of(
            self.validation_status, self.finding_status, self.severity_status, self.tools
        )


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
