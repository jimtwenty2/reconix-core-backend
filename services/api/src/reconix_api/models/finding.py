"""findings, finding_sources, evidences and validation_runs."""

import uuid
from datetime import datetime
from decimal import Decimal

from sqlalchemy import Column, DateTime, ForeignKey, Numeric, String, Table, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from reconix_api.models.base import Base, created_at, json_default, pg_enum, uuid_pk
from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (UniqueConstraint("assessment_id", "dedupe_key"),)

    finding_id: Mapped[uuid.UUID] = uuid_pk()
    code: Mapped[str] = mapped_column(String(100))  # e.g. RCX-001
    title: Mapped[str] = mapped_column(Text)
    target: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    severity_status: Mapped[SeverityStatus] = mapped_column(
        pg_enum(SeverityStatus, "severity_status"),
        server_default=SeverityStatus.UNKNOWN,
        index=True,
    )
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 1))  # 0.0 to 10.0
    cwe_ids: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    owasp_id: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    cve_ids: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    # Same as the newest validation run.
    validation_status: Mapped[ValidationStatus] = mapped_column(
        pg_enum(ValidationStatus, "validation_status"),
        server_default=ValidationStatus.UNCONFIRMED,
    )
    finding_status: Mapped[FindingStatus] = mapped_column(
        pg_enum(FindingStatus, "finding_status"), server_default=FindingStatus.OPEN, index=True
    )
    reviewed_by: Mapped[str | None] = mapped_column(String(100))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dedupe_key: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = created_at()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assessments.assessment_id"))


# Which tool runs found which finding.
finding_sources = Table(
    "finding_sources",
    Base.metadata,
    Column("finding_id", ForeignKey("findings.finding_id"), primary_key=True),
    Column("tool_run_id", ForeignKey("tool_runs.tool_run_id"), primary_key=True),
)


class Evidence(Base):
    __tablename__ = "evidences"

    evidence_id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(String(50))  # e.g. http_response, screenshot
    content: Mapped[str | None] = mapped_column(Text)  # masked text evidence
    file_path: Mapped[str | None] = mapped_column(Text)
    location: Mapped[str | None] = mapped_column(Text)  # URL, host:port or line
    created_at: Mapped[datetime] = created_at()
    # Empty until linked to a finding.
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.finding_id"), index=True
    )
    tool_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tool_runs.tool_run_id"), index=True)


class ValidationRun(Base):
    __tablename__ = "validation_runs"

    validation_run_id: Mapped[uuid.UUID] = uuid_pk()
    method: Mapped[str] = mapped_column(String(30))  # e.g. poc, manual_review
    validation_status: Mapped[ValidationStatus] = mapped_column(
        pg_enum(ValidationStatus, "validation_status")
    )
    reason: Mapped[str | None] = mapped_column(Text)
    reviewed_by: Mapped[str | None] = mapped_column(String(100))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = created_at()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.finding_id"), index=True)
    # Empty for a manual review.
    tool_run_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("tool_runs.tool_run_id"))
