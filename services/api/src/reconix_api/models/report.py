"""reports and report_assessments."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from reconix_api.models.base import Base, created_at, json_default, pg_enum, uuid_pk
from reconix_api.models.enums import ReportStatus


class Report(Base):
    __tablename__ = "reports"
    __table_args__ = (UniqueConstraint("assessment_id", "version"),)

    report_id: Mapped[uuid.UUID] = uuid_pk()
    version: Mapped[int] = mapped_column(Integer, server_default="1")
    report_status: Mapped[ReportStatus] = mapped_column(
        pg_enum(ReportStatus, "report_status"), server_default=ReportStatus.GENERATING
    )
    executive_summary: Mapped[str | None] = mapped_column(Text)
    methodology: Mapped[str | None] = mapped_column(Text)
    snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)  # frozen, masked copy of findings
    snapshot_hash: Mapped[str] = mapped_column(String(64))  # SHA-256 of the snapshot
    exports: Mapped[dict[str, str]] = mapped_column(JSONB, server_default=json_default("{}"))
    generated_by: Mapped[str] = mapped_column(String(100))
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # when READY
    created_at: Mapped[datetime] = created_at()
    assessment_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assessments.assessment_id"))
    manifest_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scope_manifests.manifest_id"))


# The 2 to 5 assessments a combined report covers.
report_assessments = Table(
    "report_assessments",
    Base.metadata,
    Column("assessment_id", ForeignKey("assessments.assessment_id"), primary_key=True),
    Column("report_id", ForeignKey("reports.report_id"), primary_key=True),
)
