"""assessments, scope_manifests and scope_targets."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, false
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from reconix_api.models.base import Base, created_at, json_default, pg_enum, updated_at, uuid_pk
from reconix_api.models.enums import AssessmentStatus, ManifestStatus, RiskLevel


class Assessment(Base):
    __tablename__ = "assessments"

    assessment_id: Mapped[uuid.UUID] = uuid_pk()
    engagement_code: Mapped[str] = mapped_column(String(50), unique=True)  # e.g. RCX-2026-0042
    name: Mapped[str] = mapped_column(String(200))
    type: Mapped[str] = mapped_column(String(60))  # e.g. web_url, network
    assessment_status: Mapped[AssessmentStatus] = mapped_column(
        pg_enum(AssessmentStatus, "assessment_status"),
        server_default=AssessmentStatus.DRAFT,
        index=True,
    )
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()
    # One assessment per session.
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.session_id"), unique=True)


class ScopeManifest(Base):
    __tablename__ = "scope_manifests"
    __table_args__ = (UniqueConstraint("session_id", "version"),)

    manifest_id: Mapped[uuid.UUID] = uuid_pk()
    version: Mapped[int] = mapped_column(Integer, server_default="1")
    manifests_status: Mapped[ManifestStatus] = mapped_column(
        pg_enum(ManifestStatus, "manifests_status"), server_default=ManifestStatus.DRAFT
    )
    max_risk: Mapped[RiskLevel] = mapped_column(
        pg_enum(RiskLevel, "risk_level"), server_default=RiskLevel.LOW
    )
    allowed_tools: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    # The ports nmap may scan; empty puts no limit on ports.
    allowed_ports: Mapped[list[int]] = mapped_column(JSONB, server_default=json_default("[]"))
    allowed_actions: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    allowed_methods: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    limitations: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(String(100))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reject_reason: Mapped[str | None] = mapped_column(Text)
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.session_id"))
    # One scope manifest per assessment; empty while draft.
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assessments.assessment_id"), unique=True
    )


class ScopeTarget(Base):
    __tablename__ = "scope_targets"

    scope_target_id: Mapped[uuid.UUID] = uuid_pk()
    type: Mapped[str] = mapped_column(String(20))  # domain, ip, cidr, url or path
    value: Mapped[str] = mapped_column(Text)
    excluded: Mapped[bool] = mapped_column(Boolean, server_default=false())
    manifest_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scope_manifests.manifest_id"), index=True
    )
