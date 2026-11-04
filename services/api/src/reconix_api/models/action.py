"""actions, approvals and tool_runs."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    false,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from reconix_api.models.base import Base, created_at, json_default, pg_enum, uuid_pk
from reconix_api.models.enums import ActionStatus, ApprovalStatus, RiskLevel, ToolRunStatus


class Action(Base):
    __tablename__ = "actions"

    action_id: Mapped[uuid.UUID] = uuid_pk()
    tool: Mapped[str] = mapped_column(String(100))  # Kali catalog name, UPPERCASE, e.g. NMAP
    args: Mapped[list[str]] = mapped_column(JSONB, server_default=json_default("[]"))
    target: Mapped[str] = mapped_column(Text)
    purpose: Mapped[str] = mapped_column(Text)  # discovery, scan or validation
    risk_level: Mapped[RiskLevel | None] = mapped_column(pg_enum(RiskLevel, "risk_level"))
    action_status: Mapped[ActionStatus] = mapped_column(
        pg_enum(ActionStatus, "action_status"), server_default=ActionStatus.PENDING, index=True
    )
    guardrail_report: Mapped[dict[str, Any]] = mapped_column(
        JSONB, server_default=json_default("{}")
    )
    source: Mapped[str] = mapped_column(String(30), server_default="agent")
    created_at: Mapped[datetime] = created_at()
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assessments.assessment_id"), index=True
    )
    # The scope version in force when the action was made.
    manifest_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scope_manifests.manifest_id"))
    # Every action comes from an agent run.
    agent_run_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("agent_runs.agent_run_id"))


class Approval(Base):
    """One approval for one thing. Exactly one of the subject ids is set, matching `kind`."""

    __tablename__ = "approvals"

    approval_id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(
        String(20)
    )  # scope, action, disclosure, configuration, review
    subject_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB)  # masked copy
    subject_hash: Mapped[str] = mapped_column(String(64))  # SHA-256 of the snapshot
    risk_level: Mapped[RiskLevel | None] = mapped_column(pg_enum(RiskLevel, "risk_level"))
    approval_status: Mapped[ApprovalStatus] = mapped_column(
        pg_enum(ApprovalStatus, "approval_status"),
        server_default=ApprovalStatus.PENDING,
        index=True,
    )
    config_change: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    confirmation_verified: Mapped[bool] = mapped_column(Boolean, server_default=false())
    reason: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[str | None] = mapped_column(String(100))
    requested_at: Mapped[datetime] = created_at()
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # single use
    action_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("actions.action_id"))
    manifest_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scope_manifests.manifest_id"))
    # use_alter breaks the tool_runs -> approvals -> evidences -> tool_runs cycle.
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidences.evidence_id", use_alter=True)
    )
    report_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("reports.report_id"))


class ToolRun(Base):
    __tablename__ = "tool_runs"
    __table_args__ = (UniqueConstraint("action_id", "attempt_no"),)

    tool_run_id: Mapped[uuid.UUID] = uuid_pk()
    attempt_no: Mapped[int] = mapped_column(Integer, server_default="1")
    tool_run_status: Mapped[ToolRunStatus] = mapped_column(
        pg_enum(ToolRunStatus, "tool_run_status"), server_default=ToolRunStatus.PENDING
    )
    exit_code: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)
    masked_count: Mapped[int] = mapped_column(Integer, server_default="0")
    request_count: Mapped[int] = mapped_column(Integer, server_default="0")
    output_masked: Mapped[str | None] = mapped_column(Text)
    # Unique, so a job token can never be used twice.
    job_token_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), unique=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    action_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("actions.action_id"))
    # Empty when no approval is needed (LOW risk).
    approval_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("approvals.approval_id"), unique=True
    )
