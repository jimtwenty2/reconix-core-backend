"""llm_providers and agent_runs."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    Text,
    false,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from reconix_api.models.base import Base, created_at, pg_enum, updated_at, uuid_pk
from reconix_api.models.enums import AgentRunStatus, ProviderType


class LlmProvider(Base):
    __tablename__ = "llm_providers"
    # Only one provider can be active at a time.
    __table_args__ = (
        Index(
            "uq_llm_providers_one_active",
            "is_active",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )

    llm_provider_id: Mapped[uuid.UUID] = uuid_pk()
    provider_type: Mapped[ProviderType] = mapped_column(pg_enum(ProviderType, "provider_type"))
    display_name: Mapped[str] = mapped_column(String(100))
    base_url: Mapped[str | None] = mapped_column(Text)  # empty for the built-in provider
    api_key_encrypted: Mapped[bytes | None] = mapped_column(LargeBinary)  # Fernet; never shown
    api_key_last4: Mapped[str | None] = mapped_column(String(4))
    model_name: Mapped[str] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(Boolean, server_default=false())
    created_by: Mapped[str] = mapped_column(String(100))
    created_at: Mapped[datetime] = created_at()
    updated_at: Mapped[datetime] = updated_at()


class AgentRun(Base):
    __tablename__ = "agent_runs"

    agent_run_id: Mapped[uuid.UUID] = uuid_pk()
    model_name: Mapped[str] = mapped_column(String(100))  # copy of the model used for this run
    checkpoint_id: Mapped[str | None] = mapped_column(Text)  # agent checkpoint for resume
    agent_runs_status: Mapped[AgentRunStatus] = mapped_column(
        pg_enum(AgentRunStatus, "agent_runs_status"), server_default=AgentRunStatus.RUNNING
    )
    started_at: Mapped[datetime] = created_at()
    plan: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.session_id"))
    # Empty before an assessment exists.
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assessments.assessment_id"), index=True
    )
    llm_provider_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("llm_providers.llm_provider_id"))
