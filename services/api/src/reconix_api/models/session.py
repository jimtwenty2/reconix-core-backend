"""sessions and messages."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from reconix_api.models.base import Base, created_at, json_default, pg_enum, uuid_pk
from reconix_api.models.enums import SessionStatus


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[uuid.UUID] = uuid_pk()
    interface: Mapped[str] = mapped_column(String(20))  # web or cli
    session_status: Mapped[SessionStatus] = mapped_column(
        pg_enum(SessionStatus, "session_status"), server_default=SessionStatus.ACTIVE
    )
    created_at: Mapped[datetime] = created_at()
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Message(Base):
    __tablename__ = "messages"
    __table_args__ = (UniqueConstraint("session_id", "sequence_no"),)

    message_id: Mapped[uuid.UUID] = uuid_pk()
    sequence_no: Mapped[int] = mapped_column(Integer)
    role: Mapped[str] = mapped_column(String(20))  # user, assistant or system
    content_masked: Mapped[str] = mapped_column(Text)
    metadata_: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, server_default=json_default("{}")
    )
    created_at: Mapped[datetime] = created_at()
    session_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("sessions.session_id"))
