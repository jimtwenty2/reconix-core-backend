"""One helper so every state change writes the same audit fields."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from reconix_api.core.interfaces import AuditEvent, Operator, WriteAudit


def audit(
    write_audit: WriteAudit,
    event_type: str,
    operator: Operator,
    assessment_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """details must already be masked."""
    write_audit(
        AuditEvent(
            event_type=event_type,
            assessment_id=assessment_id,
            session_id=operator.session_id,
            role=operator.role,
            actor=operator.actor,
            at=datetime.now(UTC),
            details=details or {},
        )
    )
