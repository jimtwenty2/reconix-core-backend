"""Enum values from Data Dictionary V3. UPPERCASE everywhere.

RiskLevel and Role are shared with other parts, so they live in core/interfaces.py.
"""

from enum import StrEnum

from reconix_api.core.interfaces import RiskLevel, Role

__all__ = [
    "ActionStatus",
    "AgentRunStatus",
    "ApprovalStatus",
    "AssessmentStatus",
    "FindingStatus",
    "ManifestStatus",
    "ProviderType",
    "ReportStatus",
    "RiskLevel",
    "Role",
    "SessionStatus",
    "SeverityStatus",
    "ToolRunStatus",
    "ValidationStatus",
]


class SessionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    CLOSED = "CLOSED"


class AssessmentStatus(StrEnum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


class ManifestStatus(StrEnum):
    DRAFT = "DRAFT"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class AgentRunStatus(StrEnum):
    RUNNING = "RUNNING"
    WAITING_APPROVAL = "WAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ProviderType(StrEnum):
    RECONIX = "RECONIX"
    OPENAI = "OPENAI"
    ANTHROPIC = "ANTHROPIC"
    DEEPSEEK = "DEEPSEEK"
    OLLAMA = "OLLAMA"
    OPENAI_API_COMPATIBLE = "OPENAI_API_COMPATIBLE"


class ActionStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    BLOCKED = "BLOCKED"


class ToolRunStatus(StrEnum):
    """Status of a tool_runs row. core.interfaces.ToolRunStatus is only the final result."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    CANCELLED = "CANCELLED"


class ApprovalStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"


class SeverityStatus(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"
    NONE = "NONE"


class ValidationStatus(StrEnum):
    CONFIRMED = "CONFIRMED"
    UNCONFIRMED = "UNCONFIRMED"
    INCONCLUSIVE = "INCONCLUSIVE"


class FindingStatus(StrEnum):
    OPEN = "OPEN"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"


class ReportStatus(StrEnum):
    GENERATING = "GENERATING"
    READY = "READY"
    FAILED = "FAILED"
