"""SQLAlchemy tables, exactly as ERD V3 and Data Dictionary V3 (16 tables).

Import everything here so Alembic sees every table in Base.metadata.
"""

from reconix_api.models.action import Action, Approval, ToolRun
from reconix_api.models.agent import AgentRun, LlmProvider
from reconix_api.models.assessment import Assessment, ScopeManifest, ScopeTarget
from reconix_api.models.base import Base
from reconix_api.models.finding import Evidence, Finding, ValidationRun, finding_sources
from reconix_api.models.report import Report, report_assessments
from reconix_api.models.session import Message, Session

__all__ = [
    "Action",
    "AgentRun",
    "Approval",
    "Assessment",
    "Base",
    "Evidence",
    "Finding",
    "LlmProvider",
    "Message",
    "Report",
    "ScopeManifest",
    "ScopeTarget",
    "Session",
    "ToolRun",
    "ValidationRun",
    "finding_sources",
    "report_assessments",
]
