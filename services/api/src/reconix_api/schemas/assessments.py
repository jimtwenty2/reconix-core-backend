"""Read-only views of an assessment for the dashboard: its list row and its overview.

AssessmentOut itself lives in schemas/scopes.py, where submitting a scope makes one.
"""

from datetime import datetime

from pydantic import BaseModel

from reconix_api.models.enums import (
    ActionStatus,
    FindingStatus,
    SeverityStatus,
    ValidationStatus,
)
from reconix_api.schemas.scopes import AssessmentOut


class AssessmentRowOut(AssessmentOut):
    """One row of GET /assessments: the assessment and what its list row shows. False
    positives are left out of finding_count and worst_severity, as the web does."""

    targets: list[str]  # the approved scope's targets; [] before approval
    finding_count: int
    # CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN, NONE, worst first. None: no findings yet.
    worst_severity: SeverityStatus | None
    pending_approval_count: int  # PENDING and not expired yet
    plan_step_count: int  # steps in the newest plan; 0 without a plan
    plan_step_done_count: int  # COMPLETED actions of that plan
    # The newest of: the assessment's own update, an action asked for, a tool run started or
    # finished. An ACTIVE assessment quiet for a long time can be shown as interrupted.
    last_activity_at: datetime


class AssessmentOverviewOut(BaseModel):
    """Everything the run overview counts, in one call. Every status is a key, 0 when none.
    findings_by_status counts every finding; the other finding counts leave out false
    positives, as the web does."""

    assessment: AssessmentOut
    targets: list[str]
    finding_count: int
    findings_by_severity: dict[SeverityStatus, int]
    findings_by_validation: dict[ValidationStatus, int]
    findings_by_status: dict[FindingStatus, int]
    actions_by_status: dict[ActionStatus, int]
    plan_step_count: int  # steps in the newest plan; 0 without a plan
    plan_step_done_count: int  # COMPLETED actions of that plan
    tool_run_count: int
    request_count: int  # requests the tools sent, over all runs
    masked_count: int  # secrets masked in the tools' output, over all runs
    pending_approval_count: int
    first_started_at: datetime | None  # the first tool run's start
    last_finished_at: datetime | None  # the last tool run's end
    duration_seconds: int  # last_finished_at - first_started_at; 0 before a tool run ends
    time_window_seconds: int | None  # approved scope's ends_at - starts_at; None: no window
    over_time_window: bool  # duration_seconds is longer than time_window_seconds
