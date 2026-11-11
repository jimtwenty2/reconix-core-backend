"""Assessments: list, read, rename or complete, and cancel. Also the dashboard's read-only
views: the list rows and one assessment's overview."""

from collections import defaultdict
from datetime import datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.models import Assessment, Finding
from reconix_api.models.enums import (
    ActionStatus,
    ApprovalStatus,
    AssessmentStatus,
    FindingStatus,
    SeverityStatus,
    ValidationStatus,
)
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as finding_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.schemas.assessments import AssessmentOverviewOut, AssessmentRowOut
from reconix_api.schemas.scopes import AssessmentOut, AssessmentUpdate
from reconix_api.services.approvals import still_open_after
from reconix_api.services.audit import audit

FINISHED = (AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLED)
# Worst first. UNKNOWN (the tool gave no severity) ranks below LOW, above NONE.
WORST_FIRST = (
    SeverityStatus.CRITICAL,
    SeverityStatus.HIGH,
    SeverityStatus.MEDIUM,
    SeverityStatus.LOW,
    SeverityStatus.UNKNOWN,
    SeverityStatus.NONE,
)


def list_assessments(
    db: Db,
    status: AssessmentStatus | None,
    ttl_minutes: int,
    type_: str | None = None,
    q: str | None = None,
) -> list[AssessmentRowOut]:
    """Newest first. `q` matches the engagement code, the name or a target, ignoring case.
    The counts come from a few grouped queries; only the plan progress is read per row.
    False positives are left out of the finding count and the worst severity."""
    assessments = assessment_repo.list_all(db, status, type_)
    targets = scope_repo.approved_targets(db, [row.assessment_id for row in assessments])
    if q:
        assessments = [row for row in assessments if matches(row, targets, q)]
    ids = [row.assessment_id for row in assessments]
    if not ids:
        return []
    severities = finding_counts(db, Finding.severity_status, ids)
    pending = approval_repo.count_waiting(db, ids, still_open_after(ttl_minutes))
    activity = action_repo.last_activity(db, ids)
    rows = []
    for row in assessments:
        step_count, step_done_count = plan_progress(db, row.assessment_id)
        last_action = activity.get(row.assessment_id)
        rows.append(
            AssessmentRowOut(
                **_out(row).model_dump(),
                targets=targets.get(row.assessment_id, []),
                finding_count=sum(severities[row.assessment_id].values()),
                worst_severity=worst(severities[row.assessment_id]),
                pending_approval_count=pending.get(row.assessment_id, 0),
                plan_step_count=step_count,
                plan_step_done_count=step_done_count,
                last_activity_at=max(row.updated_at, last_action or row.updated_at),
            )
        )
    return rows


def matches(row: Assessment, targets: dict[UUID, list[str]], q: str) -> bool:
    """True when q is in the engagement code, the name or one target, ignoring case."""
    words = [row.engagement_code, row.name, *targets.get(row.assessment_id, [])]
    return any(q.lower() in word.lower() for word in words)


def overview(db: Db, assessment_id: UUID, ttl_minutes: int) -> AssessmentOverviewOut:
    """findings_by_status counts every finding; the other finding counts leave out
    false positives."""
    assessment = _get(db, assessment_id)
    ids = [assessment_id]
    severities = finding_counts(db, Finding.severity_status, ids)[assessment_id]
    validations = finding_counts(db, Finding.validation_status, ids)[assessment_id]
    statuses = by_assessment(finding_repo.count_by(db, Finding.finding_status, ids))
    runs = action_repo.tool_run_totals(db, assessment_id)
    step_count, step_done_count = plan_progress(db, assessment_id)
    pending = approval_repo.count_waiting(db, ids, still_open_after(ttl_minutes))
    duration = seconds_between(runs.first_started_at, runs.last_finished_at) or 0
    scope = scope_repo.get_approved(db, assessment_id)
    window = seconds_between(scope.starts_at, scope.ends_at) if scope else None
    return AssessmentOverviewOut(
        assessment=_out(assessment),
        targets=scope_repo.approved_targets(db, ids).get(assessment_id, []),
        finding_count=sum(severities.values()),
        findings_by_severity=every(SeverityStatus, severities),
        findings_by_validation=every(ValidationStatus, validations),
        findings_by_status=every(FindingStatus, statuses[assessment_id]),
        actions_by_status=every(ActionStatus, action_repo.count_by_status(db, assessment_id)),
        plan_step_count=step_count,
        plan_step_done_count=step_done_count,
        tool_run_count=runs.tool_run_count,
        request_count=runs.request_count,
        masked_count=runs.masked_count,
        pending_approval_count=pending.get(assessment_id, 0),
        first_started_at=runs.first_started_at,
        last_finished_at=runs.last_finished_at,
        duration_seconds=duration,
        time_window_seconds=window,
        over_time_window=window is not None and duration > window,
    )


def seconds_between(start: datetime | None, end: datetime | None) -> int | None:
    """Whole seconds from start to end, never below 0. None when either is missing."""
    if start is None or end is None:
        return None
    return max(0, int((end - start).total_seconds()))


def update_assessment(
    db: Db, write_audit: WriteAudit, operator: Operator, assessment_id: UUID, body: AssessmentUpdate
) -> AssessmentOut:
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    assessment = _get_open(db, assessment_id)
    if "assessment_status" in changes and assessment.assessment_status != AssessmentStatus.ACTIVE:
        raise ApiError(409, "ASSESSMENT_NOT_ACTIVE", "Only an ACTIVE assessment can be completed.")
    for field, value in changes.items():
        setattr(assessment, field, value)
    db.commit()
    audit(write_audit, "ASSESSMENT_UPDATED", operator, assessment_id, {"fields": sorted(changes)})
    return _out(assessment)


def cancel_assessment(
    db: Db, write_audit: WriteAudit, operator: Operator, assessment_id: UUID
) -> AssessmentOut:
    """Cancelled, never erased: its actions, findings and audit lines stay. Its PENDING
    scope approval expires with it, so approving it later cannot bring the assessment back.
    (A waiting action's approval is refused when someone tries it: ensure_can_act.)"""
    assessment = _get_open(db, assessment_id)
    expired = approval_repo.pending_scope_approvals(db, assessment_id)
    for approval in expired:
        approval.approval_status = ApprovalStatus.EXPIRED
    assessment.assessment_status = AssessmentStatus.CANCELLED
    db.commit()
    details = {"expired_scope_approvals": ",".join(str(a.approval_id) for a in expired)}
    audit(
        write_audit, "ASSESSMENT_CANCELLED", operator, assessment_id, details if expired else None
    )
    return _out(assessment)


def plan_progress(db: Db, assessment_id: UUID) -> tuple[int, int]:
    """(steps in the newest plan, how many of its actions are COMPLETED)."""
    run = agent_run_repo.latest_plan(db, assessment_id)
    if run is None:
        return 0, 0
    steps = len((run.plan or {}).get("steps", []))
    actions = action_repo.list_by_agent_run(db, run.agent_run_id)
    done = sum(1 for action in actions if action.action_status == ActionStatus.COMPLETED)
    return steps, min(done, steps)


def finding_counts(
    db: Db, column: InstrumentedAttribute, ids: list[UUID]
) -> dict[UUID, dict[str, int]]:
    """Counts of one finding column per assessment, false positives left out."""
    return by_assessment(finding_repo.count_by(db, column, ids, without_false_positives=True))


def by_assessment(counts: list[tuple[UUID, str, int]]) -> dict[UUID, dict[str, int]]:
    grouped: dict[UUID, dict[str, int]] = defaultdict(dict)
    for assessment_id, value, count in counts:
        grouped[assessment_id][value] = count
    return grouped


def every(enum: type[StrEnum], counts: dict[str, int]) -> dict[str, int]:
    """Each value of the enum, in its order, with 0 for the missing ones."""
    return {member.value: counts.get(member, 0) for member in enum}


def worst(severities: dict[str, int]) -> SeverityStatus | None:
    return next((level for level in WORST_FIRST if severities.get(level)), None)


def _get(db: Db, assessment_id: UUID) -> Assessment:
    assessment = assessment_repo.get(db, assessment_id)
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    return assessment


def _get_open(db: Db, assessment_id: UUID) -> Assessment:
    assessment = assessment_repo.get_for_update(db, assessment_id)
    if assessment is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    if assessment.assessment_status in FINISHED:
        raise ApiError(
            409,
            "ASSESSMENT_FINISHED",
            "This assessment is already completed or cancelled.",
            {"assessment_status": assessment.assessment_status},
        )
    return assessment


def _out(assessment: Assessment) -> AssessmentOut:
    return AssessmentOut.model_validate(assessment, from_attributes=True)
