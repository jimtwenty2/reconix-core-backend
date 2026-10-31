"""Database access for approvals."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Action, Approval, Assessment, Report, ScopeManifest
from reconix_api.models.enums import ApprovalStatus, AssessmentStatus

FINISHED = (AssessmentStatus.COMPLETED, AssessmentStatus.CANCELLED)


def add(db: Db, approval: Approval) -> Approval:
    db.add(approval)
    db.flush()
    return approval


def get(db: Db, approval_id: UUID) -> Approval | None:
    return db.get(Approval, approval_id)


def get_for_update(db: Db, approval_id: UUID) -> Approval | None:
    """Locks the row until commit, so an approval cannot be decided twice at once."""
    return db.scalar(select(Approval).where(Approval.approval_id == approval_id).with_for_update())


def list_by_status(db: Db, status: ApprovalStatus, kind: str | None = None) -> list[Approval]:
    query = (
        select(Approval)
        .where(Approval.approval_status == status)
        .order_by(Approval.requested_at.desc())
    )
    if kind is not None:
        query = query.where(Approval.kind == kind)
    return list(db.scalars(query))


def count_waiting(db: Db, assessment_ids: list[UUID], requested_after: datetime) -> dict[UUID, int]:
    """PENDING approvals asked for after requested_after (not expired yet), per assessment
    that is not finished: an approval belongs to the assessment of its action, scope or
    report."""
    owner = func.coalesce(Action.assessment_id, ScopeManifest.assessment_id, Report.assessment_id)
    query = (
        select(owner, func.count())
        .select_from(Approval)
        .outerjoin(Action, Approval.action_id == Action.action_id)
        .outerjoin(ScopeManifest, Approval.manifest_id == ScopeManifest.manifest_id)
        .outerjoin(Report, Approval.report_id == Report.report_id)
        .join(Assessment, Assessment.assessment_id == owner)
        .where(
            Approval.approval_status == ApprovalStatus.PENDING,
            Approval.requested_at > requested_after,
            owner.in_(assessment_ids),
            Assessment.assessment_status.not_in(FINISHED),
        )
        .group_by(owner)
    )
    return {row[0]: row[1] for row in db.execute(query)}
