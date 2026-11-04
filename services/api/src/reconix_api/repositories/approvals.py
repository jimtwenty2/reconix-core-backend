"""Database access for approvals."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import (
    Action,
    Approval,
    Assessment,
    Evidence,
    Finding,
    Report,
    ScopeManifest,
)
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


def assessment_of(db: Db, approval: Approval) -> UUID | None:
    """The assessment the approval belongs to, through the action, scope, report or
    evidence it is for. None for a settings change, which has no assessment."""
    if approval.action_id is not None:
        query = select(Action.assessment_id).where(Action.action_id == approval.action_id)
    elif approval.manifest_id is not None:
        query = select(ScopeManifest.assessment_id).where(
            ScopeManifest.manifest_id == approval.manifest_id
        )
    elif approval.report_id is not None:
        query = select(Report.assessment_id).where(Report.report_id == approval.report_id)
    elif approval.evidence_id is not None:
        query = (
            select(Finding.assessment_id)
            .join(Evidence, Evidence.finding_id == Finding.finding_id)
            .where(Evidence.evidence_id == approval.evidence_id)
        )
    else:
        return None
    return db.scalar(query)


def latest_for_manifest(db: Db, manifest_id: UUID) -> Approval | None:
    """The newest scope approval asked for this manifest, locked until commit."""
    return db.scalar(
        select(Approval)
        .where(Approval.manifest_id == manifest_id)
        .order_by(Approval.requested_at.desc())
        .limit(1)
        .with_for_update()
    )


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


LIMITS_LOCK = 0x5243584C  # "RCXL": one limit change is applied at a time


def lock_limit_changes(db: Db) -> None:
    """Held until commit, so two approved limit changes cannot both start from the same limits."""
    db.execute(select(func.pg_advisory_xact_lock(LIMITS_LOCK)))


def latest_limit_change(db: Db) -> Approval | None:
    """The newest approved and used loop limit change: its config_change["after"] is in use."""
    return db.scalar(
        select(Approval)
        .where(
            Approval.kind == "configuration",
            Approval.approval_status == ApprovalStatus.APPROVED,
            Approval.consumed_at.is_not(None),
            Approval.config_change["setting"].astext == "loop_limits",
        )
        .order_by(Approval.consumed_at.desc())
        .limit(1)
    )


def pending_limit_changes(db: Db, requested_after: datetime) -> list[Approval]:
    """Loop limit changes still waiting for a person (asked for after requested_after)."""
    return list(
        db.scalars(
            select(Approval)
            .where(
                Approval.kind == "configuration",
                Approval.approval_status == ApprovalStatus.PENDING,
                Approval.requested_at > requested_after,
                Approval.config_change["setting"].astext == "loop_limits",
            )
            .order_by(Approval.requested_at.desc())
        )
    )
