"""Database access for approvals."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Approval
from reconix_api.models.enums import ApprovalStatus


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
