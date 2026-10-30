"""Database access for reports, report_assessments and their review approvals."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, insert, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Approval, Report, report_assessments
from reconix_api.models.enums import ReportStatus


def add(db: Db, report: Report) -> None:
    db.add(report)
    db.flush()
    db.execute(
        insert(report_assessments).values(
            report_id=report.report_id, assessment_id=report.assessment_id
        )
    )


def get(db: Db, report_id: UUID, lock: bool = False) -> Report | None:
    return db.get(Report, report_id, with_for_update=lock)


def list_by_assessment(db: Db, assessment_id: UUID) -> list[Report]:
    query = (
        select(Report).where(Report.assessment_id == assessment_id).order_by(Report.version.desc())
    )
    return list(db.scalars(query))


def next_version(db: Db, assessment_id: UUID) -> int:
    query = select(func.max(Report.version)).where(Report.assessment_id == assessment_id)
    return (db.scalar(query) or 0) + 1


def generating_before(db: Db, assessment_id: UUID, cutoff: datetime) -> list[Report]:
    query = select(Report).where(
        Report.assessment_id == assessment_id,
        Report.report_status == ReportStatus.GENERATING,
        Report.created_at < cutoff,
    )
    return list(db.scalars(query))


def review_for(db: Db, report_id: UUID) -> Approval | None:
    """The newest review approval of a report."""
    query = (
        select(Approval)
        .where(Approval.report_id == report_id, Approval.kind == "review")
        .order_by(Approval.requested_at.desc())
        .limit(1)
    )
    return db.scalar(query)
