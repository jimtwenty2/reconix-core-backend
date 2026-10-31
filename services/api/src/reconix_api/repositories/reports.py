"""Database access for reports, report_assessments and their review approvals."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import func, insert, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Approval, Report, report_assessments
from reconix_api.models.enums import ReportStatus


def add(db: Db, report: Report, assessment_ids: list[UUID] | None = None) -> None:
    """The report and the assessments it covers (its own, then any combined with it)."""
    db.add(report)
    db.flush()
    for assessment_id in assessment_ids or [report.assessment_id]:
        db.execute(
            insert(report_assessments).values(
                report_id=report.report_id, assessment_id=assessment_id
            )
        )


def covered_assessments(db: Db, report_id: UUID) -> list[UUID]:
    query = select(report_assessments.c.assessment_id).where(
        report_assessments.c.report_id == report_id
    )
    return list(db.scalars(query))


def get(db: Db, report_id: UUID, lock: bool = False) -> Report | None:
    return db.get(Report, report_id, with_for_update=lock)


def list_by_assessment(db: Db, assessment_id: UUID) -> list[Report]:
    """Its own reports, newest version first, then combined reports that cover it."""
    covers = select(report_assessments.c.report_id).where(
        report_assessments.c.assessment_id == assessment_id
    )
    query = (
        select(Report)
        .where(Report.report_id.in_(covers))
        .order_by((Report.assessment_id != assessment_id), Report.created_at.desc())
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
