"""Database access for assessments."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Assessment
from reconix_api.models.enums import AssessmentStatus


def add(db: Db, assessment: Assessment) -> Assessment:
    db.add(assessment)
    db.flush()
    return assessment


def get(db: Db, assessment_id: UUID) -> Assessment | None:
    return db.get(Assessment, assessment_id)


def lock(db: Db, assessment_id: UUID) -> None:
    """Hold the assessment row until commit, so other runs wait to add findings to it."""
    db.execute(
        select(Assessment.assessment_id)
        .where(Assessment.assessment_id == assessment_id)
        .with_for_update()
    )


def get_by_session(db: Db, session_id: UUID) -> Assessment | None:
    return db.scalar(select(Assessment).where(Assessment.session_id == session_id))


def latest_engagement_code(db: Db, prefix: str) -> str | None:
    """The highest code that starts with prefix, e.g. 'RCX-2026-'."""
    return db.scalar(
        select(func.max(Assessment.engagement_code)).where(
            Assessment.engagement_code.startswith(prefix)
        )
    )


def list_all(db: Db, status: AssessmentStatus | None = None) -> list[Assessment]:
    query = select(Assessment).order_by(Assessment.created_at.desc())
    if status is not None:
        query = query.where(Assessment.assessment_status == status)
    return list(db.scalars(query))


def get_for_update(db: Db, assessment_id: UUID) -> Assessment | None:
    return db.get(Assessment, assessment_id, with_for_update=True)
