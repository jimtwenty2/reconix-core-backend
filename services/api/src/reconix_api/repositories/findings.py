"""Database access for findings, finding_sources and evidences."""

from uuid import UUID

from sqlalchemy import func, insert, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Evidence, Finding, finding_sources


def add(db: Db, row: Finding | Evidence) -> None:
    db.add(row)
    db.flush()


def get_by_dedupe_key(db: Db, assessment_id: UUID, dedupe_key: str) -> Finding | None:
    query = select(Finding).where(
        Finding.assessment_id == assessment_id, Finding.dedupe_key == dedupe_key
    )
    return db.scalars(query).first()


def count_in_assessment(db: Db, assessment_id: UUID) -> int:
    query = select(func.count()).select_from(Finding).where(Finding.assessment_id == assessment_id)
    return db.scalar(query) or 0


def add_source(db: Db, finding_id: UUID, tool_run_id: UUID) -> None:
    """Link a finding to the tool run that found it, once."""
    query = select(finding_sources).where(
        finding_sources.c.finding_id == finding_id, finding_sources.c.tool_run_id == tool_run_id
    )
    if db.execute(query).first() is None:
        db.execute(insert(finding_sources).values(finding_id=finding_id, tool_run_id=tool_run_id))


def list_by_assessment(db: Db, assessment_id: UUID) -> list[Finding]:
    query = (
        select(Finding)
        .where(Finding.assessment_id == assessment_id)
        .order_by(Finding.created_at, Finding.code)
    )
    return list(db.scalars(query))


def source_run_ids(db: Db, finding_id: UUID) -> list[UUID]:
    query = select(finding_sources.c.tool_run_id).where(finding_sources.c.finding_id == finding_id)
    return list(db.scalars(query))


def list_evidence(db: Db, finding_id: UUID) -> list[Evidence]:
    query = select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.created_at)
    return list(db.scalars(query))


def get(db: Db, finding_id: UUID, lock: bool = False) -> Finding | None:
    return db.get(Finding, finding_id, with_for_update=lock)


def list_all(db: Db) -> list[Finding]:
    return list(db.scalars(select(Finding).order_by(Finding.created_at.desc(), Finding.code)))


def get_evidence(db: Db, evidence_id: UUID) -> Evidence | None:
    return db.get(Evidence, evidence_id)
