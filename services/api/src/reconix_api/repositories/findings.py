"""Database access for findings, finding_sources and evidences."""

from uuid import UUID

from sqlalchemy import func, insert, select
from sqlalchemy.orm import InstrumentedAttribute
from sqlalchemy.orm import Session as Db

from reconix_api.models import Action, Evidence, Finding, ToolRun, finding_sources
from reconix_api.models.enums import FindingStatus, SeverityStatus, ValidationStatus


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
    return list_matching(db, assessment_id)


def sources(db: Db, finding_id: UUID) -> list[tuple[UUID, str]]:
    """(tool_run_id, tool) of every run that found it, e.g. (..., "NMAP")."""
    query = (
        select(finding_sources.c.tool_run_id, Action.tool)
        .join(ToolRun, ToolRun.tool_run_id == finding_sources.c.tool_run_id)
        .join(Action, Action.action_id == ToolRun.action_id)
        .where(finding_sources.c.finding_id == finding_id)
    )
    return [(row[0], row[1]) for row in db.execute(query)]


def source_outputs(db: Db, finding_ids: list[UUID], limit: int) -> list[str]:
    """The masked output of the newest tool runs that found these findings."""
    query = (
        select(ToolRun.output_masked)
        .join(finding_sources, finding_sources.c.tool_run_id == ToolRun.tool_run_id)
        .where(finding_sources.c.finding_id.in_(finding_ids), ToolRun.output_masked.is_not(None))
        .group_by(ToolRun.tool_run_id)
        .order_by(func.max(ToolRun.finished_at).desc().nulls_last())
        .limit(limit)
    )
    return list(db.scalars(query))


def list_evidence(db: Db, finding_id: UUID) -> list[Evidence]:
    query = select(Evidence).where(Evidence.finding_id == finding_id).order_by(Evidence.created_at)
    return list(db.scalars(query))


def get(db: Db, finding_id: UUID, lock: bool = False) -> Finding | None:
    return db.get(Finding, finding_id, with_for_update=lock)


def get_evidence(db: Db, evidence_id: UUID) -> Evidence | None:
    return db.get(Evidence, evidence_id)


def list_matching(
    db: Db,
    assessment_id: UUID | None = None,
    severity_status: SeverityStatus | None = None,
    validation_status: ValidationStatus | None = None,
    finding_status: FindingStatus | None = None,
) -> list[Finding]:
    """Every finding newest first, or one assessment's in the order they were found. Each
    value given must match."""
    query = select(Finding)
    if assessment_id is None:
        query = query.order_by(Finding.created_at.desc(), Finding.code)
    else:
        query = query.where(Finding.assessment_id == assessment_id)
        query = query.order_by(Finding.created_at, Finding.code)
    if severity_status is not None:
        query = query.where(Finding.severity_status == severity_status)
    if validation_status is not None:
        query = query.where(Finding.validation_status == validation_status)
    if finding_status is not None:
        query = query.where(Finding.finding_status == finding_status)
    return list(db.scalars(query))


def count_by(
    db: Db,
    column: InstrumentedAttribute,
    assessment_ids: list[UUID],
    without_false_positives: bool = False,
) -> list[tuple[UUID, str, int]]:
    """(assessment_id, value, count) for one column, e.g. Finding.severity_status."""
    query = (
        select(Finding.assessment_id, column, func.count())
        .where(Finding.assessment_id.in_(assessment_ids))
        .group_by(Finding.assessment_id, column)
    )
    if without_false_positives:
        query = query.where(Finding.finding_status != FindingStatus.FALSE_POSITIVE)
    return [(row[0], row[1], row[2]) for row in db.execute(query)]
