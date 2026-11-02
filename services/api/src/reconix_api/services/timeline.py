"""An assessment's timeline, for the web's Overview: its audit log lines, oldest first."""

from pathlib import Path
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session as Db

from reconix_api.core import timeline
from reconix_api.core.errors import ApiError
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.schemas.timeline import TimelineEventOut, TimelineOut


def read_timeline(
    db: Db, audit_log_path: str | Path, assessment_id: UUID, event_types: list[str], limit: int
) -> TimelineOut:
    if assessment_repo.get(db, assessment_id) is None:
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "No assessment with this id.")
    lines, has_older = timeline.read(audit_log_path, assessment_id, event_types, limit)
    events = [event for event in map(event_out, lines) if event is not None]
    return TimelineOut(events=events, has_older=has_older)


def event_out(line: dict) -> TimelineEventOut | None:
    """None for a line whose fields have the wrong type: the log is read, never trusted."""
    try:
        return TimelineEventOut.model_validate(line)
    except ValidationError:
        return None
