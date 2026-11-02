"""An assessment's timeline: what happened, from the audit log."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from pydantic import Field

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.security import CurrentOperator
from reconix_api.schemas.timeline import TimelineOut
from reconix_api.services import timeline

router = APIRouter(tags=["assessments"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]
EventType = Annotated[str, Field(pattern=r"^[A-Z_]{1,64}$")]  # e.g. SCOPE_APPROVED
MAX_EVENTS = 2000


@router.get("/assessments/{assessment_id}/timeline")
def read_timeline(
    assessment_id: UUID,
    db: Db,
    _: CurrentOperator,
    settings: CurrentSettings,
    event_type: Annotated[list[EventType] | None, Query(max_length=50)] = None,
    limit: Annotated[int, Query(ge=1, le=MAX_EVENTS)] = 500,
) -> TimelineOut:
    """Returns the assessment's audit log lines, oldest first. You get at most the newest `limit`
    lines, and has_older tells you when older ones were left out. Repeat ?event_type= to keep
    only those event types. Lines are masked when they are written and again when they are read."""
    return timeline.read_timeline(
        db, settings.audit_log_path, assessment_id, event_type or [], limit
    )
