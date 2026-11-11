"""Request and response shapes for /sessions/{id}/code-fixes and /code-fixes (VS Code).

A fix run is an agent run with plan = {"task": "CODE_FIX", ...}. Nothing is written to the
person's files or to the stored code: the result is line edits VS Code shows as a diff.
"""

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.models.enums import AgentRunStatus

MAX_FIX_FINDINGS = 200


class CodeFixIn(BaseModel):
    # Finding ids of the session's latest finished code scan.
    finding_ids: list[UUID] = Field(min_length=1, max_length=MAX_FIX_FINDINGS)


class CodeFixStarted(BaseModel):
    agent_run_id: UUID  # the fix run


class FixStatus(StrEnum):
    FIXED = "FIXED"  # the scanners no longer report it
    STILL_REPORTED = "STILL_REPORTED"  # the scanners still report it after the change
    NOT_VERIFIED = "NOT_VERIFIED"  # changed, but it could not be rechecked
    NOT_FIXED = "NOT_FIXED"  # its file was not changed; the note says why


class FixEdit(BaseModel):
    start_line: int = Field(ge=1)  # 1-based, whole lines, inclusive
    end_line: int = Field(ge=1)
    replacement: str  # the new text of those lines, no final newline; "" deletes them


class FileFix(BaseModel):
    path: str  # relative to the workspace, forward slashes
    file_sha256: str  # of the file the edits were made for: apply only to that file
    edits: list[FixEdit]  # sorted, never overlapping


class FixOutcome(BaseModel):
    finding_id: UUID
    status: FixStatus
    note: str  # one plain sentence


class CodeFixResult(BaseModel):
    files: list[FileFix]
    summary: str  # Markdown: what changed and why
    results: list[FixOutcome]  # one per requested finding


class CodeFixOut(BaseModel):
    agent_run_id: UUID
    agent_runs_status: AgentRunStatus  # RUNNING, COMPLETED, FAILED or CANCELLED
    started_at: datetime
    finished_at: datetime | None
    session_id: UUID
    assessment_id: UUID
    finding_count: int
    error: str | None  # why it FAILED, as an error code, e.g. "MODEL_UNAVAILABLE"
    result: CodeFixResult | None  # only when COMPLETED


class EventKind(StrEnum):
    START = "START"  # an agent starts on a file ("3 findings")
    THINKING = "THINKING"  # a streamed piece of reasoning
    TEXT = "TEXT"  # a streamed piece of the answer
    TOOL = "TOOL"  # one tool call ("Edit db.py")
    RESULT = "RESULT"  # the last tool's result ("+2 −1 lines")
    STATUS = "STATUS"  # about the whole request
    DONE = "DONE"  # an agent finished ("Finished 2 of 5 files")
    HEARTBEAT = "HEARTBEAT"  # nothing to show; keeps the stream open


class CodeFixEvent(BaseModel):
    """One line of the live transcript (GET /code-fixes/{id}/events)."""

    agent_run_id: UUID
    seq: int  # 1, 2, 3 ... in order; reconnect with ?after=<last seq seen>
    file: str | None  # the file an agent works on, or None for the whole request
    kind: EventKind
    text: str  # masked
