"""Request and response shapes for /sessions/{id}/code and /code-scans (VS Code)."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field

from reconix_api.core.code_files import MAX_FILES, MAX_PATH
from reconix_api.models.enums import AgentRunStatus, SeverityStatus
from reconix_api.schemas.findings import FindingOut


class CodeFileIn(BaseModel):
    """One file the workspace has now."""

    path: str = Field(min_length=1, max_length=MAX_PATH)  # relative, forward slashes
    size_bytes: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class CodeSync(BaseModel):
    files: list[CodeFileIn] = Field(max_length=MAX_FILES)


class CodeSyncOut(BaseModel):
    missing: list[str]  # upload these, as a tar.gz to PUT /sessions/{id}/code
    target: str  # the folder for a "path" scope target and the semgrep and gitleaks runs


class CodeUploadOut(BaseModel):
    files: int  # written by this upload
    size_bytes: int
    target: str


class CodeScanIn(BaseModel):
    analyze: bool = True  # also ask the agent to analyze the findings after the tools ran


class CodeScanOut(BaseModel):
    """A code scan is an agent run with plan = {"task": "CODE_SCAN", ...}. Poll it with
    GET /code-scans/{agent_run_id} until agent_runs_status is no longer RUNNING."""

    agent_run_id: UUID
    agent_runs_status: AgentRunStatus
    stage: Literal["SCANNING", "ANALYZING", "DONE"]
    progress: int  # 0..100, best effort
    started_at: datetime
    finished_at: datetime | None
    session_id: UUID
    assessment_id: UUID
    counts: dict[SeverityStatus, int]  # findings of this scan per severity
    notes: list[str]  # e.g. "GITLEAKS FAILED": a step that did not finish, while the scan did
    error: str | None  # why the scan FAILED, as an error code
    analysis_run_id: UUID | None  # the ANALYZE run with the agent's suggestions, if any


class CodeFindingOut(FindingOut):
    """A finding with where it is in the session's code, for the editor."""

    path: str | None  # relative to the workspace, forward slashes
    line: int | None
    end_line: int | None
    rule_id: str | None  # the tool's rule, e.g. "javascript.express.security.audit.xss"
    snippet: str | None  # the first line, masked; never for GITLEAKS
    file_sha256: str | None  # of the stored file the scan read
