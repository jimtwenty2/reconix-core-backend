"""Request and response shapes for /sessions/{id}/code and /code-scans (VS Code)."""

from datetime import datetime
from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr, field_validator

from reconix_api.core.code_files import MAX_FILES, MAX_PATH, CodeFileError, check_rel_path
from reconix_api.core.interfaces import ToolName
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


class CodeCloneIn(BaseModel):
    url: str = Field(max_length=300)  # https://github.com/<owner>/<repo>
    # For a private repo; never stored. Without it, this computer's git credentials apply.
    token: SecretStr | None = Field(None, max_length=1000)


class CodeClonedOut(CodeUploadOut):
    source: Literal["LOCAL_CLONE", "GITHUB"]  # a clone found on this computer, or a git clone


class CodeFolderIn(BaseModel):
    path: str = Field(min_length=1, max_length=MAX_PATH)  # an absolute folder on this computer


# The tools a code scan runs, in this order.
CODE_TOOLS = (
    ToolName.SEMGREP,
    ToolName.GITLEAKS,
    ToolName.TRIVY,
    ToolName.GRYPE,
    ToolName.OSV_SCANNER,
    ToolName.SYFT,
    ToolName.SONAR_SCAN,
)


class CodeScanIn(BaseModel):
    # Files or folders of the session's code, relative, forward slashes. Empty scans it all.
    paths: list[str] = Field(default_factory=list, max_length=100)
    # Some of CODE_TOOLS. None: every one of them the scope allows.
    tools: list[ToolName] | None = Field(None, min_length=1)
    analyze: bool = True  # also ask the AI to review each new finding after the tools ran
    # Re-run every due tool even when no file changed, so new advisories in the trivy/grype
    # databases surface on unchanged code (a full scan, not an incremental one).
    refresh: bool = False

    @field_validator("paths")
    @classmethod
    def paths_are_relative(cls, paths: list[str]) -> list[str]:
        try:
            return sorted({check_rel_path(path) for path in paths})
        except CodeFileError as error:
            raise ValueError(str(error)) from error

    @field_validator("tools")
    @classmethod
    def tools_scan_code(cls, tools: list[ToolName] | None) -> list[ToolName] | None:
        if tools is not None and not set(tools) <= set(CODE_TOOLS):
            raise ValueError(f"a code scan runs only {', '.join(CODE_TOOLS)}")
        return tools


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
    # findings of this scan per severity, with the ones kept from earlier scans (unchanged files)
    counts: dict[SeverityStatus, int]
    # e.g. "GITLEAKS FAILED" (a step that did not finish, while the scan did), "SYFT 5 packages"
    notes: list[str]
    error: str | None  # why the scan FAILED, as an error code


class Verdict(StrEnum):
    """What a code finding most likely is. Only a validation makes it CONFIRMED; the AI
    review gives the other three, and a person's FALSE_POSITIVE gives LIKELY_FALSE_POSITIVE."""

    CONFIRMED = "CONFIRMED"
    LIKELY_TRUE_POSITIVE = "LIKELY_TRUE_POSITIVE"
    LIKELY_FALSE_POSITIVE = "LIKELY_FALSE_POSITIVE"
    UNVERIFIED = "UNVERIFIED"  # not reviewed, the AI was unsure, or its review failed


class CodeFindingOut(FindingOut):
    """A finding with where it is in the session's code, for the editor."""

    path: str | None  # relative to the workspace, forward slashes
    line: int | None
    end_line: int | None
    rule_id: str | None  # the tool's rule, e.g. "javascript.express.security.audit.xss"
    snippet: str | None  # the first line, masked; never for GITLEAKS
    file_sha256: str | None  # of the stored file the scan read
    verdict: Verdict = Verdict.UNVERIFIED
    explanation: str | None = None  # the AI review's, masked; None before a review
    fix_recommendation: str | None = None
