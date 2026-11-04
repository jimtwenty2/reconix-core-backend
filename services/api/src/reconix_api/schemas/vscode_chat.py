"""The VS Code chat and its chat functions.

A chat function is something a chat message can ask for ("list the high findings",
"scan this project"). It is not a Kali tool: it never runs one. SERVER functions run in
the backend and only read. Anything that changes something is a CLIENT function: it
comes back to VS Code, which asks the person first and then runs it. VS Code runs it
through an existing endpoint where there is one (cancel, the code scan, the provider
activation, with their own checks and approvals), and on its own where there is none
yet (a fix is prepared by VS Code).
"""

from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from reconix_api.core.code_files import MAX_PATH
from reconix_api.models.enums import SeverityStatus
from reconix_api.schemas.code import CodeFindingOut, CodeScanOut
from reconix_api.schemas.messages import MessageOut

MAX_PATHS = 20
MAX_FIX_FINDINGS = 200


class FunctionName(StrEnum):
    LIST_FINDINGS = "LIST_FINDINGS"
    EXPLAIN_FINDING = "EXPLAIN_FINDING"
    SUMMARIZE_FINDINGS = "SUMMARIZE_FINDINGS"
    SCAN_STATUS = "SCAN_STATUS"
    CANCEL_SCAN = "CANCEL_SCAN"
    START_SCAN = "START_SCAN"
    PROPOSE_FIX = "PROPOSE_FIX"
    SWITCH_MODEL = "SWITCH_MODEL"


class RunsOn(StrEnum):
    SERVER = "SERVER"  # the backend ran it; the answer is in result
    CLIENT = "CLIENT"  # VS Code asks the person, then runs it (see the module docstring)


# ---------------------------------------------------------------------------
# Arguments, one model per function. Their JSON schema is what a model sees later.
# ---------------------------------------------------------------------------


class Arguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ListFindingsArgs(Arguments):
    severity: SeverityStatus | None = None
    path: str | None = Field(default=None, max_length=MAX_PATH)  # relative to the workspace


class ExplainFindingArgs(Arguments):
    finding_id: UUID


class NoArgs(Arguments):
    pass


class CancelScanArgs(Arguments):
    agent_run_id: UUID | None = None  # the running code scan; None: the session's own


class StartScanArgs(Arguments):
    """Both are hints for VS Code, which decides what to sync and upload. The code scan
    endpoint takes neither: it always scans the session's stored code within the scope."""

    full: bool = Field(
        default=False,
        description="VS Code uploads every file again, even when nothing changed.",
    )
    paths: list[str] = Field(
        default_factory=list,
        max_length=MAX_PATHS,
        description="Relative folders or files VS Code limits the upload to; empty: all.",
    )


class ProposeFixArgs(Arguments):
    finding_ids: list[UUID] = Field(default_factory=list, max_length=MAX_FIX_FINDINGS)


class SwitchModelArgs(Arguments):
    llm_provider_id: UUID


# ---------------------------------------------------------------------------
# Calls, results and the answer
# ---------------------------------------------------------------------------


class FunctionCall(BaseModel):
    name: FunctionName
    arguments: dict[str, Any] = Field(default_factory=dict)


class FunctionSpec(BaseModel):
    """One chat function as a client or a model sees it."""

    name: FunctionName
    description: str
    runs_on: RunsOn
    confirm: bool  # VS Code asks the person Yes/No before it runs it
    parameters: dict[str, Any]  # JSON schema of the arguments


class FindingsResult(BaseModel):
    findings: list[CodeFindingOut]


class FindingResult(BaseModel):
    finding: CodeFindingOut


class FileCount(BaseModel):
    path: str
    count: int


class SummaryResult(BaseModel):
    """Open findings of the latest code scan, counted. No model writes any of it."""

    total: int
    counts: dict[SeverityStatus, int]
    files: list[FileCount]  # the most affected, at most 3
    fix_first: list[UUID]  # the most serious open findings, at most 3


class ScanResult(BaseModel):
    scan: CodeScanOut | None  # None before the session's first code scan


FunctionResult = FindingsResult | FindingResult | SummaryResult | ScanResult


class VscodeChatOut(BaseModel):
    """The person's message as saved and the answer to it, both masked.

    A question is answered by the agent (agent_run_id set, function_call None). A chat
    function is answered at once without the agent: SERVER functions put their answer
    in result, CLIENT functions leave VS Code to run function_call.
    """

    message: MessageOut
    reply: MessageOut
    agent_run_id: UUID | None
    function_call: FunctionCall | None
    runs_on: RunsOn | None
    confirm: bool
    result: FunctionResult | None
