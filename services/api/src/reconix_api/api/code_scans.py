"""Code scans of the source code a session sent (VS Code): start, poll, cancel, findings."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
from fastapi.responses import PlainTextResponse
from sqlalchemy.orm import Session, sessionmaker

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db, get_session_factory
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.code import CodeFindingOut, CodeScanIn, CodeScanOut
from reconix_api.services import code_scans

router = APIRouter(tags=["code scans"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]
SessionFactory = Annotated[sessionmaker[Session], Depends(get_session_factory)]


@router.post("/sessions/{session_id}/code-scans", status_code=status.HTTP_202_ACCEPTED)
async def start_session_code_scan(
    session_id: UUID,
    body: CodeScanIn,
    db: Db,
    session_factory: SessionFactory,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> CodeScanOut:
    """Scans the code sent to your own session, with no scope to write or approve.

    Business Rules:
    - The scope is only the session's code folder, so the server approves it itself; the
      session's assessment is reused while its scope is exactly that folder.
    - paths limits the scan to files or folders of the code; tools picks some of SEMGREP,
      GITLEAKS, TRIVY, GRYPE, OSV_SCANNER, SYFT and SONAR_SCAN (default: all of them).
    - A rescan reads only what changed since the last completed scan and keeps the earlier
      findings on unchanged files.
    - Returns 403 NOT_YOUR_SESSION, 409 SESSION_CLOSED, 409 CODE_SCOPE_MISMATCH if the
      session's assessment has another scope, 409 ASSESSMENT_NOT_ACTIVE if it has ended,
      or any error of POST /assessments/{id}/code-scans.

    Execution Behavior:
    - Runs each tool through the same safety checks as any action.
    - Responds immediately (202); poll GET /code-scans/{id} to follow it.

    State Changes:
    - The first time: creates the scope and its assessment and approves it (one
      SCOPE_APPROVED audit line with reason CODE_SESSION_FOLDER). That scope takes only
      the code scan's own tool calls: any other action on it is BLOCKED CODE_SCAN_ONLY.
    - Creates a code scan.

    Security:
    - Requires a valid session token.
    """
    assessment_id = code_scans.session_assessment(
        db, interfaces, settings, operator, session_id, body.tools
    )
    return await code_scans.start_scan(
        db, session_factory, interfaces, mask, settings, operator, assessment_id, body
    )


@router.post("/assessments/{assessment_id}/code-scans", status_code=status.HTTP_202_ACCEPTED)
async def start_code_scan(
    assessment_id: UUID,
    body: CodeScanIn,
    db: Db,
    session_factory: SessionFactory,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> CodeScanOut:
    """Scans the code sent to the assessment's session with the source code tools.

    Business Rules:
    - The scope needs a "path" target for that code.
    - paths limits the scan to files or folders of the code; tools picks some of SEMGREP,
      GITLEAKS, TRIVY, GRYPE, OSV_SCANNER, SYFT and SONAR_SCAN (default: those the scope
      allows). A tool the scope does not allow ends as a "<TOOL> BLOCKED" note.
    - A rescan reads only what changed since the last completed scan and keeps the earlier
      findings on unchanged files.
    - With analyze (the default), the AI reviews each new finding with the active AI
      provider; a finding reviewed before on the same file with the same model keeps its
      review. A failed review is a "ANALYZE <CODE>" note, never a failed scan. A file no
      GITLEAKS run read as it is now (GITLEAKS not picked, or it failed) sends the AI no
      code.
    - Returns 503 NO_ACTIVE_PROVIDER if no AI provider is active (even without analyze:
      a scan is an agent run), 422 NO_CODE if no code was sent, 422 PATH_NOT_FOUND if a
      path holds no file, 422 NO_CODE_TOOLS if the scope allows none of the tools, 422
      CODE_EXCLUDED if the scope excludes the whole code folder, or 409 SCAN_RUNNING if a
      scan is already running.

    Execution Behavior:
    - Runs each tool through the same safety checks as any action.
    - Responds immediately (202); poll GET /code-scans/{id} to follow it.

    State Changes:
    - Creates a code scan.
    - Deletes excluded "path" targets inside the code folder (for example ".../node_modules")
      from the stored code before the scan, so the tools never read them.

    Security:
    - Requires a valid session token.
    """
    return await code_scans.start_scan(
        db, session_factory, interfaces, mask, settings, operator, assessment_id, body
    )


@router.get("/code-scans/{agent_run_id}")
def read_code_scan(agent_run_id: UUID, db: Db, _: CurrentOperator) -> CodeScanOut:
    """Returns a code scan's status, stage, and progress, with how many findings of each severity it
    has found so far.

    Security:
    - Requires a valid session token.
    """
    return code_scans.read_scan(db, agent_run_id)


@router.post("/code-scans/{agent_run_id}/cancel")
def cancel_code_scan(
    agent_run_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> CodeScanOut:
    """Cancels the scan immediately; it stops before its next step.

    Business Rules:
    - Returns 409 SCAN_ENDED if the scan has already ended.

    State Changes:
    - Cancels the running scan.

    Security:
    - Requires a valid session token.
    """
    return code_scans.cancel_scan(db, interfaces, operator, agent_run_id)


@router.get("/code-scans/{agent_run_id}/findings")
def list_code_scan_findings(
    agent_run_id: UUID,
    db: Db,
    _: CurrentOperator,
    mask: CurrentMask,
    settings: CurrentSettings,
    include_false_positives: bool = True,
) -> list[CodeFindingOut]:
    """Lists the findings this scan found, in the order they were found, then the ones it
    kept from earlier scans for unchanged files.

    Business Rules:
    - Each finding has its relative path, line, rule, and a masked code snippet.
    - Each finding has a verdict, with the AI review's explanation and fix
      recommendation. CONFIRMED only after a validation confirmed it; a finding a
      person marked FALSE_POSITIVE is LIKELY_FALSE_POSITIVE; UNVERIFIED when it was not
      reviewed, the review was unsure, or the review failed.
    - With include_false_positives=false, LIKELY_FALSE_POSITIVE findings are left out:
      every one a person marked FALSE_POSITIVE, and the ones only the AI calls false
      unless they are HIGH, CRITICAL or a GITLEAKS leak.
    - Only findings at or under the scan's paths are listed.

    Security:
    - Requires a valid session token.
    - Code snippets are masked.
    """
    return code_scans.list_scan_findings(db, settings, mask, agent_run_id, include_false_positives)


@router.get("/code-scans/{agent_run_id}/logs/{tool}", response_class=PlainTextResponse)
def read_code_scan_log(agent_run_id: UUID, tool: str, db: Db, _: CurrentOperator) -> str:
    """Returns the masked output of one tool's run in this scan, as text; for example
    the SONAR_SCAN log, which has the SonarQube dashboard link.

    Business Rules:
    - The tool name may be written in any case, e.g. sonar_scan or SONAR_SCAN.
    - Returns 404 CODE_SCAN_NOT_FOUND, or 404 TOOL_LOG_NOT_FOUND if the tool left no output
      in this scan.

    Security:
    - Requires a valid session token.
    - Secrets in the output are masked.
    """
    return code_scans.scan_log(db, agent_run_id, tool)
