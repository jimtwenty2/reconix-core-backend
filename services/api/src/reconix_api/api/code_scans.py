"""Code scans of the source code a session sent (VS Code): start, poll, cancel, findings."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status
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
    """Scans the code sent to the assessment's session with SEMGREP, then GITLEAKS.

    Business Rules:
    - With analyze, the agent also analyzes the results afterward.
    - The scope needs a "path" target for that code.
    - Returns 422 NO_CODE if no code was sent, or 409 SCAN_RUNNING if a scan is already running.

    Execution Behavior:
    - Runs each tool through the same safety checks as any action.
    - Responds immediately (202); poll GET /code-scans/{id} to follow it.

    State Changes:
    - Creates a code scan.

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
    agent_run_id: UUID, db: Db, _: CurrentOperator, mask: CurrentMask, settings: CurrentSettings
) -> list[CodeFindingOut]:
    """Lists the findings this scan found, in the order they were found.

    Business Rules:
    - Each finding has its relative path, line, rule, and a masked code snippet.

    Security:
    - Requires a valid session token.
    - Code snippets are masked.
    """
    return code_scans.list_scan_findings(db, settings, mask, agent_run_id)
