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
    """Runs SEMGREP, then GITLEAKS, on the code sent to the assessment's session, then
    (with analyze) the agent's analysis. Answers at once; poll GET /code-scans/{id}. Each
    tool goes through the safety checks like any action, so the scope needs a "path"
    target for that code. 422 NO_CODE, 409 SCAN_RUNNING."""
    return await code_scans.start_scan(
        db, session_factory, interfaces, mask, settings, operator, assessment_id, body
    )


@router.get("/code-scans/{agent_run_id}")
def read_code_scan(agent_run_id: UUID, db: Db, _: CurrentOperator) -> CodeScanOut:
    """Status, stage, progress and the counts per severity of the findings so far."""
    return code_scans.read_scan(db, agent_run_id)


@router.post("/code-scans/{agent_run_id}/cancel")
def cancel_code_scan(
    agent_run_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> CodeScanOut:
    """The scan is CANCELLED at once and stops before its next step. 409 SCAN_ENDED."""
    return code_scans.cancel_scan(db, interfaces, operator, agent_run_id)


@router.get("/code-scans/{agent_run_id}/findings")
def list_code_scan_findings(
    agent_run_id: UUID, db: Db, _: CurrentOperator, mask: CurrentMask, settings: CurrentSettings
) -> list[CodeFindingOut]:
    """The findings this scan found, with path (relative), line, rule and a masked
    snippet, in the order they were found."""
    return code_scans.list_scan_findings(db, settings, mask, agent_run_id)
