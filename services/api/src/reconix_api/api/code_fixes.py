"""Code fixes for code scan findings (VS Code): start, live transcript, result, cancel."""

from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.orm import Session, sessionmaker

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db, get_session_factory
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, bearer
from reconix_api.schemas.code_fixes import CodeFixIn, CodeFixOut, CodeFixStarted
from reconix_api.services import code_fixes

router = APIRouter(tags=["code fixes"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]
Credentials = Annotated[HTTPAuthorizationCredentials, Depends(bearer)]
SessionFactory = Annotated[sessionmaker[Session], Depends(get_session_factory)]


@router.post("/sessions/{session_id}/code-fixes", status_code=status.HTTP_202_ACCEPTED)
async def start_code_fix(
    session_id: UUID,
    body: CodeFixIn,
    db: Db,
    session_factory: SessionFactory,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> CodeFixStarted:
    """Starts an AI fix of findings from your session's latest finished code scan.

    Business Rules:
    - finding_ids are 1 to 200 finding ids of the session's latest COMPLETED code scan.
    - One agent per file, at most 3 at once, with the active AI provider. Each agent can
      only read and edit its own file. It reruns SEMGREP on its edited copy to check its
      work.
    - A GITLEAKS finding (rotate the secret), a dependency finding (upgrade the package),
      a finding without a line, a file that changed since the scan, and any code when the
      scan's GITLEAKS did not run are not sent to the model: they end NOT_FIXED with the
      reason.
    - FIXED means SEMGREP no longer matches on the edited copy, not that a person checked it.
    - Returns 403 NOT_YOUR_SESSION, 409 SESSION_CLOSED, 409 NO_FINISHED_SCAN if the session
      has no finished code scan, 409 SCAN_RUNNING or 409 FIX_RUNNING while one runs in the
      session, 422 FINDING_NOT_IN_SCAN (details.finding_ids) for an id not in that scan, or
      503 NO_ACTIVE_PROVIDER.

    Execution Behavior:
    - Responds immediately (202). Follow it with GET /code-fixes/{id}/events and read the
      result with GET /code-fixes/{id}.
    - A model error ends the fix FAILED with its code, e.g. MODEL_UNAVAILABLE,
      PROVIDER_AUTH_FAILED, PROVIDER_URL_MISSING.

    State Changes:
    - Creates a code fix (an agent run with task CODE_FIX), audited as CODE_FIX_STARTED and
      AGENT_RUN_COMPLETED / FAILED / CANCELLED, with ids and counts only.
    - Never changes the stored code or your files: the result is line edits to review.
    - Each recheck is a SEMGREP action of the fix, through the usual safety checks; it
      saves no findings.

    Security:
    - Requires a valid session token, of this session.
    - The model sees the code masked; lines that may hold a secret are hidden.
    """
    return await code_fixes.start_fix(
        db, session_factory, interfaces, mask, settings, operator, session_id, body
    )


@router.get("/code-fixes/{agent_run_id}")
def read_code_fix(agent_run_id: UUID, db: Db, operator: CurrentOperator) -> CodeFixOut:
    """Returns a code fix's status and, once it is COMPLETED, its result.

    Business Rules:
    - result.files: per changed file, its path, the sha256 of the file the edits were made
      for, and sorted, non-overlapping whole-line edits (1-based start_line and end_line;
      replacement is the new text without a final newline, "" deletes the lines).
    - result.results: one per requested finding, with status FIXED, STILL_REPORTED,
      NOT_VERIFIED or NOT_FIXED and a one-sentence note.
    - result.summary: Markdown, what the agents changed and why.
    - error: the error code when the fix FAILED, e.g. MODEL_UNAVAILABLE or INTERRUPTED.
    - Returns 404 CODE_FIX_NOT_FOUND, or 403 NOT_YOUR_SESSION for another session's fix.

    Security:
    - Requires a valid session token, of the fix's session.
    - The summary and notes are masked.
    """
    return code_fixes.read_fix(db, operator, agent_run_id)


@router.get(
    "/code-fixes/{agent_run_id}/events",
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}},
)
async def read_code_fix_events(
    agent_run_id: UUID,
    request: Request,
    operator: CurrentOperator,
    credentials: Credentials,
    interfaces: CurrentInterfaces,
    settings: CurrentSettings,
    session_factory: SessionFactory,
    after: Annotated[int, Query(ge=0)] = 0,
) -> StreamingResponse:
    """Streams the fix agents' live transcript as Server-Sent Events.

    Business Rules:
    - Each message is `event: FIX_EVENT` with `data: {agent_run_id, seq, file, kind, text}`.
      kind is START, THINKING, TEXT, TOOL, RESULT, STATUS, DONE or HEARTBEAT; file is the
      file an agent works on, or null for the whole request. THINKING and TEXT are pieces
      to append to the previous piece of the same kind and file.
    - Every event since the start is sent first; with ?after=<seq> only the later ones, so
      a reconnect misses nothing.
    - When the fix has ended and every event is sent, one `event: FIX_ENDED` with
      `data: {agent_run_id, agent_runs_status}` arrives and the stream ends. Then read GET
      /code-fixes/{id}.
    - The transcript is kept in memory: after an API restart a stream gets only FIX_ENDED.
    - Returns 404 CODE_FIX_NOT_FOUND, or 403 NOT_YOUR_SESSION for another session's fix.

    Execution Behavior:
    - A HEARTBEAT event arrives every few seconds while nothing happens.
    - The stream ends when the session is closed.

    Security:
    - Requires a valid session token, of the fix's session, sent as a Bearer header (read
      the stream with fetch, not EventSource).
    - Every text is masked.
    """
    with session_factory() as db:  # a short session: a Db dependency would hold it open
        code_fixes.ensure_own_fix(db, operator, agent_run_id)

    async def body() -> AsyncIterator[str]:
        async for part in code_fixes.event_frames(
            session_factory,
            agent_run_id,
            after,
            interfaces.get_operator,
            credentials.credentials,
            settings.stream_heartbeat_seconds,
            request.is_disconnected,
        ):
            yield part

    headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no"}
    return StreamingResponse(body(), media_type="text/event-stream", headers=headers)


@router.post("/code-fixes/{agent_run_id}/cancel")
def cancel_code_fix(
    agent_run_id: UUID, db: Db, operator: CurrentOperator, interfaces: CurrentInterfaces
) -> CodeFixOut:
    """Cancels the fix immediately; its agents stop and it gives no result.

    Business Rules:
    - Returns 409 FIX_ENDED if the fix has already ended, 404 CODE_FIX_NOT_FOUND, or 403
      NOT_YOUR_SESSION for another session's fix.

    State Changes:
    - Ends the fix CANCELLED (one AGENT_RUN_CANCELLED audit line).

    Security:
    - Requires a valid session token, of the fix's session.
    """
    return code_fixes.cancel_fix(db, interfaces, operator, agent_run_id)
