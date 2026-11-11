"""Opening, reading and closing sessions."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.models.enums import SessionStatus
from reconix_api.schemas.sessions import (
    Interface,
    SessionCreate,
    SessionCreated,
    SessionRead,
    WebSignIn,
    WebSignInCode,
)
from reconix_api.services import sessions

router = APIRouter(prefix="/sessions", tags=["sessions"])


def get_session_tokens(request: Request) -> SessionTokens:
    return request.app.state.session_tokens


@router.post("", status_code=status.HTTP_201_CREATED)
def open_session(
    body: SessionCreate,
    db: Db,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> SessionCreated:
    """Opens a new session and returns its token.

    Business Rules:
    - Send `operator` as user@host of the computer the client runs on (for example
      "vanneth@kshrd-laptop"). It is the name in /operator, approvals and the audit log.
      Without it, the API uses its own OS user and host name.

    State Changes:
    - Creates a session and issues its token.

    Security:
    - Open. Needs no token; the Host check and CORS restrict it to this computer.
    """
    session, _, token = sessions.open_session(
        db, tokens, interfaces.write_audit, body.interface, sent_operator=body.operator
    )
    created = SessionRead.model_validate(session, from_attributes=True)
    return SessionCreated(**created.model_dump(), token=token)


@router.post("/web-sign-in-codes", status_code=status.HTTP_201_CREATED)
def issue_web_sign_in_code(
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> WebSignInCode:
    """Creates a one-time code for signing in to the local web at `/web`.

    Business Rules:
    - Add the code to the sign-in link. It is valid for 2 minutes.

    State Changes:
    - Creates a one-time web sign-in code.

    Security:
    - Requires a valid session token.
    """
    code, expires_at = sessions.issue_web_sign_in_code(tokens, interfaces.write_audit, operator)
    return WebSignInCode(code=code, expires_at=expires_at)


@router.post("/web-sign-in", status_code=status.HTTP_201_CREATED)
def web_sign_in(
    body: WebSignIn,
    db: Db,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> SessionCreated:
    """Exchanges a sign-in code for a new web session and returns its token.

    Business Rules:
    - Returns 401 INVALID_SIGN_IN_CODE if the code is unknown, already used, or expired.
    - The web session gets the same operator name as the session that asked for the code.

    State Changes:
    - Creates a web session and issues its token.

    Security:
    - Open. Needs no token; the one-time code is the check.
    """
    session, _, token = sessions.open_web_session(db, tokens, interfaces.write_audit, body.code)
    created = SessionRead.model_validate(session, from_attributes=True)
    return SessionCreated(**created.model_dump(), token=token)


@router.get("")
def list_sessions(
    db: Db,
    _: CurrentOperator,
    interface: Interface | None = None,
    session_status: SessionStatus | None = None,
) -> list[SessionRead]:
    """Lists the sessions, newest first.

    Business Rules:
    - Filter with `interface` and `session_status` (e.g. `?interface=vscode&session_status=ACTIVE`
      lists only the open VS Code sessions).

    Security:
    - Requires a valid session token.
    """
    return sessions.list_sessions(db, interface, session_status)


@router.get("/{session_id}")
def read_session(session_id: UUID, db: Db, _: CurrentOperator) -> SessionRead:
    """Returns one session and its status.

    Business Rules:
    - Returns 404 SESSION_NOT_FOUND if no session has this id.

    Security:
    - Requires a valid session token.
    """
    return sessions.read_session(db, session_id)


@router.post("/{session_id}/resume", status_code=status.HTTP_201_CREATED)
def resume_session(
    session_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> SessionCreated:
    """Gives a new token for an open web session, so its chat can go on after a restart.

    Business Rules:
    - The API keeps tokens in memory only, so a restart of the API, or of the web server that
      held the token, leaves an open web session without one. This gives it a new token.
    - Returns 403 NOT_A_WEB_SESSION for a cli or vscode session, 409 SESSION_CLOSED for a
      closed one, and 404 SESSION_NOT_FOUND for an unknown id.
    - The resumed session takes the caller's operator name.

    State Changes:
    - Issues a new token for the session. Tokens it had before keep working.

    Security:
    - Requires a valid session token. It gives no new rights: any valid token may do
      everything already.
    """
    session, token = sessions.resume_session(
        db, tokens, interfaces.write_audit, operator, session_id
    )
    resumed = SessionRead.model_validate(session, from_attributes=True)
    return SessionCreated(**resumed.model_dump(), token=token)


@router.post("/{session_id}/close")
def close_session(
    session_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> SessionRead:
    """Closes the session.

    State Changes:
    - Invalidates the session token.
    - Deletes any source code sent to the session.

    Security:
    - Requires a valid session token.
    """
    return sessions.close_session(
        db, tokens, interfaces.write_audit, operator, session_id, settings.code_dir
    )
