"""Opening, reading and closing sessions."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.schemas.sessions import (
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
    """Opens a session. Only reachable from this computer (Host check + CORS)."""
    session, _, token = sessions.open_session(db, tokens, interfaces.write_audit, body.interface)
    created = SessionRead.model_validate(session, from_attributes=True)
    return SessionCreated(**created.model_dump(), token=token)


@router.post("/web-sign-in-codes", status_code=status.HTTP_201_CREATED)
def issue_web_sign_in_code(
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> WebSignInCode:
    """For `/web`: a one-time code to put in the sign-in link. It works for 2 minutes."""
    code, expires_at = sessions.issue_web_sign_in_code(tokens, interfaces.write_audit, operator)
    return WebSignInCode(code=code, expires_at=expires_at)


@router.post("/web-sign-in", status_code=status.HTTP_201_CREATED)
def web_sign_in(
    body: WebSignIn,
    db: Db,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> SessionCreated:
    """Trades a sign-in code for a new web session. Open, like POST /sessions: the code is
    the check. 401 INVALID_SIGN_IN_CODE if the code is unknown, used or expired."""
    session, _, token = sessions.open_web_session(db, tokens, interfaces.write_audit, body.code)
    created = SessionRead.model_validate(session, from_attributes=True)
    return SessionCreated(**created.model_dump(), token=token)


@router.get("")
def list_sessions(db: Db, _: CurrentOperator) -> list[SessionRead]:
    return sessions.list_sessions(db)


@router.get("/{session_id}")
def read_session(session_id: UUID, db: Db, _: CurrentOperator) -> SessionRead:
    return sessions.read_session(db, session_id)


@router.post("/{session_id}/close")
def close_session(
    session_id: UUID,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> SessionRead:
    return sessions.close_session(db, tokens, interfaces.write_audit, operator, session_id)
