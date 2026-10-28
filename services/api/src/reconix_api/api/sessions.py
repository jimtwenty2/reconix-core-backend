"""Opening, reading and closing sessions."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Request, status

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.schemas.sessions import SessionCreate, SessionCreated, SessionRead
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
    """Opens an OPERATOR session. Only reachable from this computer (Host check + CORS)."""
    session, operator, token = sessions.open_session(
        db, tokens, interfaces.write_audit, body.interface
    )
    return SessionCreated(
        session_id=session.session_id,
        interface=session.interface,
        role=operator.role,
        session_status=session.session_status,
        created_at=session.created_at,
        token=token,
    )


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
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
    tokens: Annotated[SessionTokens, Depends(get_session_tokens)],
) -> SessionRead:
    return sessions.close_session(db, tokens, interfaces.write_audit, operator, session_id)
