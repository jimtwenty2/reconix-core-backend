"""Opening a session."""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, status

from reconix_api.core.db import Db
from reconix_api.core.security import CurrentInterfaces
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.schemas.sessions import SessionCreate, SessionCreated
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
