"""Opening, reading and closing sessions."""

import getpass
import socket
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.models import Session
from reconix_api.models.enums import SessionStatus
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.sessions import SessionRead
from reconix_api.services.audit import audit

FALLBACK_USER = "operator"  # when the OS gives no user name
MAX_ACTOR = 100  # decided_by, reviewed_by, created_by ... are String(100)


def open_session(
    db: Db, tokens: SessionTokens, write_audit: WriteAudit, interface: str
) -> tuple[Session, Operator, str]:
    """Opens a session for the person at this computer. There are no roles: the token
    may do everything."""
    session = session_repo.add(db, Session(interface=interface))
    db.commit()
    operator = Operator(session_id=session.session_id, actor=local_actor())
    token = tokens.issue(operator)
    audit(write_audit, "SESSION_OPENED", operator, details={"interface": interface})
    return session, operator, token


def list_sessions(db: Db) -> list[SessionRead]:
    return [
        SessionRead.model_validate(row, from_attributes=True) for row in session_repo.list_all(db)
    ]


def read_session(db: Db, session_id: UUID) -> SessionRead:
    return SessionRead.model_validate(_get(db, session_id), from_attributes=True)


def close_session(
    db: Db, tokens: SessionTokens, write_audit: WriteAudit, operator: Operator, session_id: UUID
) -> SessionRead:
    """Only your own session. Its token stops working at once."""
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only close your own session.")
    session = _get(db, session_id)
    if session.session_status == SessionStatus.CLOSED:
        raise ApiError(409, "SESSION_CLOSED", "This session is already closed.")
    session.session_status = SessionStatus.CLOSED
    session.closed_at = datetime.now(UTC)
    db.commit()
    tokens.revoke_session(session_id)
    audit(write_audit, "SESSION_CLOSED", operator)
    return SessionRead.model_validate(session, from_attributes=True)


def _get(db: Db, session_id: UUID) -> Session:
    session = session_repo.get(db, session_id)
    if session is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    return session


def local_actor() -> str:
    """Who is at this computer, e.g. "vanneth@kshrd-laptop". Reconix only runs locally,
    so the OS user and host name say who decided, in approvals, reviews and the audit log."""
    try:
        user = getpass.getuser()
    except (KeyError, OSError):  # no user name in the environment or the user database
        user = FALLBACK_USER
    return f"{user}@{socket.gethostname()}"[:MAX_ACTOR]
