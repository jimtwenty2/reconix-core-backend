"""Opening, reading and closing sessions."""

import getpass
import re
import socket
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core import code_files
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.models import Session
from reconix_api.models.enums import SessionStatus
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.sessions import SessionRead
from reconix_api.services import code_scans
from reconix_api.services.audit import audit

FALLBACK_USER = "operator"  # when the OS gives no user name
MAX_ACTOR = 100  # decided_by, reviewed_by, created_by ... are String(100)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def open_session(
    db: Db,
    tokens: SessionTokens,
    write_audit: WriteAudit,
    interface: str,
    issued_by: UUID | None = None,
    sent_operator: str | None = None,
) -> tuple[Session, Operator, str]:
    """Opens a session for the person at this computer. There are no roles: the token
    may do everything. issued_by is the session whose sign-in code opened this one.
    sent_operator is the user@host the client sent; without it, local_actor()."""
    session = session_repo.add(db, Session(interface=interface))
    db.commit()
    sent = clean_actor(sent_operator or "")
    operator = Operator(session_id=session.session_id, actor=sent or local_actor())
    token = tokens.issue(operator)
    details = {"interface": interface, "operator_from": "client" if sent else "server"}
    if issued_by is not None:
        details["issued_by_session"] = str(issued_by)
    audit(write_audit, "SESSION_OPENED", operator, details=details)
    return session, operator, token


def issue_web_sign_in_code(
    tokens: SessionTokens, write_audit: WriteAudit, operator: Operator
) -> tuple[str, datetime]:
    """A one-time code for the web sign-in link. Only a signed-in person can ask for one."""
    code, expires_at = tokens.issue_sign_in_code(operator, datetime.now(UTC))
    audit(write_audit, "WEB_SIGN_IN_CODE_ISSUED", operator)
    return code, expires_at


def open_web_session(
    db: Db, tokens: SessionTokens, write_audit: WriteAudit, code: str
) -> tuple[Session, Operator, str]:
    """Trades a sign-in code for a new web session and its token. Each code works once,
    and only while the session that asked for it is open."""
    try:
        used = tokens.use_sign_in_code(code, datetime.now(UTC))
    except PermissionError as error:
        raise ApiError(
            401, "INVALID_SIGN_IN_CODE", "This sign-in link is not valid. Run /web again."
        ) from error
    # The web session is the same person as the session that asked for the code.
    return open_session(db, tokens, write_audit, "web", used.issued_by, used.actor)


def list_sessions(
    db: Db, interface: str | None = None, session_status: SessionStatus | None = None
) -> list[SessionRead]:
    rows = session_repo.list_all(db, interface, session_status)
    return [SessionRead.model_validate(row, from_attributes=True) for row in rows]


def read_session(db: Db, session_id: UUID) -> SessionRead:
    return SessionRead.model_validate(_get(db, session_id), from_attributes=True)


def close_session(
    db: Db,
    tokens: SessionTokens,
    write_audit: WriteAudit,
    operator: Operator,
    session_id: UUID,
    code_dir: str,
) -> SessionRead:
    """Only your own session. Its token stops working at once, and any source code sent
    to it (VS Code) is deleted from this computer."""
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only close your own session.")
    session = _get(db, session_id)
    if session.session_status == SessionStatus.CLOSED:
        raise ApiError(409, "SESSION_CLOSED", "This session is already closed.")
    session.session_status = SessionStatus.CLOSED
    session.closed_at = datetime.now(UTC)
    db.commit()
    tokens.revoke_session(session_id)
    code_scans.cancel_for_session(db, write_audit, operator, session_id)
    code_files.remove(code_files.session_folder(code_dir, session_id))
    audit(write_audit, "SESSION_CLOSED", operator)
    return SessionRead.model_validate(session, from_attributes=True)


def _get(db: Db, session_id: UUID) -> Session:
    session = session_repo.get(db, session_id)
    if session is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    return session


def local_actor() -> str:
    """The API process's own OS user and host name, e.g. "vanneth@kshrd-laptop": the name
    used when the client sends none. Inside Docker they are the container's."""
    try:
        user = getpass.getuser()
    except (KeyError, OSError):  # no user name in the environment or the user database
        user = FALLBACK_USER
    return f"{user}@{socket.gethostname()}"[:MAX_ACTOR]


def clean_actor(name: str) -> str:
    """A name as it may be saved: no control characters, no outer spaces, at most MAX_ACTOR."""
    return CONTROL.sub("", name).strip()[:MAX_ACTOR]
