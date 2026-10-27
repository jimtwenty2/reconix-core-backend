"""Opening a session and handing out its token."""

from sqlalchemy.orm import Session as Db

from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.session_tokens import SessionTokens
from reconix_api.models import Session
from reconix_api.models.enums import Role
from reconix_api.repositories import sessions as session_repo
from reconix_api.services.audit import audit

LOCAL_ACTOR = "operator"


def open_session(
    db: Db, tokens: SessionTokens, write_audit: WriteAudit, interface: str
) -> tuple[Session, str]:
    """Opens an OPERATOR session for the person at this computer.

    Viewer sessions are issued by `/web` (week 2), never by this endpoint.
    """
    session = session_repo.add(db, Session(interface=interface, role=Role.OPERATOR))
    db.commit()
    operator = Operator(session_id=session.session_id, role=session.role, actor=LOCAL_ACTOR)
    token = tokens.issue(operator)
    audit(write_audit, "SESSION_OPENED", operator, details={"interface": interface})
    return session, token
