"""Database access for sessions."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Session
from reconix_api.models.enums import SessionStatus


def add(db: Db, session: Session) -> Session:
    db.add(session)
    db.flush()
    return session


def get(db: Db, session_id: UUID) -> Session | None:
    return db.get(Session, session_id)


def get_for_update(db: Db, session_id: UUID) -> Session | None:
    """The session, locked until commit, so its messages are numbered one at a time."""
    return db.get(Session, session_id, with_for_update=True)


def list_all(
    db: Db, interface: str | None = None, session_status: SessionStatus | None = None
) -> list[Session]:
    """Newest first. Each filter given must match."""
    query = select(Session).order_by(Session.created_at.desc())
    if interface is not None:
        query = query.where(Session.interface == interface)
    if session_status is not None:
        query = query.where(Session.session_status == session_status)
    return list(db.scalars(query))
