"""Database access for sessions."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Session


def add(db: Db, session: Session) -> Session:
    db.add(session)
    db.flush()
    return session


def get(db: Db, session_id: UUID) -> Session | None:
    return db.get(Session, session_id)


def get_for_update(db: Db, session_id: UUID) -> Session | None:
    """The session, locked until commit, so its messages are numbered one at a time."""
    return db.get(Session, session_id, with_for_update=True)


def list_all(db: Db) -> list[Session]:
    return list(db.scalars(select(Session).order_by(Session.created_at.desc())))
