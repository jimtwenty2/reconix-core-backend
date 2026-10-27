"""Database access for sessions."""

from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.models import Session


def add(db: Db, session: Session) -> Session:
    db.add(session)
    db.flush()
    return session


def get(db: Db, session_id: UUID) -> Session | None:
    return db.get(Session, session_id)
