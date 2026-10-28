"""Database access for chat messages."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session as Db

from reconix_api.models import Message


def add(db: Db, message: Message) -> Message:
    db.add(message)
    db.flush()
    return message


def last_sequence_no(db: Db, session_id: UUID) -> int:
    query = select(func.max(Message.sequence_no)).where(Message.session_id == session_id)
    return db.scalar(query) or 0


def list_by_session(db: Db, session_id: UUID) -> list[Message]:
    query = select(Message).where(Message.session_id == session_id).order_by(Message.sequence_no)
    return list(db.scalars(query))
