"""Chat messages in a session: add the person's message (masked) and read them back."""

from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Operator, WriteAudit
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import Message
from reconix_api.models.enums import SessionStatus
from reconix_api.repositories import messages as message_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.messages import MessageOut
from reconix_api.services.audit import audit

USER = "user"  # messages.role: user, assistant or system


def add_message(
    db: Db,
    write_audit: WriteAudit,
    mask: MaskSecrets,
    operator: Operator,
    session_id: UUID,
    content: str,
) -> MessageOut:
    """The person's own message, in their own open session. Only the masked text is kept."""
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only write in your own session.")
    session = session_repo.get_for_update(db, session_id)
    if session is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    if session.session_status != SessionStatus.ACTIVE:
        raise ApiError(409, "SESSION_CLOSED", "This session is closed.")

    content_masked, hidden = mask(content)
    message = message_repo.add(
        db,
        Message(
            sequence_no=message_repo.last_sequence_no(db, session_id) + 1,
            role=USER,
            content_masked=content_masked,
            session_id=session_id,
        ),
    )
    db.commit()
    details = {
        "message_id": str(message.message_id),
        "sequence_no": message.sequence_no,
        "masked_count": hidden,
    }
    audit(write_audit, "MESSAGE_ADDED", operator, details=details)
    return MessageOut.model_validate(message, from_attributes=True)


def list_messages(db: Db, session_id: UUID) -> list[MessageOut]:
    if session_repo.get(db, session_id) is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    return [
        MessageOut.model_validate(row, from_attributes=True)
        for row in message_repo.list_by_session(db, session_id)
    ]
