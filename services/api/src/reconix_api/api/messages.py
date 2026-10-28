"""Chat messages of a session."""

from uuid import UUID

from fastapi import APIRouter, status

from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator, RequireOperator
from reconix_api.schemas.messages import MessageCreate, MessageOut
from reconix_api.services import messages

router = APIRouter(prefix="/sessions/{session_id}/messages", tags=["messages"])


@router.post("", status_code=status.HTTP_201_CREATED)
def add_message(
    session_id: UUID,
    body: MessageCreate,
    db: Db,
    operator: RequireOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
) -> MessageOut:
    return messages.add_message(
        db, interfaces.write_audit, mask, operator, session_id, body.content
    )


@router.get("")
def list_messages(session_id: UUID, db: Db, _: CurrentOperator) -> list[MessageOut]:
    return messages.list_messages(db, session_id)
