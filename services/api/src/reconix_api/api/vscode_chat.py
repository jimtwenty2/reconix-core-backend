"""Chat from VS Code: answers, and the chat functions a message asks for."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, status

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.db import Db
from reconix_api.core.masking import CurrentMask
from reconix_api.core.security import CurrentInterfaces, CurrentOperator
from reconix_api.schemas.messages import MessageCreate
from reconix_api.schemas.vscode_chat import FunctionSpec, VscodeChatOut
from reconix_api.services import vscode_chat

router = APIRouter(tags=["vscode chat"])

CurrentSettings = Annotated[Settings, Depends(get_settings)]


@router.post("/sessions/{session_id}/vscode-chat", status_code=status.HTTP_201_CREATED)
async def chat_in_vscode(
    session_id: UUID,
    body: MessageCreate,
    db: Db,
    operator: CurrentOperator,
    interfaces: CurrentInterfaces,
    mask: CurrentMask,
    settings: CurrentSettings,
) -> VscodeChatOut:
    """Saves the person's message and answers it. A message that asks for a chat function
    ("list the high findings", "scan this project", "stop") is answered at once: a SERVER
    function's answer is in result, a CLIENT function is for VS Code to run after it asks
    the person (confirm is true). Anything else is answered by the agent, like /chat.
    403 NOT_YOUR_SESSION, 404 SESSION_NOT_FOUND, 409 NOT_VSCODE_SESSION, 409 SESSION_CLOSED;
    for a question answered by the agent also 409 CHAT_IN_PROGRESS."""
    return await vscode_chat.chat_in_vscode(
        db, interfaces, mask, settings, operator, session_id, body.content
    )


@router.get("/vscode-chat/functions")
def list_chat_functions(_: CurrentOperator) -> list[FunctionSpec]:
    """Every chat function: what it does, its arguments (JSON schema), where it runs and
    whether VS Code asks the person first."""
    return vscode_chat.list_functions()
