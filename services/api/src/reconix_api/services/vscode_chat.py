"""The VS Code chat: a message that asks for a chat function is answered at once, without
the agent; anything else is a question for the agent, through the same CHAT as the
other apps (services/chat.py, unchanged).

Only an open vscode session may use it, so VS Code only ever sees its own messages.
Chat functions that run here only read, so the person's message is saved after the
function has run without anything having changed if saving fails.
"""

import json
from functools import cache
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session as Db

from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Interfaces, Operator
from reconix_api.core.masking import MaskSecrets, mask_json
from reconix_api.models import Message
from reconix_api.models.enums import SessionStatus
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.repositories import messages as message_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.code import CodeFindingOut
from reconix_api.schemas.messages import MessageOut
from reconix_api.schemas.vscode_chat import FunctionCall, FunctionSpec, VscodeChatOut
from reconix_api.services import chat, code_scans, messages
from reconix_api.services.audit import audit
from reconix_api.services.chat import ASSISTANT
from reconix_api.services.chat_chooser import ProviderWords, choose, provider_words
from reconix_api.services.chat_functions import (
    FUNCTIONS,
    FunctionContext,
    FunctionError,
    Outcome,
    newest_scan,
    spec,
)

VSCODE = "vscode"  # sessions.interface of a VS Code session (schemas.sessions.Interface)


def list_functions() -> list[FunctionSpec]:
    return [spec(function) for function in FUNCTIONS.values()]


async def chat_in_vscode(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    settings: Settings,
    operator: Operator,
    session_id: UUID,
    content: str,
) -> VscodeChatOut:
    check_vscode_session(db, operator, session_id)
    context = FunctionContext(
        db=db,
        interfaces=interfaces,
        mask=mask,
        settings=settings,
        operator=operator,
        session_id=session_id,
        load_findings=cache(lambda: scan_findings(db, settings, mask, session_id)),
    )
    call = choose(content, context.findings, lambda: providers(db))
    outcome = run_call(context, call) if call else None
    if call is None or outcome is None:
        answered = await chat.chat(db, interfaces, mask, operator, session_id, content)
        return VscodeChatOut(
            **answered.model_dump(), function_call=None, runs_on=None, confirm=False, result=None
        )

    function = FUNCTIONS[call.name]
    checked = None
    if outcome.arguments is not None:
        arguments = outcome.arguments.model_dump(mode="json")
        checked = FunctionCall(name=call.name, arguments=masked(mask, arguments))
    message = messages.add_message(db, interfaces.write_audit, mask, operator, session_id, content)
    reply = add_reply(db, mask, session_id, outcome.text, checked)
    details = {
        "message_id": str(reply.message_id),
        "function": call.name,
        "runs_on": function.runs_on,
        "ran": checked is not None,
    }
    audit(interfaces.write_audit, "CHAT_FUNCTION_CALLED", operator, details=details)
    return VscodeChatOut(
        message=message,
        reply=reply,
        agent_run_id=None,
        function_call=checked,
        runs_on=function.runs_on if checked else None,
        confirm=function.confirm if checked else False,
        result=outcome.result,
    )


def run_call(context: FunctionContext, call: FunctionCall) -> Outcome | None:
    """The function's outcome, or None when the call does not fit: then the message is
    a question for the agent. A refused or failed call writes one audit line (S9), with
    the error's kind only: the arguments may hold anything. A failure is raised again."""
    function = FUNCTIONS[call.name]
    try:
        arguments = function.arguments.model_validate(call.arguments)
        return function.run(context, arguments)
    except (ValidationError, FunctionError) as error:
        audit_refusal(context, call, error)
        return None
    except Exception as error:
        audit_refusal(context, call, error)
        raise


def audit_refusal(context: FunctionContext, call: FunctionCall, error: Exception) -> None:
    details = {"function": call.name, "error": type(error).__name__}
    audit(
        context.interfaces.write_audit, "CHAT_FUNCTION_REFUSED", context.operator, details=details
    )


def check_vscode_session(db: Db, operator: Operator, session_id: UUID) -> None:
    """Before anything runs: the person's own, open, vscode session."""
    if session_id != operator.session_id:
        raise ApiError(403, "NOT_YOUR_SESSION", "You can only write in your own session.")
    session = session_repo.get(db, session_id)
    if session is None:
        raise ApiError(404, "SESSION_NOT_FOUND", "No session with this id.")
    if session.interface != VSCODE:
        raise ApiError(409, "NOT_VSCODE_SESSION", "The VS Code chat is only for VS Code sessions.")
    if session.session_status != SessionStatus.ACTIVE:
        raise ApiError(409, "SESSION_CLOSED", "This session is closed.")


def scan_findings(
    db: Db, settings: Settings, mask: MaskSecrets, session_id: UUID
) -> list[CodeFindingOut]:
    """The findings of the session's newest finished code scan, masked; none before one."""
    run = newest_scan(db, session_id, finished=True)
    if run is None:
        return []
    return code_scans.list_scan_findings(db, settings, mask, run.agent_run_id)


def providers(db: Db) -> list[ProviderWords]:
    return [
        ProviderWords(
            llm_provider_id=row.llm_provider_id,
            words=provider_words(row.display_name, row.model_name, row.provider_type),
        )
        for row in provider_repo.list_visible(db)
    ]


def masked(mask: MaskSecrets, value: dict) -> dict:
    """Every string in the arguments masked, like everything else that is saved (S8)."""
    text, _ = mask_json(mask, json.dumps(value)) or (json.dumps(value), 0)
    return json.loads(text)


def add_reply(
    db: Db, mask: MaskSecrets, session_id: UUID, text: str, call: FunctionCall | None
) -> MessageOut:
    """The answer to a chat function, with the checked call in its metadata."""
    session_repo.get_for_update(db, session_id)  # the next sequence_no is this one's
    reply = message_repo.add(
        db,
        Message(
            sequence_no=message_repo.last_sequence_no(db, session_id) + 1,
            role=ASSISTANT,
            content_masked=mask(text)[0],
            metadata_={"function_call": call.model_dump(mode="json")} if call else {},
            session_id=session_id,
        ),
    )
    db.commit()
    return MessageOut.model_validate(reply, from_attributes=True)
