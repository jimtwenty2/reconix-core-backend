"""The VS Code chat: a message that asks for a chat function is answered at once, without
the agent; anything else is evaluated by the model with tools, and falls back to CHAT
as the other apps (services/chat.py, unchanged).

Only an open vscode session may use it, so VS Code only ever sees its own messages.
Chat functions that run here only read, so the person's message is saved after the
function has run without anything having changed if saving fails.
"""

import json
import logging
from collections.abc import Callable
from functools import cache
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy.orm import Session as Db

from reconix_ai.providers import complete_with_tools
from reconix_api.core.agent import provider_config
from reconix_api.core.config import Settings
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import Interfaces, Operator
from reconix_api.core.masking import MaskSecrets, mask_json
from reconix_api.models import Message
from reconix_api.models.enums import FindingStatus, SessionStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import llm_providers as provider_repo
from reconix_api.repositories import messages as message_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.code import CodeFindingOut
from reconix_api.schemas.messages import MessageOut
from reconix_api.schemas.vscode_chat import (
    CancelScanArgs,
    ExplainFindingArgs,
    FunctionCall,
    FunctionName,
    FunctionSpec,
    ListFindingsArgs,
    MAX_FIX_FINDINGS,
    NoArgs,
    ProposeFixArgs,
    StartScanArgs,
    VscodeChatOut,
)
from reconix_api.services import chat, code_scans, messages
from reconix_api.services.audit import audit
from reconix_api.services.chat import ASSISTANT
from reconix_api.services.chat_chooser import ProviderWords, choose, fix_targets, provider_words
from reconix_api.services.chat_functions import (
    FUNCTIONS,
    FunctionContext,
    FunctionError,
    Outcome,
    newest_scan,
    spec,
)

logger = logging.getLogger(__name__)

VSCODE = "vscode"  # sessions.interface of a VS Code session (schemas.sessions.Interface)

MODEL_SYSTEM_PROMPT = (
    "You are the Reconix AI security assistant in VS Code. "
    "The user communicates with you in natural language chat.\n"
    "Understand the user's intent and choose the appropriate tool if they ask for an action:\n"
    "- If the user asks to scan, check, analyze, audit, or inspect their code, repository, or workspace for vulnerabilities or secrets (e.g. 'this source code, please scan', 'check my project for bugs', 'audit code'), call START_SCAN.\n"
    "- If the user asks to fix, patch, repair, or remediate vulnerabilities or findings in their code, call PROPOSE_FIX.\n"
    "- If the user asks for a summary or overview of findings or scan results, call SUMMARIZE_FINDINGS.\n"
    "- If the user asks to list or show findings, call LIST_FINDINGS.\n"
    "- If the user asks to explain a specific finding in full, call EXPLAIN_FINDING.\n"
    "- If the user asks to stop, cancel, or abort a running scan, call CANCEL_SCAN.\n"
    "- If the user asks about the scan status or whether it is still running, call SCAN_STATUS.\n"
    "- If the user asks a general question, advice, or asks how to fix something manually, DO NOT call any tool; instead, provide a direct, helpful explanation in markdown text."
)


def model_tool_definitions() -> list[dict]:
    """OpenAI/LiteLLM tool definitions derived from chat functions."""
    return [
        {
            "type": "function",
            "function": {
                "name": func.name.value,
                "description": func.description,
                "parameters": func.arguments.model_json_schema(),
            },
        }
        for func in FUNCTIONS.values()
    ]


async def choose_with_model(
    db: Db,
    settings: Settings,
    content: str,
    load_findings: Callable[[], list[CodeFindingOut]],
) -> tuple[FunctionCall | None, str | None]:
    """Uses the active LLM provider with tools to understand user intent."""
    provider_row = agent_run_repo.active_provider(db)
    if provider_row is None:
        return None, None

    config = provider_config(settings, provider_row, provider_row.model_name)
    tools = model_tool_definitions()
    messages_payload = [
        {"role": "system", "content": MODEL_SYSTEM_PROMPT},
        {"role": "user", "content": content},
    ]

    try:
        reply = await complete_with_tools(messages_payload, tools, config)
    except Exception as err:
        logger.warning(f"choose_with_model failed: {err}")
        return None, None

    if reply.tool_calls:
        tool_call = reply.tool_calls[0]
        name_upper = (tool_call.name or "").upper()
        if name_upper in FunctionName.__members__:
            func_name = FunctionName(name_upper)
            raw_args = tool_call.arguments
            if isinstance(raw_args, str):
                try:
                    args = json.loads(raw_args) if raw_args.strip() else {}
                except Exception:
                    args = {}
            elif isinstance(raw_args, dict):
                args = dict(raw_args)
            else:
                args = {}

            if not isinstance(args, dict):
                args = {}

            if func_name == FunctionName.PROPOSE_FIX and not args.get("finding_ids"):
                findings = load_findings()
                targets = fix_targets(content, findings)
                if targets:
                    args["finding_ids"] = [str(f.finding_id) for f in targets]
                elif findings:
                    open_f = [f for f in findings if f.finding_status == FindingStatus.OPEN]
                    args["finding_ids"] = [str(f.finding_id) for f in open_f[:MAX_FIX_FINDINGS]]

            return FunctionCall(name=func_name, arguments=args), reply.text or None

    if reply.text and reply.text.strip():
        return None, reply.text.strip()

    return None, None


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

    # If fast keyword chooser didn't match, ask the LLM with tool definitions
    if call is None or outcome is None:
        try:
            model_call, direct_text = await choose_with_model(
                db, settings, content, context.findings
            )
        except Exception as err:
            logger.warning(f"choose_with_model unhandled error: {err}")
            model_call, direct_text = None, None
        if model_call is not None:
            model_outcome = run_call(context, model_call)
            if model_outcome is not None:
                call = model_call
                outcome = model_outcome
                if direct_text and not outcome.text:
                    outcome = Outcome(direct_text, outcome.arguments, outcome.result)
        elif direct_text is not None:
            message = messages.add_message(
                db, interfaces.write_audit, mask, operator, session_id, content
            )
            reply = add_reply(db, mask, session_id, direct_text, None)
            return VscodeChatOut(
                message=message,
                reply=reply,
                agent_run_id=None,
                function_call=None,
                runs_on=None,
                confirm=False,
                result=None,
            )

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
