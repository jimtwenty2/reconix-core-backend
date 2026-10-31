"""Chat with the agent: save the person's message, ask the agent (CHAT) and save its answer.

The agent only answers. It changes nothing: the scope, the plan and the approvals
change only through their own endpoints, by a person. Its context is read from the
session's own rows (the newest scope, approved or a draft, and the newest plan),
never from the request, and everything sent to it is already masked.
"""

from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    AgentRequest,
    AgentTask,
    ChatMessage,
    ChatScope,
    Interfaces,
    Operator,
)
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import AgentRun, Message
from reconix_api.models.enums import AgentRunStatus
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import messages as message_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.messages import ChatOut, MessageOut
from reconix_api.services import agent_runs, messages
from reconix_api.services.scopes import to_chat_scope

ASSISTANT = "assistant"  # messages.role of the agent's answer
CHAT_ROLES = ("user", "assistant")


async def chat(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    session_id: UUID,
    content: str,
) -> ChatOut:
    """The message is saved first, so it is kept even when the agent fails. A failed
    ask ends the CHAT run FAILED (one audit line) and its error is raised. One chat per
    session asks the agent at a time: 409 CHAT_IN_PROGRESS."""
    message = messages.add_message(db, interfaces.write_audit, mask, operator, session_id, content)
    chat_scope = session_scope(db, session_id, mask)
    assessment_id = chat_scope.assessment_id if chat_scope else None
    if assessment_id is None:
        assessment = assessment_repo.get_by_session(db, session_id)
        assessment_id = assessment.assessment_id if assessment else None
    # The session row is locked while the open chats are checked and the run is saved,
    # so two chats can never both start.
    session_repo.get_for_update(db, session_id)
    if agent_run_repo.running_chat(db, session_id) is not None:
        db.rollback()
        raise ApiError(409, "CHAT_IN_PROGRESS", "The agent is still answering. Try again soon.")
    run = agent_runs.new_agent_run(db, operator, assessment_id, task="CHAT")
    db.commit()
    try:
        return await answer(db, interfaces, mask, operator, run, message, chat_scope)
    except Exception as error:
        agent_runs.fail(db, interfaces, operator, run, error)
        raise


async def answer(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    run: AgentRun,
    message: MessageOut,
    chat_scope: ChatScope | None,
) -> ChatOut:
    provider, model = agent_runs.agent_provider(db, run)
    request = AgentRequest(
        task=AgentTask.CHAT,
        assessment_id=run.assessment_id,
        agent_run_id=run.agent_run_id,
        provider=provider,
        model=model,
        messages=history(db, run.session_id),
        chat_scope=chat_scope,
        plan=plan_lines(db, run.assessment_id),
    )
    response = await agent_runs.ask_agent(db, interfaces, request)
    session_repo.get_for_update(db, run.session_id)  # the next sequence_no is this one's
    reply = message_repo.add(
        db,
        Message(
            sequence_no=message_repo.last_sequence_no(db, run.session_id) + 1,
            role=ASSISTANT,
            content_masked=mask(response.text)[0],
            session_id=run.session_id,
        ),
    )
    run.checkpoint_id = response.checkpoint_id
    db.commit()
    agent_runs.end(
        db,
        interfaces,
        operator,
        run,
        AgentRunStatus.COMPLETED,
        {"message_id": str(reply.message_id)},
    )
    return ChatOut(
        message=message,
        reply=MessageOut.model_validate(reply, from_attributes=True),
        agent_run_id=run.agent_run_id,
    )


def session_scope(db: Db, session_id: UUID, mask: MaskSecrets) -> ChatScope | None:
    """The session's newest scope, approved or a draft, or None before there is one.
    A draft can hold anything half written (a URL with a password in it), so every
    target is masked before the agent sees it (S8)."""
    manifest = scope_repo.latest_in_session(db, session_id)
    if manifest is None:
        return None
    scope = to_chat_scope(manifest, scope_repo.list_targets(db, manifest.manifest_id))
    lists = ("ip_ranges", "domains", "url_prefixes", "repo_paths", "excluded_targets")
    masked = {name: [mask(value)[0] for value in getattr(scope, name)] for name in lists}
    return scope.model_copy(update=masked)


def history(db: Db, session_id: UUID) -> list[ChatMessage]:
    """The session's chat, oldest first, masked when it was saved. The agent keeps the
    last few and names each speaker."""
    return [
        ChatMessage(role=row.role, content_masked=row.content_masked)
        for row in message_repo.list_by_session(db, session_id)
        if row.role in CHAT_ROLES
    ]


def plan_lines(db: Db, assessment_id: UUID | None) -> list[str]:
    """The newest saved plan, one line a step, for questions about it."""
    if assessment_id is None:
        return []
    run = agent_run_repo.latest_plan(db, assessment_id)
    if run is None:
        return []
    lines = [f"Summary: {run.plan['text']}"] if run.plan.get("text") else []
    return lines + [step_line(step) for step in run.plan.get("steps", [])]


def step_line(step: dict) -> str:
    line = f"{step['order']}. {step['title']}"
    action = step.get("action")
    if action:
        command = " ".join([action["tool"], action["target"], *action.get("arguments", [])])
        line += f" ({command})"
    return line
