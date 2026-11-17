"""Chat with the agent: save the person's message, ask the agent (CHAT) and save its answer.

The agent only answers. It changes nothing: the scope, the plan and the approvals
change only through their own endpoints, by a person. Its context is read from the
session's own rows (the newest scope, approved or a draft, and the newest plan),
never from the request, and everything sent to it is already masked.
"""

import asyncio
import logging
from collections import Counter
from collections.abc import AsyncIterator
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.orm import Session as Db

from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    AgentRequest,
    AgentTask,
    ChatMessage,
    ChatScope,
    FindingInput,
    Interfaces,
    OnPiece,
    Operator,
)
from reconix_api.core.masking import MaskSecrets
from reconix_api.models import (
    Action,
    AgentRun,
    Assessment,
    Finding,
    Message,
    ScopeManifest,
    ScopeTarget,
)
from reconix_api.models.enums import AgentRunStatus, FindingStatus, SeverityStatus
from reconix_api.repositories import actions as action_repo
from reconix_api.repositories import agent_runs as agent_run_repo
from reconix_api.repositories import approvals as approval_repo
from reconix_api.repositories import assessments as assessment_repo
from reconix_api.repositories import findings as findings_repo
from reconix_api.repositories import messages as message_repo
from reconix_api.repositories import scopes as scope_repo
from reconix_api.repositories import sessions as session_repo
from reconix_api.schemas.messages import ChatOut, MessageOut
from reconix_api.services import agent_runs, messages
from reconix_api.services.analysis import finding_input
from reconix_api.services.approvals import still_open_after
from reconix_api.services.scopes import to_chat_scope
from reconix_api.services.stream import sse

logger = logging.getLogger(__name__)

ASSISTANT = "assistant"  # messages.role of the agent's answer
CHAT_ROLES = ("user", "assistant")
DEFAULT_APPROVAL_TTL_MINUTES = 30
MAX_CHAT_ASSESSMENTS = 10
MAX_CHAT_FINDINGS = 50
MAX_CHAT_PLAN_LINES = 10
_SEVERITY_RANK = {
    SeverityStatus.CRITICAL: 0,
    SeverityStatus.HIGH: 1,
    SeverityStatus.MEDIUM: 2,
    SeverityStatus.LOW: 3,
    SeverityStatus.NONE: 4,
    SeverityStatus.UNKNOWN: 5,
}

# Streamed asks still running: kept here so one is never dropped half way when its
# client leaves (the answer is still saved and the run still ends).
_asks: set[asyncio.Task] = set()


@dataclass(frozen=True)
class StartedChat:
    message: MessageOut  # the person's message, saved
    run: AgentRun  # the CHAT run, RUNNING
    chat_scope: ChatScope | None
    ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES


async def chat(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    session_id: UUID,
    content: str,
    assessment_id: UUID | None = None,
    ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
) -> ChatOut:
    """Saves the message, asks the agent and saves its answer (see start and finish)."""
    started = start(
        db,
        interfaces,
        mask,
        operator,
        session_id,
        content,
        assessment_id=assessment_id,
        ttl_minutes=ttl_minutes,
    )
    return await finish(db, interfaces, mask, operator, started)


def start(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    session_id: UUID,
    content: str,
    assessment_id: UUID | None = None,
    ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
) -> StartedChat:
    """The message is saved first, so it is kept even when the agent fails. One chat per
    session asks the agent at a time: 409 CHAT_IN_PROGRESS, and the refused message is not
    kept. The message, the check and the new run share one transaction, under the session
    row lock save_message takes, so two chats can never both start."""
    saved, hidden = messages.save_message(db, mask, operator, session_id, content)
    if agent_run_repo.running_chat(db, session_id) is not None:
        db.rollback()
        raise ApiError(409, "CHAT_IN_PROGRESS", "The agent is still answering. Try again soon.")
    chat_scope = session_scope(db, session_id, mask)
    resolved_id = resolve_assessment_id(db, session_id, chat_scope, assessment_id)
    if resolved_id is not None and (chat_scope is None or chat_scope.assessment_id != resolved_id):
        chat_scope = assessment_scope(db, resolved_id, mask) or chat_scope
    run = agent_runs.new_agent_run(db, operator, resolved_id, task="CHAT")
    db.commit()
    messages.audit_message(interfaces.write_audit, operator, saved, hidden)
    message = MessageOut.model_validate(saved, from_attributes=True)
    return StartedChat(message, run, chat_scope, ttl_minutes)


async def finish(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    started: StartedChat,
    on_piece: OnPiece | None = None,
) -> ChatOut:
    """Asks the agent and saves its answer. A failed or cancelled ask ends the CHAT run
    FAILED (one audit line) and its error is raised, so no run is left RUNNING. on_piece
    gets the answer in masked pieces."""
    try:
        return await answer(
            db,
            interfaces,
            mask,
            operator,
            started.run,
            started.message,
            started.chat_scope,
            on_piece,
            started.ttl_minutes,
        )
    except (Exception, asyncio.CancelledError) as error:
        agent_runs.fail(db, interfaces, operator, started.run, error)
        raise


@dataclass(frozen=True)
class StreamedAsk:
    task: asyncio.Task  # gives the saved ChatOut
    pieces: asyncio.Queue[str]  # masked pieces of the answer


def ask_in_background(
    db: Db, interfaces: Interfaces, mask: MaskSecrets, operator: Operator, started: StartedChat
) -> StreamedAsk:
    """Starts finish() as its own task, before any response is sent, so the answer is
    saved and the run ends even if the client leaves at once. The task opens its own
    database session on the same engine: the request's session closes when the
    response ends, and a session is never shared between two tasks."""
    pieces: asyncio.Queue[str] = asyncio.Queue()

    async def on_piece(piece: str) -> None:
        # Masked by the agent already; masked again here, as the saved answer is.
        await pieces.put(mask(piece)[0])

    async def run() -> ChatOut:
        with Db(bind=db.get_bind(), expire_on_commit=False) as own_db:
            run = agent_run_repo.get(own_db, started.run.agent_run_id)
            own = StartedChat(started.message, run, started.chat_scope, started.ttl_minutes)
            return await finish(own_db, interfaces, mask, operator, own, on_piece)

    task = asyncio.ensure_future(run())
    _asks.add(task)
    task.add_done_callback(_asks.discard)
    return StreamedAsk(task, pieces)


async def stream_events(ask: StreamedAsk) -> AsyncIterator[str]:
    """The ask as Server-Sent Events: PIECE {"text"} while the agent writes, then DONE
    with the saved ChatOut, or ERROR with the error shape. Show DONE's reply in place of
    the pieces: it is the saved answer, masked once more, and may differ from them.
    Leaving early only stops the events; the ask carries on."""
    while not (ask.task.done() and ask.pieces.empty()):
        next_piece = asyncio.ensure_future(ask.pieces.get())
        try:
            await asyncio.wait({next_piece, ask.task}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            if not next_piece.done():
                next_piece.cancel()
        if next_piece.done() and not next_piece.cancelled():
            yield sse("PIECE", {"text": next_piece.result()})
    yield end_event(ask.task)


def end_event(task: asyncio.Task) -> str:
    error = None if task.cancelled() else task.exception()
    if not task.cancelled() and error is None:
        return sse("DONE", task.result().model_dump(mode="json"))
    if isinstance(error, ApiError):
        return sse(
            "ERROR", {"code": error.code, "message": error.message, "details": error.details}
        )
    if error is not None:
        logger.error("Unexpected error in a streamed chat", exc_info=error)
    return sse(
        "ERROR", {"code": "INTERNAL_ERROR", "message": "Something went wrong.", "details": {}}
    )


async def answer(
    db: Db,
    interfaces: Interfaces,
    mask: MaskSecrets,
    operator: Operator,
    run: AgentRun,
    message: MessageOut,
    chat_scope: ChatScope | None,
    on_piece: OnPiece | None = None,
    ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
) -> ChatOut:
    provider, model = agent_runs.agent_provider(db, run)
    scope = chat_scope or assessment_scope(db, run.assessment_id, mask)
    request = AgentRequest(
        task=AgentTask.CHAT,
        assessment_id=run.assessment_id,
        agent_run_id=run.agent_run_id,
        provider=provider,
        model=model,
        messages=history(db, run.session_id),
        chat_scope=scope,
        plan=plan_lines(db, run.assessment_id, mask, ttl_minutes),
        findings=chat_findings(db, run.assessment_id),
    )
    response = await agent_runs.ask_agent(db, interfaces, request, on_piece)
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
        # The knowledge the answer cites, as the agent read it (masked when it was ingested).
        sources=list(response.sources),
    )


def resolve_assessment_id(
    db: Db, session_id: UUID, chat_scope: ChatScope | None, requested: UUID | None
) -> UUID | None:
    """Resolve the assessment for a CHAT run, validating any explicit id from a web session."""
    own_id = chat_scope.assessment_id if chat_scope else None
    if own_id is None:
        assessment = assessment_repo.get_by_session(db, session_id)
        own_id = assessment.assessment_id if assessment else None
    if requested is None:
        return own_id
    if assessment_repo.get(db, requested) is None:
        db.rollback()
        raise ApiError(404, "ASSESSMENT_NOT_FOUND", "The assessment does not exist.")
    if own_id is not None and own_id != requested:
        db.rollback()
        raise ApiError(409, "ASSESSMENT_MISMATCH", "This session belongs to another assessment.")
    return requested


def mask_scope_targets(
    manifest: ScopeManifest, targets: list[ScopeTarget], mask: MaskSecrets
) -> ChatScope:
    scope = to_chat_scope(manifest, targets)
    lists = ("ip_ranges", "domains", "url_prefixes", "repo_paths", "excluded_targets")
    masked = {name: [mask(value)[0] for value in getattr(scope, name)] for name in lists}
    return scope.model_copy(update=masked)


def session_scope(db: Db, session_id: UUID, mask: MaskSecrets) -> ChatScope | None:
    """The session's newest scope, approved or a draft, or None before there is one.
    A draft can hold anything half written (a URL with a password in it), so every
    target is masked before the agent sees it (S8)."""
    manifest = scope_repo.latest_in_session(db, session_id)
    if manifest is None:
        return None
    return mask_scope_targets(manifest, scope_repo.list_targets(db, manifest.manifest_id), mask)


def assessment_scope(db: Db, assessment_id: UUID | None, mask: MaskSecrets) -> ChatScope | None:
    """The assessment's scope manifest for cross-session web chat, with masked targets (S8)."""
    if assessment_id is None:
        return None
    manifest = scope_repo.get_by_assessment(db, assessment_id)
    if manifest is None:
        return None
    return mask_scope_targets(manifest, scope_repo.list_targets(db, manifest.manifest_id), mask)


def rank_chat_findings(rows: list[Finding]) -> list[Finding]:
    """Exclude false positives, rank worst severity first, and cap at MAX_CHAT_FINDINGS."""
    kept = [row for row in rows if row.finding_status != FindingStatus.FALSE_POSITIVE]
    kept.sort(key=lambda row: _SEVERITY_RANK.get(row.severity_status, 99))
    return kept[:MAX_CHAT_FINDINGS]


def chat_findings(db: Db, assessment_id: UUID | None) -> list[FindingInput]:
    """The findings for CHAT context: one assessment's or all saved assessments' non-FP findings."""
    rows = findings_repo.list_matching(db, assessment_id=assessment_id)
    return [finding_input(db, row) for row in rank_chat_findings(rows)]


def history(db: Db, session_id: UUID) -> list[ChatMessage]:
    """The session's chat, oldest first, masked when it was saved. The agent keeps the
    last few and names each speaker."""
    return [
        ChatMessage(role=row.role, content_masked=row.content_masked)
        for row in message_repo.list_by_session(db, session_id)
        if row.role in CHAT_ROLES
    ]


def assessment_summary_line(row: Assessment, waiting_count: int) -> str:
    status = getattr(row.assessment_status, "value", str(row.assessment_status))
    return (
        f"{row.engagement_code} ({row.name}, {row.type}): "
        f"{status}, {waiting_count} waiting approval"
    )


def all_assessments_summary(db: Db, ttl_minutes: int) -> list[str]:
    """Brief status and pending-approval summary when chat runs across All assessments."""
    assessments = assessment_repo.list_all(db)[:MAX_CHAT_ASSESSMENTS]
    if not assessments:
        return []
    ids = [row.assessment_id for row in assessments]
    waiting = approval_repo.count_waiting(db, ids, still_open_after(ttl_minutes))
    return [assessment_summary_line(row, waiting.get(row.assessment_id, 0)) for row in assessments]


def action_key(tool: str, target: str, args: list[str]) -> tuple[str, str, tuple[str, ...]]:
    return (tool, target, tuple(args))


def action_status_map(actions: list[Action]) -> dict[tuple[str, str, tuple[str, ...]], str]:
    """Map each tool/target/args tuple to its newest ActionStatus value (newest-first input)."""
    statuses: dict[tuple[str, str, tuple[str, ...]], str] = {}
    for row in actions:
        key = action_key(row.tool, row.target, list(row.args or []))
        statuses.setdefault(key, getattr(row.action_status, "value", str(row.action_status)))
    return statuses


def plan_lines(
    db: Db,
    assessment_id: UUID | None,
    mask: MaskSecrets,
    ttl_minutes: int = DEFAULT_APPROVAL_TTL_MINUTES,
) -> list[str]:
    """The newest saved plan + action status (masked), or assessment status when global."""
    if assessment_id is None:
        lines = all_assessments_summary(db, ttl_minutes)
        return [mask(line)[0] for line in lines][:MAX_CHAT_PLAN_LINES]

    lines: list[str] = []
    run = agent_run_repo.latest_plan(db, assessment_id)
    actions = action_repo.list_by_assessment(db, assessment_id)
    if run is not None:
        if run.plan.get("text"):
            lines.append(f"Summary: {run.plan['text']}")
        statuses = action_status_map(actions)
        lines.extend(step_line(step, statuses) for step in run.plan.get("steps", []))
    elif actions:
        counts = Counter(getattr(a.action_status, "value", str(a.action_status)) for a in actions)
        parts = ", ".join(f"{count} {status}" for status, count in sorted(counts.items()))
        lines.append(f"Actions: {parts}")

    assessment = assessment_repo.get(db, assessment_id)
    if assessment is not None:
        waiting = approval_repo.count_waiting(db, [assessment_id], still_open_after(ttl_minutes))
        summary = assessment_summary_line(assessment, waiting.get(assessment_id, 0))
        lines = lines[: MAX_CHAT_PLAN_LINES - 1] + [summary]

    return [mask(line)[0] for line in lines][:MAX_CHAT_PLAN_LINES]


def step_line(
    step: dict, action_statuses: dict[tuple[str, str, tuple[str, ...]], str] | None = None
) -> str:
    line = f"{step['order']}. {step['title']}"
    status = step.get("status")
    action = step.get("action")
    if action:
        command = " ".join([action["tool"], action["target"], *action.get("arguments", [])])
        line += f" ({command})"
        if not status and action_statuses:
            status = action_statuses.get(
                action_key(action["tool"], action["target"], list(action.get("arguments", [])))
            )
    if status:
        line += f" [{status}]"
    return line
