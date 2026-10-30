"""The real ask_agent: the AI Service's LangGraph agent, called as a Python package.

Each call opens the graph on its checkpointer, runs one task or one resume, and
returns the answer as the shared AgentResponse. The agent only suggests; the API
keeps its own approvals and runs check() again before any tool runs.
"""

from collections.abc import AsyncIterator, Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import asdict, dataclass
from uuid import UUID

from langgraph.graph.state import CompiledStateGraph

from reconix_ai import agent
from reconix_ai.contracts import AgentAnswer
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentResponse,
    ApprovedScope,
    AskAgent,
)

OpenGraph = Callable[[], AbstractAsyncContextManager[CompiledStateGraph]]

BUILT_IN_PROVIDER = "RECONIX"  # the other providers come with the provider endpoints
# Agent error code -> HTTP status. Any other code is the agent or model failing: 502.
AGENT_ERROR_STATUS = {
    "INPUT_BLOCKED": 422,
    "TASK_NOT_SUPPORTED": 422,
    "RUN_IS_WAITING": 409,
    "RUN_NOT_WAITING": 409,
    "STEP_LIMIT": 422,  # the run stopped itself
    "TOKEN_BUDGET": 422,
    "MODEL_UNAVAILABLE": 503,  # the model is down: try again later
}


@dataclass(frozen=True)
class PlanInput:
    """The fields the agent reads for PLAN and SUGGEST."""

    task: str
    assessment_id: UUID
    scope: ApprovedScope
    messages: list[str]
    tool_results: list[str]


def postgres_graph(database_url: str) -> OpenGraph:
    """Opens the graph on the Postgres checkpointer, so a waiting run survives a restart."""

    @asynccontextmanager
    async def open_graph() -> AsyncIterator[CompiledStateGraph]:
        async with agent.postgres_checkpointer(database_url) as saver:
            yield agent.build_graph(saver)

    return open_graph


def make_ask_agent(open_graph: OpenGraph, deps: agent.AgentDeps) -> AskAgent:
    async def ask_agent(request: AgentRequest) -> AgentResponse:
        check_provider(request)
        async with open_graph() as graph:
            try:
                answer = await run_agent(graph, request, deps)
            except agent.AgentError as error:
                status = AGENT_ERROR_STATUS.get(error.code, 502)
                raise ApiError(status, error.code, error.message) from None
        return to_response(answer)

    return ask_agent


def check_provider(request: AgentRequest) -> None:
    if request.provider != BUILT_IN_PROVIDER or request.model is not None:
        raise ApiError(
            503,
            "NOT_READY",
            "Only the built-in RECONIX provider and its model are ready.",
            {"part": "ai_providers"},
        )


async def run_agent(
    graph: CompiledStateGraph, request: AgentRequest, deps: agent.AgentDeps
) -> AgentAnswer:
    run_id = str(request.agent_run_id)
    if request.resume is None:
        return await agent.ask_agent(graph, plan_input(request), run_id, deps)
    await check_resume(graph, request)
    approved = request.resume.decision == "APPROVED"
    return await agent.resume_agent(graph, run_id, approved, deps)


async def check_resume(graph: CompiledStateGraph, request: AgentRequest) -> None:
    """A decision only counts for the run, the assessment and the exact action it waits on.

    A run that is not waiting is left to the agent, which answers 409 RUN_NOT_WAITING.
    """
    resume = request.resume
    if resume.agent_run_id != request.agent_run_id:
        raise ApiError(422, "RESUME_RUN_MISMATCH", "The decision is for another agent run.")
    if resume.assessment_id != request.assessment_id:
        raise ApiError(422, "RESUME_RUN_MISMATCH", "The decision is for another assessment.")
    snapshot = await graph.aget_state({"configurable": {"thread_id": str(request.agent_run_id)}})
    if "wait" not in snapshot.next:
        return
    waiting = snapshot.values
    if waiting.get("assessment_id") != str(request.assessment_id):
        raise ApiError(422, "RESUME_RUN_MISMATCH", "The run belongs to another assessment.")
    if Action(**waiting["proposed_action"]) != resume.action:
        raise ApiError(422, "RESUME_RUN_MISMATCH", "The decision is for another action.")


def plan_input(request: AgentRequest) -> PlanInput:
    # Until the agent takes ChatMessage, only the person's words are sent, so an
    # earlier answer of the agent is never read as something the person wrote.
    person_messages = [m.content_masked for m in request.messages if m.role == "user"]
    return PlanInput(
        task=request.task,
        assessment_id=request.assessment_id,
        scope=request.scope,
        messages=person_messages,
        tool_results=list(request.tool_results),
    )


def to_response(answer: AgentAnswer) -> AgentResponse:
    return AgentResponse(**asdict(answer))
