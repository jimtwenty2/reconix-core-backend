"""The LangGraph graph: understand -> find -> plan -> suggest -> wait.

ask_agent() runs it for one agent run and stops at wait, where it is saved in
the checkpointer (Postgres in the app) until a person decides. resume_agent()
hands it the decision. The run id is agent_runs.agent_run_id and is the
LangGraph thread id.
"""

from typing import Any, Protocol
from uuid import UUID

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from reconix_ai.agent import nodes
from reconix_ai.agent.nodes import AgentDeps, AgentError
from reconix_ai.agent.state import (
    MAX_MESSAGES,
    MAX_TOOL_RESULTS,
    AgentState,
    ScopeLike,
    masked_texts,
    scope_to_dict,
)
from reconix_ai.contracts import AgentAnswer, BlockedStep, PlanStep, ProposedAction
from reconix_ai.providers import ProviderError

SUPPORTED_TASKS = {"PLAN", "SUGGEST"}  # ANALYZE, REPORT and CHAT come with tasks 4 and 6

NO_ACTION_TEXT = "No step in the plan passed the safety checks, so nothing is suggested."
NO_KNOWLEDGE_TEXT = "The knowledge search was not available, so this plan uses no reference data."


class AgentRequestLike(Protocol):
    """The fields of the shared AgentRequest the agent reads."""

    task: str
    assessment_id: UUID
    scope: ScopeLike
    messages: list[str]
    tool_results: list[str]


def build_graph(checkpointer: BaseCheckpointSaver) -> CompiledStateGraph:
    graph = StateGraph(AgentState, context_schema=AgentDeps)
    graph.add_node("understand", nodes.understand)
    graph.add_node("find", nodes.find)
    graph.add_node("plan", nodes.plan)
    graph.add_node("suggest", nodes.suggest)
    graph.add_node("wait", nodes.wait)
    graph.add_edge(START, "understand")
    graph.add_edge("understand", "find")
    graph.add_edge("find", "plan")
    graph.add_edge("plan", "suggest")
    graph.add_conditional_edges("suggest", nodes.after_suggest, {"wait": "wait", "done": END})
    graph.add_edge("wait", END)
    return graph.compile(checkpointer=checkpointer)


async def ask_agent(
    graph: CompiledStateGraph, request: AgentRequestLike, run_id: str, deps: AgentDeps
) -> AgentAnswer:
    """Plan for the approved scope and suggest one step, then wait for a person."""
    task = str(request.task).upper()
    if task not in SUPPORTED_TASKS:
        raise AgentError("TASK_NOT_SUPPORTED", f"The agent cannot do {task} yet.")
    config = thread_config(run_id)
    if (await graph.aget_state(config)).next:
        raise AgentError("RUN_IS_WAITING", "This run is waiting for a person to decide.")

    messages, masked_in_messages = masked_texts(list(request.messages), MAX_MESSAGES)
    results, masked_in_results = masked_texts(list(request.tool_results), MAX_TOOL_RESULTS)
    start: AgentState = {
        "task": task,
        "assessment_id": str(request.assessment_id),
        "scope": scope_to_dict(request.scope),
        "messages": messages,
        "tool_results": results,
        "proposed_action": None,
        "risk": None,
        "blocked": [],
        "decision": None,
        "masked_count": masked_in_messages + masked_in_results,
    }
    await run_graph(graph, start, config, deps)
    return await answer_for(graph, run_id)


async def resume_agent(
    graph: CompiledStateGraph, run_id: str, approved: bool, deps: AgentDeps
) -> AgentAnswer:
    """Give a waiting run the person's decision."""
    config = thread_config(run_id)
    if "wait" not in (await graph.aget_state(config)).next:
        raise AgentError("RUN_NOT_WAITING", "This run is not waiting for a decision.")
    decision = {"decision": "APPROVED" if approved else "REJECTED"}
    await run_graph(graph, Command(resume=decision), config, deps)
    return await answer_for(graph, run_id)


async def run_graph(
    graph: CompiledStateGraph, value: Any, config: dict[str, Any], deps: AgentDeps
) -> None:
    failure = None
    try:
        await graph.ainvoke(value, config, context=deps)
    except ProviderError as error:
        failure = AgentError(error.code, error.message)
    if failure is not None:
        raise failure


async def answer_for(graph: CompiledStateGraph, run_id: str) -> AgentAnswer:
    snapshot = await graph.aget_state(thread_config(run_id))
    values = snapshot.values
    proposed = values.get("proposed_action")
    notes = [values.get("summary", "")]
    if proposed is None:
        notes.append(NO_ACTION_TEXT)
    if values.get("knowledge_unavailable"):
        notes.append(NO_KNOWLEDGE_TEXT)
    return AgentAnswer(
        text=" ".join(note for note in notes if note),
        plan=[plan_step(step) for step in values.get("steps", [])],
        proposed_action=ProposedAction(**proposed) if proposed else None,
        risk=values.get("risk"),
        blocked=[BlockedStep(**step) for step in values.get("blocked", [])],
        references=[hit["ref_id"] for hit in values.get("knowledge", [])],
        run_id=run_id,
        checkpoint_id=snapshot.config["configurable"].get("checkpoint_id"),
        waiting="wait" in snapshot.next,
        decision=values.get("decision"),
        prompt_tokens=values.get("prompt_tokens", 0),
        completion_tokens=values.get("completion_tokens", 0),
        masked_count=values.get("masked_count", 0),
    )


def plan_step(step: dict[str, Any]) -> PlanStep:
    action = step["action"]
    return PlanStep(
        order=step["order"],
        title=step["title"],
        action=ProposedAction(**action) if action else None,
    )


def thread_config(run_id: str) -> dict[str, Any]:
    if not run_id:
        raise AgentError("RUN_ID_MISSING", "Every agent run needs its agent_run_id.")
    return {"configurable": {"thread_id": str(run_id)}}
