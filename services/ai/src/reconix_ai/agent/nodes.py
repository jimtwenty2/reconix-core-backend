"""The steps of the agent: understand, find, plan, suggest and wait for PLAN and
SUGGEST; find and analyze for ANALYZE; report for REPORT.

Only understand, plan, analyze and report call the model. suggest runs the harness check() on
each planned step and offers the first one it allows; the API runs check()
again, with the full context, before anything runs. wait pauses the graph
until a person approves or rejects the step.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

from langgraph.runtime import Runtime
from langgraph.types import interrupt

from reconix_ai.agent.answers import (
    MAX_GOAL_CHARS,
    MAX_QUERY_CHARS,
    BadAnswer,
    json_object,
    read_plan,
    read_understanding,
)
from reconix_ai.agent.prompts import (
    analyze_messages,
    plan_messages,
    report_messages,
    understand_messages,
)
from reconix_ai.agent.state import AgentScope, AgentState, scope_from_dict
from reconix_ai.analysis.answers import read_analysis
from reconix_ai.contracts import ProposedAction
from reconix_ai.harness import check
from reconix_ai.harness.checks.result import Decision
from reconix_ai.knowledge import KnowledgeHit, search_knowledge
from reconix_ai.knowledge.search import ref_ids_in
from reconix_ai.providers import (
    Completion,
    Message,
    ProviderConfig,
    ProviderError,
    complete,
    reconix_provider,
)
from reconix_ai.reports.answers import read_report

ATTEMPTS = 2  # a bad answer is asked once more
# Tokens one ask may spend in total, prompts and answers together. A plan uses a few thousand.
DEFAULT_TOKEN_BUDGET = 20_000
HITS_PER_QUERY = 3
# An analysis answers for up to 10 findings at once, so it may write more than a plan.
ANALYZE_MAX_TOKENS = 6000
REPORT_MAX_TOKENS = 3000
MAX_HITS = 6
MAX_PROMPT_HIT_CHARS = 1200
DEFAULT_GOAL = "Find what runs on the approved targets."

Complete = Callable[..., Awaitable[Completion]]
Search = Callable[..., Awaitable[list[KnowledgeHit]]]


class AgentError(Exception):
    """The agent could not answer. code is UPPERCASE, e.g. BAD_MODEL_ANSWER."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AgentDeps:
    """What the steps use besides the state. Never saved in a checkpoint, so the
    provider's API key stays out of the database."""

    provider: ProviderConfig = field(default_factory=reconix_provider)
    complete: Complete = complete
    search: Search = search_knowledge
    now: Callable[[], datetime] = lambda: datetime.now(UTC)
    token_budget: int = DEFAULT_TOKEN_BUDGET


@dataclass(frozen=True)
class CheckInput:
    """The harness context the agent can fill in. The agent does not know the
    recent runs, so the API's own check() is the one that enforces the loop limits."""

    scope: AgentScope
    now: datetime
    input_text: str | None
    recent_runs: tuple = ()
    runs_in_assessment: int = 0


async def understand(state: AgentState, runtime: Runtime[AgentDeps]) -> dict[str, Any]:
    answer, usage = await ask_json(
        runtime.context, understand_messages(state), read_understanding, tokens_used(state)
    )
    if answer is None:
        messages = state.get("messages", [])
        goal = messages[-1][:MAX_GOAL_CHARS] if messages else DEFAULT_GOAL
        answer = (goal, [goal[:MAX_QUERY_CHARS]])
    goal, queries = answer
    return {"goal": goal, "queries": queries, **added(state, usage)}


async def find(state: AgentState, runtime: Runtime[AgentDeps]) -> dict[str, Any]:
    """Knowledge for the plan. Planning goes on without it if the search is down."""
    hits: list[dict[str, str]] = []
    seen = set()
    try:
        for query in state.get("queries", []):
            for hit in await runtime.context.search(query, limit=HITS_PER_QUERY):
                if (hit.ref_id, hit.section) not in seen:
                    seen.add((hit.ref_id, hit.section))
                    hits.append(hit_dict(hit))
    except Exception:  # KnowledgeError, ProviderError or anything else: plan without it
        return {"knowledge": hits[:MAX_HITS], "knowledge_unavailable": True}
    return {"knowledge": hits[:MAX_HITS], "knowledge_unavailable": False}


async def plan(state: AgentState, runtime: Runtime[AgentDeps]) -> dict[str, Any]:
    answer, usage = await ask_json(
        runtime.context, plan_messages(state), read_plan, tokens_used(state)
    )
    if answer is None:
        raise AgentError("BAD_MODEL_ANSWER", "The model did not give a usable plan.")
    summary, steps = answer
    return {"summary": summary, "steps": steps, **added(state, usage)}


def suggest(state: AgentState, runtime: Runtime[AgentDeps]) -> dict[str, Any]:
    """Offer the first planned step the harness allows."""
    messages = state.get("messages", [])
    context = CheckInput(
        scope=scope_from_dict(state["scope"]),
        now=runtime.context.now(),
        input_text=messages[-1] if messages else None,
    )
    blocked = []
    for step in state.get("steps", []):
        if step["action"] is None:
            continue
        result = check(ProposedAction(**step["action"]), context)
        if result.decision == Decision.ALLOW:
            return {"proposed_action": step["action"], "risk": str(result.risk), "blocked": blocked}
        blocked.append(
            {"order": step["order"], "blocked_by": str(result.blocked_by), "reason": result.reason}
        )
    return {"proposed_action": None, "risk": None, "blocked": blocked}


async def analyze(state: AgentState, runtime: Runtime[AgentDeps]) -> dict[str, Any]:
    """The 8-part analysis of each finding. Suggestions only; a person accepts them."""
    deps = runtime.context
    longer = replace(deps, provider=replace(deps.provider, max_tokens=ANALYZE_MAX_TOKENS))
    findings = state.get("findings", [])
    tool_results = state.get("tool_results", [])
    known = known_ids(state.get("knowledge", []))
    answer, usage = await ask_json(
        longer,
        analyze_messages(state),
        lambda data: read_analysis(data, findings, tool_results, known),
        tokens_used(state),
    )
    if answer is None:
        raise AgentError("BAD_MODEL_ANSWER", "The model did not give a usable analysis.")
    summary, analyses = answer
    context = CheckInput(scope=scope_from_dict(state["scope"]), now=deps.now(), input_text=None)
    return {
        "analysis_summary": summary,
        "analysis": [checked_next_step(analysis, context) for analysis in analyses],
        **added(state, usage),
    }


async def report(state: AgentState, runtime: Runtime[AgentDeps]) -> dict[str, Any]:
    """The executive summary and the methodology, written from the locked copy."""
    deps = runtime.context
    longer = replace(deps, provider=replace(deps.provider, max_tokens=REPORT_MAX_TOKENS))
    answer, usage = await ask_json(longer, report_messages(state), read_report, tokens_used(state))
    if answer is None:
        raise AgentError("BAD_MODEL_ANSWER", "The model did not give a usable report text.")
    executive_summary, methodology = answer
    return {
        "executive_summary": executive_summary,
        "methodology": methodology,
        **added(state, usage),
    }


def checked_next_step(analysis: dict[str, Any], context: "CheckInput") -> dict[str, Any]:
    """A next step the harness blocks is dropped, and the person is told why."""
    step = analysis["next_step"]
    if step is None:
        return analysis
    result = check(ProposedAction(**step), context)
    if result.decision == Decision.ALLOW:
        return analysis
    note = (
        f"The suggested next step was blocked by the {result.blocked_by} check ({result.reason})."
    )
    unsure = " ".join(part for part in (analysis["unsure"], note) if part)
    return {**analysis, "next_step": None, "unsure": unsure}


def known_ids(hits: list[dict[str, str]]) -> set[str]:
    """Ids the knowledge gives: each hit's own id only. An id named inside a hit's
    text does not count, because a search on attacker-written text chose the hit."""
    return {ref_id for hit in hits for ref_id in ref_ids_in(hit["ref_id"])}


def wait(state: AgentState) -> dict[str, Any]:
    """Pause until a person decides. Anything but APPROVED counts as REJECTED."""
    answer = interrupt({"proposed_action": state["proposed_action"], "risk": state["risk"]})
    approved = isinstance(answer, dict) and answer.get("decision") == "APPROVED"
    return {"decision": "APPROVED" if approved else "REJECTED"}


def start_task(state: AgentState) -> str:
    task = state.get("task")
    return {"ANALYZE": "analyze", "REPORT": "report"}.get(task, "plan")


def after_suggest(state: AgentState) -> str:
    return "wait" if state.get("proposed_action") else "done"


async def ask_json(
    deps: AgentDeps,
    messages: list[Message],
    read: Callable[[dict[str, Any]], Any],
    spent: int,
) -> tuple[Any | None, dict[str, int]]:
    """Ask for a JSON answer and read it with `read`. None after ATTEMPTS bad answers.

    spent is the tokens this ask used before this step; no call starts once the
    budget is used up.
    """
    usage = {"prompt_tokens": 0, "completion_tokens": 0, "masked_count": 0}
    for _ in range(ATTEMPTS):
        check_budget(deps, spent + usage["prompt_tokens"] + usage["completion_tokens"])
        completion = await safe_complete(deps, messages)
        usage["prompt_tokens"] += completion.prompt_tokens
        usage["completion_tokens"] += completion.completion_tokens
        usage["masked_count"] += completion.masked_count
        try:
            return read(json_object(completion.text)), usage
        except BadAnswer:
            continue
    return None, usage


async def safe_complete(deps: AgentDeps, messages: list[Message]) -> Completion:
    """A model call whose errors carry only a code and a masked message.

    LangGraph saves a failing step's exception in the checkpoint, so nothing raw
    may be raised from a node.
    """
    failure = None
    try:
        return await deps.complete(messages, deps.provider, json_answer=True)
    except ProviderError as error:
        failure = AgentError(error.code, error.message)  # already masked
    except Exception:
        failure = AgentError("MODEL_UNAVAILABLE", "The model could not answer.")
    raise failure


def check_budget(deps: AgentDeps, spent: int) -> None:
    if spent >= deps.token_budget:
        raise AgentError(
            "TOKEN_BUDGET",
            f"The agent used its budget of {deps.token_budget} tokens and stopped.",
        )


def tokens_used(state: AgentState) -> int:
    return state.get("prompt_tokens", 0) + state.get("completion_tokens", 0)


def added(state: AgentState, usage: dict[str, int]) -> dict[str, int]:
    """This step's usage added to the totals of the current ask."""
    return {name: state.get(name, 0) + count for name, count in usage.items()}


def hit_dict(hit: KnowledgeHit) -> dict[str, str]:
    return {
        "source": str(hit.source),
        "ref_id": hit.ref_id,
        "title": hit.title,
        "section": hit.section,
        "text": hit.text[:MAX_PROMPT_HIT_CHARS],
        "url": hit.url,
    }
