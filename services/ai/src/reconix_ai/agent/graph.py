"""The LangGraph graph: understand -> find -> plan -> suggest -> wait for PLAN
and SUGGEST, with reflect (up to 5 times) between find and plan when there are
tool results; find -> analyze for ANALYZE, report for REPORT and find -> chat
for CHAT. Only PLAN and SUGGEST ever wait.

ask_agent() runs it for one agent run and stops at wait, where it is saved in
the checkpointer (Postgres in the app) until a person decides. resume_agent()
hands it the decision. The run id is agent_runs.agent_run_id and is the
LangGraph thread id.
"""

from typing import Any, Protocol
from uuid import UUID

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.errors import GraphRecursionError
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph
from langgraph.types import Command

from reconix_ai.agent import nodes
from reconix_ai.agent.nodes import AgentDeps, AgentError
from reconix_ai.agent.state import (
    MAX_MESSAGES,
    MAX_PRIOR_REASONING,
    MAX_TOOL_RESULTS,
    AgentState,
    ScopeLike,
    masked_findings,
    masked_report,
    masked_texts,
    scope_to_dict,
)
from reconix_ai.contracts import (
    SEVERITY_ORDER,
    AgentAnswer,
    BlockedStep,
    FindingAnalysis,
    PlanStep,
    ProposedAction,
)
from reconix_ai.harness.checks.input import check_input
from reconix_ai.harness.checks.result import Decision
from reconix_ai.knowledge.search import ref_ids_in
from reconix_ai.providers import ProviderError

SUPPORTED_TASKS = {"PLAN", "SUGGEST", "ANALYZE", "REPORT", "CHAT", "VALIDATE"}
SCOPE_STATUSES = {"APPROVED", "DRAFT"}
MAX_PLAN_LINES = 10  # CHAT: the plan has at most 5 steps; a few lines of notes besides
MAX_CHAT_QUERY_CHARS = 200
MAX_FINDINGS = 10  # per ANALYZE ask; the API sends a long list in parts
MAX_ANALYZE_QUERIES = 5
# A report bigger than this is refused; the model sees at most MAX_REPORT_PROMPT_ROWS
# of each list, worst first, and the files always hold everything.
MAX_REPORT_FINDINGS = 500
MAX_REPORT_TOOL_RUNS = 200
# Steps one ask may take. A plan takes 5; the limit stops a loop, never a normal run.
MAX_STEPS = 25

NO_ACTION_TEXT = "No step in the plan passed the safety checks, so nothing is suggested."
NO_KNOWLEDGE_TEXT = "The knowledge search was not available, so this plan uses no reference data."


class ChatScopeLike(ScopeLike, Protocol):
    status: str  # APPROVED or DRAFT


class AgentRequestLike(Protocol):
    """The fields of the shared AgentRequest the agent reads."""

    task: str
    assessment_id: UUID | None  # CHAT: none before the scope is submitted
    scope: ScopeLike | None  # every task but CHAT needs it
    messages: list[str]
    tool_results: list[str]
    findings: list[Any]  # ANALYZE: the shared FindingInput
    report: Any | None  # REPORT: the shared ReportInput
    chat_scope: ChatScopeLike | None  # CHAT: the scope the person talks about
    plan: list[str]  # CHAT: the current plan, one line per step
    recent_reasoning: list[str]  # the agent's own earlier per-step reasoning, oldest first


def build_graph(checkpointer: BaseCheckpointSaver) -> CompiledStateGraph:
    graph = StateGraph(AgentState, context_schema=AgentDeps)
    graph.add_node("understand", nodes.understand)
    graph.add_node("find", nodes.find)
    graph.add_node("reflect", nodes.reflect)
    graph.add_node("plan", nodes.plan)
    graph.add_node("suggest", nodes.suggest)
    graph.add_node("wait", nodes.wait)
    graph.add_node("analyze", nodes.analyze)
    graph.add_node("validate", nodes.validate)
    graph.add_node("report", nodes.report)
    graph.add_node("chat", nodes.chat)
    graph.add_conditional_edges(
        START,
        nodes.start_task,
        {
            "plan": "understand",
            "analyze": "find",
            "validate": "validate",
            "report": "report",
            "chat": "find",
        },
    )
    graph.add_edge("understand", "find")
    graph.add_conditional_edges(
        "find",
        nodes.after_find,
        {"reflect": "reflect", "plan": "plan", "analyze": "analyze", "chat": "chat"},
    )
    graph.add_conditional_edges(
        "reflect", nodes.after_reflect, {"reflect": "reflect", "plan": "plan"}
    )
    graph.add_edge("analyze", END)
    graph.add_edge("validate", END)
    graph.add_edge("report", END)
    graph.add_edge("chat", END)
    graph.add_edge("plan", "suggest")
    graph.add_conditional_edges("suggest", nodes.after_suggest, {"wait": "wait", "done": END})
    graph.add_edge("wait", END)
    return graph.compile(checkpointer=checkpointer)


async def ask_agent(
    graph: CompiledStateGraph, request: AgentRequestLike, run_id: str, deps: AgentDeps
) -> AgentAnswer:
    """PLAN or SUGGEST: plan for the approved scope, suggest one step and wait for a
    person. ANALYZE: suggest the 8-part analysis of each finding and stop. CHAT: answer
    the person's last message and stop."""
    task = str(request.task).upper()
    if task not in SUPPORTED_TASKS:
        raise AgentError("TASK_NOT_SUPPORTED", f"The agent cannot do {task} yet.")
    config = thread_config(run_id)
    # A run that failed half way may be asked again; only a waiting run may not.
    if "wait" in (await graph.aget_state(config)).next:
        raise AgentError("RUN_IS_WAITING", "This run is waiting for a person to decide.")
    check_chat(list(request.messages)[-MAX_MESSAGES:])

    messages, masked_in_messages = masked_texts(list(request.messages), MAX_MESSAGES)
    results, masked_in_results = masked_texts(list(request.tool_results), MAX_TOOL_RESULTS)
    findings, masked_in_findings = masked_findings(list(request.findings))
    reasoning, masked_in_reasoning = masked_texts(
        list(request.recent_reasoning), MAX_PRIOR_REASONING
    )
    if task == "ANALYZE":
        check_findings(findings)
    if task == "VALIDATE":
        check_validate(findings, results)
    report, masked_in_report = {}, 0
    if task == "REPORT":
        check_report(request.report)
        report, masked_in_report = masked_report(request.report)
    start: AgentState = {
        "task": task,
        "assessment_id": str(request.assessment_id or ""),
        **task_scope(task, request),
        "messages": messages,
        "tool_results": results,
        "reflections": [],
        "prior_reasoning": reasoning,
        "proposed_action": None,
        "risk": None,
        "blocked": [],
        "decision": None,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "findings": findings,
        "analysis_summary": "",
        "analysis": [],
        "report": report,
        "executive_summary": "",
        "methodology": "",
        "masked_count": masked_in_messages
        + masked_in_results
        + masked_in_findings
        + masked_in_reasoning
        + masked_in_report,
    }
    if task == "ANALYZE":
        start["queries"] = analyze_queries(findings)
    if task == "CHAT":
        plan, masked_in_plan = masked_texts(list(request.plan), MAX_PLAN_LINES)
        start["plan_lines"] = plan
        start["masked_count"] += masked_in_plan
        start["queries"] = [messages[-1][:MAX_CHAT_QUERY_CHARS]] if messages else []
    await run_graph(graph, start, config, deps)
    return await answer_for(graph, run_id)


def task_scope(task: str, request: AgentRequestLike) -> dict[str, Any]:
    """The scope the task reads. Every task but CHAT needs the approved scope; CHAT reads
    the scope the person talks about, approved or a draft, or none at all."""
    if task != "CHAT":
        if request.scope is None:
            raise AgentError("SCOPE_MISSING", f"{task} needs the approved scope.")
        return {"scope": scope_to_dict(request.scope), "scope_status": "APPROVED"}
    chat_scope = request.chat_scope
    if chat_scope is None:
        return {"scope": None, "scope_status": "NONE"}
    status = str(chat_scope.status).upper()
    if status not in SCOPE_STATUSES:
        raise AgentError("BAD_SCOPE_STATUS", "A chat scope is APPROVED or DRAFT.")
    return {"scope": scope_to_dict(chat_scope), "scope_status": status}


def check_findings(findings: list[dict[str, Any]]) -> None:
    """The list is well formed, and the input check passes on the text the parsers
    copied from the target, as it does on the chat."""
    if not findings:
        raise AgentError("NO_FINDINGS", "There are no findings to analyze.")
    if len(findings) > MAX_FINDINGS:
        raise AgentError(
            "TOO_MANY_FINDINGS", f"Send at most {MAX_FINDINGS} findings in one analysis."
        )
    codes = [finding.get("code") for finding in findings]
    if not all(isinstance(code, str) and code for code in codes):
        raise AgentError("FINDING_WITHOUT_CODE", "Every finding needs its code.")
    if len(set(codes)) != len(codes):
        raise AgentError("DUPLICATE_FINDING", "Each finding code may be sent only once.")
    for finding in findings:
        for name in ("title", "target", "description"):
            outcome = check_input(finding.get(name) or "")
            if outcome.decision == Decision.BLOCKED:
                raise AgentError(
                    "INPUT_BLOCKED", f"Finding {finding['code']} was blocked: {outcome.reason}."
                )


def check_validate(findings: list[dict[str, Any]], tool_results: list[str]) -> None:
    """VALIDATE judges exactly one finding against a real PoC run, so it needs that one
    finding (input-checked like ANALYZE) and at least one tool result to read."""
    if len(findings) != 1:
        raise AgentError("ONE_FINDING", "A validation judges exactly one finding.")
    check_findings(findings)
    if not any(result.strip() for result in tool_results):
        raise AgentError("NO_TOOL_RESULT", "A validation needs the PoC tool output to judge.")


def check_report(report: Any) -> None:
    if report is None:
        raise AgentError("NO_REPORT_DATA", "A report needs the locked copy of its data.")
    if len(report.findings) > MAX_REPORT_FINDINGS or len(report.tool_runs) > MAX_REPORT_TOOL_RUNS:
        raise AgentError(
            "REPORT_TOO_LARGE",
            f"A report holds at most {MAX_REPORT_FINDINGS} findings and "
            f"{MAX_REPORT_TOOL_RUNS} tool runs.",
        )
    for level, count in dict(report.severity_counts).items():
        # bool is an int in Python; true is not a count.
        good_count = isinstance(count, int) and not isinstance(count, bool) and count >= 0
        if level not in SEVERITY_ORDER or not good_count:
            raise AgentError(
                "BAD_REPORT_DATA", "severity_counts takes the 6 severities and whole counts."
            )


def analyze_queries(findings: list[dict[str, Any]]) -> list[str]:
    """Knowledge searches for the analysis: the findings' own ids, else their titles."""
    names = ("cve_ids", "cwe_ids", "owasp_id")
    # ref_ids_in keeps only well-formed ids, so no other text from a list is searched.
    ids = [i for f in findings for name in names for i in ref_ids_in(" ".join(f.get(name, [])))]
    titles = [finding.get("title") or finding["code"] for finding in findings]
    queries = list(dict.fromkeys(ids)) or titles
    return [query[:200] for query in queries[:MAX_ANALYZE_QUERIES]]


# A CHAT's own earlier answers, as the API names them. They are not the person's
# words: an answer that says it "can't skip the safety checks" must not block the chat.
AGENT_SPEAKERS = ("Reconix: ", "Reconix note: ")


def check_chat(messages: list[str]) -> None:
    """The harness input check on each chat message the person wrote that the model will
    see, on the raw text before it is cut, so a long message or a buried injection is
    caught."""
    for message in messages:
        if message.startswith(AGENT_SPEAKERS):
            continue
        outcome = check_input(message)
        if outcome.decision == Decision.BLOCKED:
            raise AgentError("INPUT_BLOCKED", f"The chat was blocked: {outcome.reason}.")


async def resume_agent(
    graph: CompiledStateGraph, run_id: str, approved: bool, deps: AgentDeps
) -> AgentAnswer:
    """Give a waiting run the person's decision.

    approved is True only for an APPROVED approval. REJECTED and EXPIRED both
    pass False, and the run records REJECTED.

    This only tells the agent what happened. It is not the approval: the API
    keeps its own approval row (action hash, 30-minute expiry, single use) and
    runs check() again with the current scope right before the tool runs. Two
    resumes at the same moment are not locked here; the single-use approval is
    what stops a tool running twice.
    """
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
        await graph.ainvoke(value, config | {"recursion_limit": MAX_STEPS}, context=deps)
    except GraphRecursionError:
        failure = AgentError(
            "STEP_LIMIT", f"The agent took more than {MAX_STEPS} steps and stopped."
        )
    except AgentError as error:
        failure = AgentError(error.code, error.message)
    except ProviderError as error:
        failure = AgentError(error.code, error.message)
    except Exception:
        # The original may carry a URL, a request or a secret; none of it is passed on.
        failure = AgentError("AGENT_FAILED", "The agent stopped on an unexpected error.")
    if failure is not None:
        raise failure


async def answer_for(graph: CompiledStateGraph, run_id: str) -> AgentAnswer:
    snapshot = await graph.aget_state(thread_config(run_id))
    values = snapshot.values
    proposed = values.get("proposed_action")
    # The latest ReflAct line, labelled as the agent's own note on the tool results.
    reflected = [f"Agent note: {line}" for line in values.get("reflections", [])[-1:]]
    notes = [*reflected, values.get("summary", "")]
    if values.get("task") == "ANALYZE":
        notes = [values.get("analysis_summary", "")]
    elif values.get("task") == "VALIDATE":
        notes = [values.get("validation_reason", "")]
    elif values.get("task") == "REPORT":
        notes = [values.get("executive_summary", "")]
    elif values.get("task") == "CHAT":
        notes = [values.get("answer", "")]
    elif proposed is None:
        notes.append(NO_ACTION_TEXT)
    if values.get("knowledge_unavailable") and values.get("task") != "CHAT":
        notes.append(NO_KNOWLEDGE_TEXT)
    return AgentAnswer(
        text=" ".join(note for note in notes if note),
        plan=[plan_step(step) for step in values.get("steps", [])],
        proposed_action=ProposedAction(**proposed) if proposed else None,
        risk=values.get("risk"),
        blocked=[BlockedStep(**step) for step in values.get("blocked", [])],
        references=references(values),
        agent_run_id=run_id,
        checkpoint_id=snapshot.config["configurable"].get("checkpoint_id"),
        waiting="wait" in snapshot.next,
        decision=values.get("decision"),
        analysis_summary=values.get("analysis_summary", ""),
        analysis=[finding_analysis(item) for item in values.get("analysis", [])],
        validation_status=values.get("validation_status"),
        validation_reason=values.get("validation_reason", ""),
        executive_summary=values.get("executive_summary") or None,
        methodology=values.get("methodology") or None,
        prompt_tokens=values.get("prompt_tokens", 0),
        completion_tokens=values.get("completion_tokens", 0),
        masked_count=values.get("masked_count", 0),
    )


def references(values: dict[str, Any]) -> list[str]:
    """The knowledge used; for CHAT, only the known ids its answer names."""
    if values.get("task") == "CHAT":
        return list(values.get("chat_references", []))
    return [hit["ref_id"] for hit in values.get("knowledge", [])]


def finding_analysis(item: dict[str, Any]) -> FindingAnalysis:
    step = item["next_step"]
    return FindingAnalysis(**{**item, "next_step": ProposedAction(**step) if step else None})


def plan_step(step: dict[str, Any]) -> PlanStep:
    action = step["action"]
    return PlanStep(
        order=step["order"],
        title=step["title"],
        action=ProposedAction(**action) if action else None,
        phase=step.get("phase"),
        reason=step.get("reason", ""),
    )


def thread_config(run_id: str) -> dict[str, Any]:
    if not run_id:
        raise AgentError("RUN_ID_MISSING", "Every agent run needs its agent_run_id.")
    return {"configurable": {"thread_id": str(run_id)}}
