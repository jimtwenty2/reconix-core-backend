"""The LangGraph graph: understand -> find -> plan -> suggest -> wait for PLAN
and SUGGEST, find -> analyze for ANALYZE and report for REPORT. Only PLAN and
SUGGEST ever wait.

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

SUPPORTED_TASKS = {"PLAN", "SUGGEST", "ANALYZE", "REPORT"}  # CHAT comes with task 6
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


class AgentRequestLike(Protocol):
    """The fields of the shared AgentRequest the agent reads."""

    task: str
    assessment_id: UUID
    scope: ScopeLike
    messages: list[str]
    tool_results: list[str]
    findings: list[Any]  # ANALYZE: the shared FindingInput
    report: Any | None  # REPORT: the shared ReportInput


def build_graph(checkpointer: BaseCheckpointSaver) -> CompiledStateGraph:
    graph = StateGraph(AgentState, context_schema=AgentDeps)
    graph.add_node("understand", nodes.understand)
    graph.add_node("find", nodes.find)
    graph.add_node("plan", nodes.plan)
    graph.add_node("suggest", nodes.suggest)
    graph.add_node("wait", nodes.wait)
    graph.add_node("analyze", nodes.analyze)
    graph.add_node("report", nodes.report)
    graph.add_conditional_edges(
        START, nodes.start_task, {"plan": "understand", "analyze": "find", "report": "report"}
    )
    graph.add_edge("understand", "find")
    graph.add_conditional_edges("find", nodes.start_task, {"plan": "plan", "analyze": "analyze"})
    graph.add_edge("analyze", END)
    graph.add_edge("report", END)
    graph.add_edge("plan", "suggest")
    graph.add_conditional_edges("suggest", nodes.after_suggest, {"wait": "wait", "done": END})
    graph.add_edge("wait", END)
    return graph.compile(checkpointer=checkpointer)


async def ask_agent(
    graph: CompiledStateGraph, request: AgentRequestLike, run_id: str, deps: AgentDeps
) -> AgentAnswer:
    """PLAN or SUGGEST: plan for the approved scope, suggest one step and wait for a
    person. ANALYZE: suggest the 8-part analysis of each finding and stop."""
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
    if task == "ANALYZE":
        check_findings(findings)
    report, masked_in_report = {}, 0
    if task == "REPORT":
        check_report(request.report)
        report, masked_in_report = masked_report(request.report)
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
        + masked_in_report,
    }
    if task == "ANALYZE":
        start["queries"] = analyze_queries(findings)
    await run_graph(graph, start, config, deps)
    return await answer_for(graph, run_id)


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


def check_chat(messages: list[str]) -> None:
    """The harness input check on each chat message the model will see, on the raw
    text before it is cut, so a long message or a buried injection is caught."""
    for message in messages:
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
    notes = [values.get("summary", "")]
    if values.get("task") == "ANALYZE":
        notes = [values.get("analysis_summary", "")]
    elif values.get("task") == "REPORT":
        notes = [values.get("executive_summary", "")]
    elif proposed is None:
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
        agent_run_id=run_id,
        checkpoint_id=snapshot.config["configurable"].get("checkpoint_id"),
        waiting="wait" in snapshot.next,
        decision=values.get("decision"),
        analysis_summary=values.get("analysis_summary", ""),
        analysis=[finding_analysis(item) for item in values.get("analysis", [])],
        executive_summary=values.get("executive_summary") or None,
        methodology=values.get("methodology") or None,
        prompt_tokens=values.get("prompt_tokens", 0),
        completion_tokens=values.get("completion_tokens", 0),
        masked_count=values.get("masked_count", 0),
    )


def finding_analysis(item: dict[str, Any]) -> FindingAnalysis:
    step = item["next_step"]
    return FindingAnalysis(**{**item, "next_step": ProposedAction(**step) if step else None})


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
