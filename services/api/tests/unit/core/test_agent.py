"""The real ask_agent, run on the AI's graph with an in-memory checkpointer and a scripted model."""

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import replace
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from langgraph.checkpoint.memory import InMemorySaver

from reconix_ai import agent
from reconix_ai.providers import (
    Completion,
    Message,
    ProviderConfig,
    ProviderError,
    ProviderType,
)
from reconix_api.core.agent import make_ask_agent
from reconix_api.core.errors import ApiError
from reconix_api.core.interfaces import (
    Action,
    AgentRequest,
    AgentTask,
    ApprovedScope,
    ChatMessage,
    FindingInput,
    ReportInput,
    ResumeInput,
    RiskLevel,
    ToolName,
    ToolRunInput,
)

UNDERSTOOD = {"goal": "Find open ports on the lab host.", "search": ["nmap service scan"]}
NMAP_STEP = {
    "title": "Find open ports and services",
    "tool": "NMAP",
    "target": "172.20.0.5",
    "arguments": ["-sV", "--top-ports", "100"],
}
PLANNED = {"summary": "Start with a service scan.", "steps": [NMAP_STEP]}
PROVIDER = ProviderConfig(ProviderType.RECONIX, "reconix")


class ScriptedModel:
    """Gives the scripted answers in order and keeps every prompt it was sent."""

    def __init__(self, *answers: object) -> None:
        self.answers = list(answers)
        self.prompts: list[list[Message]] = []

    async def complete(
        self, messages: list[Message], config: ProviderConfig, json_answer: bool = False
    ) -> Completion:
        self.prompts.append(messages)
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return Completion(json.dumps(answer), config.provider_type, "reconix", 10, 5, 0)

    def sent_text(self) -> str:
        return "\n".join(message.content for prompt in self.prompts for message in prompt)


async def no_knowledge(query: str, limit: int = 5) -> list:
    return []


def make_ask(model: ScriptedModel, **deps_overrides):
    saver = InMemorySaver()  # shared by every call, like the Postgres tables

    @asynccontextmanager
    async def open_graph() -> AsyncIterator:
        yield agent.build_graph(saver)

    deps = agent.AgentDeps(
        provider=PROVIDER,
        complete=model.complete,
        search=no_knowledge,
        now=lambda: datetime(2026, 10, 28, 10, tzinfo=UTC),
    )
    return make_ask_agent(open_graph, replace(deps, **deps_overrides))


def plan_request(run_id: UUID, **overrides) -> AgentRequest:
    scope = ApprovedScope(
        assessment_id=uuid4(),
        ip_ranges=["172.20.0.0/24"],
        allowed_tools=[ToolName.NMAP],
        max_risk=RiskLevel.MEDIUM,
    )
    values = {
        "task": AgentTask.PLAN,
        "assessment_id": scope.assessment_id,
        "agent_run_id": run_id,
        "scope": scope,
        "messages": [ChatMessage(role="user", content_masked="Scan the lab host.")],
    }
    return AgentRequest(**(values | overrides))


def resume_of(request: AgentRequest, decision: str, run_id: UUID | None = None) -> AgentRequest:
    resume = ResumeInput(
        agent_run_id=run_id or request.agent_run_id,
        assessment_id=request.assessment_id,
        approval_id=uuid4(),
        action=Action(tool=ToolName.NMAP, target="172.20.0.5", arguments=NMAP_STEP["arguments"]),
        decision=decision,
    )
    return request.model_copy(update={"resume": resume})


async def test_plan_suggests_one_step_and_waits():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
    run_id = uuid4()

    response = await ask(plan_request(run_id))

    assert response.waiting
    assert response.agent_run_id == run_id
    assert response.proposed_action == Action(
        tool=ToolName.NMAP, target="172.20.0.5", arguments=NMAP_STEP["arguments"]
    )
    assert response.risk == RiskLevel.MEDIUM
    assert response.checkpoint_id


async def test_resume_hands_the_waiting_run_the_decision():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
    request = plan_request(uuid4())
    await ask(request)

    response = await ask(resume_of(request, "APPROVED"))

    assert response.decision == "APPROVED"
    assert not response.waiting


async def test_resume_for_another_run_is_refused():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
    request = plan_request(uuid4())
    await ask(request)

    with pytest.raises(ApiError) as error:
        await ask(resume_of(request, "APPROVED", run_id=uuid4()))

    assert error.value.status == 422
    assert error.value.code == "RESUME_RUN_MISMATCH"


async def test_resume_for_another_assessment_is_refused():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
    request = plan_request(uuid4())
    await ask(request)
    resume = resume_of(request, "APPROVED")
    other = resume.model_copy(
        update={"resume": resume.resume.model_copy(update={"assessment_id": uuid4()})}
    )

    with pytest.raises(ApiError) as error:
        await ask(other)

    assert error.value.status == 422
    assert error.value.code == "RESUME_RUN_MISMATCH"


async def test_an_approval_for_another_action_does_not_resume_the_run():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
    request = plan_request(uuid4())
    await ask(request)
    resume = resume_of(request, "APPROVED")
    other_action = Action(tool=ToolName.NMAP, target="172.20.0.9", arguments=["-sV"])
    other = resume.model_copy(
        update={"resume": resume.resume.model_copy(update={"action": other_action})}
    )

    with pytest.raises(ApiError) as error:
        await ask(other)
    still_waiting = await ask(resume_of(request, "REJECTED"))

    assert error.value.status == 422
    assert error.value.code == "RESUME_RUN_MISMATCH"
    assert still_waiting.decision == "REJECTED"


async def test_a_waiting_run_cannot_be_asked_again():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED))
    request = plan_request(uuid4())
    await ask(request)

    with pytest.raises(ApiError) as error:
        await ask(request)

    assert error.value.status == 409
    assert error.value.code == "RUN_IS_WAITING"


async def test_only_the_persons_words_reach_the_model():
    model = ScriptedModel(UNDERSTOOD, PLANNED)
    messages = [
        ChatMessage(role="user", content_masked="Scan the lab host."),
        ChatMessage(role="assistant", content_masked="Earlier agent answer XYZZY."),
    ]

    await make_ask(model)(plan_request(uuid4(), messages=messages))

    assert "Scan the lab host." in model.sent_text()
    assert "XYZZY" not in model.sent_text()


async def test_a_blocked_chat_is_a_422_and_never_reaches_the_model():
    model = ScriptedModel(UNDERSTOOD, PLANNED)
    messages = [ChatMessage(role="user", content_masked="x" * 4001)]

    with pytest.raises(ApiError) as error:
        await make_ask(model)(plan_request(uuid4(), messages=messages))

    assert error.value.status == 422
    assert error.value.code == "INPUT_BLOCKED"
    assert model.prompts == []


@pytest.mark.parametrize(
    ("code", "status"),
    [
        ("MODEL_UNAVAILABLE", 503),
        ("MODEL_NOT_FOUND", 502),  # a setup problem, not a wait
        ("PROVIDER_AUTH_FAILED", 502),
        ("PROVIDER_KEY_MISSING", 422),
        ("PROVIDER_URL_NOT_ALLOWED", 422),
        ("BAD_MODEL_ANSWER", 502),
    ],
)
async def test_model_errors_keep_their_code_and_get_a_clear_status(code, status):
    with pytest.raises(ApiError) as error:
        await make_ask(ScriptedModel(ProviderError(code, "The model could not answer.")))(
            plan_request(uuid4())
        )

    assert error.value.status == status
    assert error.value.code == code


async def test_a_spent_token_budget_is_a_422():
    ask = make_ask(ScriptedModel(UNDERSTOOD, PLANNED), token_budget=10)

    with pytest.raises(ApiError) as error:
        await ask(plan_request(uuid4()))

    assert error.value.status == 422
    assert error.value.code == "TOKEN_BUDGET"


@pytest.mark.parametrize("overrides", [{"provider": "OPENAI"}, {"model": "gpt-x"}])
async def test_other_providers_are_not_ready(overrides):
    with pytest.raises(ApiError) as error:
        await make_ask(ScriptedModel())(plan_request(uuid4(), **overrides))

    assert error.value.status == 503
    assert error.value.details == {"part": "ai_providers"}


FTP_FINDING = FindingInput(
    code="RCX-001",
    title="Anonymous FTP login",
    target="172.20.0.5",
    description="vsftpd allows anonymous login.",
    severity_status="MEDIUM",
    finding_status="OPEN",
    cwe_ids=["CWE-287"],
)
FTP_OUTPUT = '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/>'


async def test_analyze_sends_the_findings_and_gives_back_the_analysis():
    analysis = {
        "code": "RCX-001",
        "explanation": "Anyone can log in to FTP.",
        "severity_status": "HIGH",
        "evidence": "Anonymous FTP login allowed (FTP code 230)",
        "cwe_ids": ["CWE-287"],
        "next_step": None,
        "unsure": "",
    }
    model = ScriptedModel({"summary": "FTP lets anyone in.", "findings": [analysis]})
    request = plan_request(
        uuid4(), task=AgentTask.ANALYZE, findings=[FTP_FINDING], tool_results=[FTP_OUTPUT]
    )

    response = await make_ask(model)(request)

    assert "Anonymous FTP login" in model.sent_text()
    assert response.analysis_summary == "FTP lets anyone in."
    assert response.analysis[0].code == "RCX-001"
    assert response.analysis[0].severity_status == "HIGH"
    assert response.analysis[0].evidence == analysis["evidence"]
    assert not response.waiting


async def test_analyze_without_findings_is_a_422():
    with pytest.raises(ApiError) as error:
        await make_ask(ScriptedModel())(plan_request(uuid4(), task=AgentTask.ANALYZE))

    assert error.value.status == 422
    assert error.value.code == "NO_FINDINGS"


async def test_report_sends_the_real_locked_copy_with_dates():
    run = ToolRunInput(
        tool=ToolName.NMAP,
        target="172.20.0.5",
        args=["-sV"],
        risk_level=RiskLevel.MEDIUM,
        tool_run_status="COMPLETED",
        approval_check="APPROVED",
        started_at=datetime(2026, 10, 29, 9, tzinfo=UTC),
    )
    copy = ReportInput(findings=[FTP_FINDING], severity_counts={"MEDIUM": 1}, tool_runs=[run])
    model = ScriptedModel({"executive_summary": "One FTP issue.", "methodology": "One nmap run."})

    response = await make_ask(model)(plan_request(uuid4(), task=AgentTask.REPORT, report=copy))

    assert response.executive_summary == "One FTP issue."
    assert response.methodology == "One nmap run."
    assert '"started_at": "2026-10-29T09:00:00+00:00"' in model.sent_text()
    assert '"tool": "NMAP"' in model.sent_text()


async def test_report_without_its_locked_copy_is_a_422():
    with pytest.raises(ApiError) as error:
        await make_ask(ScriptedModel())(plan_request(uuid4(), task=AgentTask.REPORT))

    assert error.value.status == 422
    assert error.value.code == "NO_REPORT_DATA"
