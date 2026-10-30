"""CHAT: one answer to the person's last message, with the scope and plan as context."""

from uuid import uuid4

import pytest

from reconix_ai.agent import AgentError, ask_agent
from tests.unit.agent.fakes import ChatScope, FakeModel, FakeSearch, Request, make_deps, nmap_guide

ANSWER = {"answer": "nmap -sV finds service versions.", "references": ["nmap", "CVE-2099-1"]}


def chat_request(**values) -> Request:
    return Request(
        task="CHAT",
        assessment_id=None,
        scope=None,
        messages=["What does -sV do?"],
        **values,
    )


def user_prompt(model: FakeModel) -> str:
    return model.prompts[0][-1].content


async def test_chat_answers_and_never_waits(graph) -> None:
    model = FakeModel(ANSWER)

    answer = await ask_agent(graph, chat_request(), str(uuid4()), make_deps(model))

    assert answer.text == "nmap -sV finds service versions."
    assert not answer.waiting
    assert answer.proposed_action is None and answer.plan == []
    assert answer.references == ["nmap"]  # CVE-2099-1 is not in the knowledge: dropped
    assert len(model.prompts) == 1


async def test_chat_searches_the_knowledge_with_the_question(graph) -> None:
    search = FakeSearch([nmap_guide("-sV probes open ports for versions.")])
    model = FakeModel(ANSWER)

    await ask_agent(graph, chat_request(), str(uuid4()), make_deps(model, search))

    assert search.queries == ["What does -sV do?"]
    assert "-sV probes open ports for versions." in user_prompt(model)


async def test_a_draft_scope_is_shown_as_not_approved(graph) -> None:
    model = FakeModel(ANSWER)
    request = chat_request(chat_scope=ChatScope(status="DRAFT"))

    await ask_agent(graph, request, str(uuid4()), make_deps(model))

    prompt = user_prompt(model)
    assert "Draft scope (not approved yet" in prompt
    assert "172.20.0.0/24" in prompt
    assert "Allowed tools: NMAP, NUCLEI, ZAP" in prompt


async def test_without_a_scope_the_model_is_told_so(graph) -> None:
    model = FakeModel(ANSWER)

    await ask_agent(graph, chat_request(), str(uuid4()), make_deps(model))

    assert "No scope has been written yet." in user_prompt(model)


async def test_the_plan_is_fenced_as_data_and_masked(graph) -> None:
    model = FakeModel(ANSWER)
    plan = ["1. Find open ports: NMAP 172.20.0.5 -sV", "2. Log in with password=hunter2"]

    answer = await ask_agent(graph, chat_request(plan=plan), str(uuid4()), make_deps(model))

    prompt = user_prompt(model)
    assert "<plan>" in prompt and "Find open ports" in prompt
    assert "hunter2" not in prompt
    assert answer.masked_count >= 1


async def test_a_bad_status_is_refused(graph) -> None:
    request = chat_request(chat_scope=ChatScope(status="MAYBE"))

    with pytest.raises(AgentError) as error:
        await ask_agent(graph, request, str(uuid4()), make_deps(FakeModel(ANSWER)))

    assert error.value.code == "BAD_SCOPE_STATUS"


async def test_two_bad_answers_are_a_bad_model_answer(graph) -> None:
    model = FakeModel("not json", {"answer": ""})

    with pytest.raises(AgentError) as error:
        await ask_agent(graph, chat_request(), str(uuid4()), make_deps(model))

    assert error.value.code == "BAD_MODEL_ANSWER"


async def test_control_characters_are_dropped_from_the_answer(graph) -> None:
    model = FakeModel({"answer": "line one\n\x1b[31mline two\x07", "references": []})

    answer = await ask_agent(graph, chat_request(), str(uuid4()), make_deps(model))

    assert answer.text == "line one\n[31mline two"


async def test_other_tasks_still_need_the_approved_scope(graph) -> None:
    with pytest.raises(AgentError) as error:
        await ask_agent(graph, Request(scope=None), str(uuid4()), make_deps(FakeModel()))

    assert error.value.code == "SCOPE_MISSING"
