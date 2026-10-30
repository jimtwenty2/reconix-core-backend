from dataclasses import replace
from uuid import uuid4

import pytest

from reconix_ai.agent import ask_agent
from reconix_ai.agent.answers import MAX_REFLECTION_CHARS, BadAnswer, read_reflection
from reconix_ai.agent.graph import NO_KNOWLEDGE_TEXT
from reconix_ai.knowledge import KnowledgeError, KnowledgeHit, Source
from tests.unit.agent.fakes import (
    PLANNED,
    REFLECTED,
    UNDERSTOOD,
    FakeModel,
    Request,
    make_deps,
)

RESULTS = Request(tool_results=["22/tcp open ssh OpenSSH 8.9"])


def run_id() -> str:
    return str(uuid4())


def looked_up(query: str) -> KnowledgeHit:
    return KnowledgeHit(Source.TOOL_GUIDE, query, query, f"About {query}.", "", "Options", 1.0)


class LookupSearch:
    """One hit named after each query; down from the query number `down_from` on."""

    def __init__(self, down_from: int | None = None) -> None:
        self.queries: list[str] = []
        self.down_from = down_from

    async def search(self, query: str, limit: int = 5) -> list[KnowledgeHit]:
        self.queries.append(query)
        if self.down_from is not None and len(self.queries) >= self.down_from:
            raise KnowledgeError("KNOWLEDGE_UNAVAILABLE", "Qdrant is down.")
        return [looked_up(query)]


async def test_reflects_once_on_tool_results_before_planning(graph) -> None:
    model = FakeModel(UNDERSTOOD, REFLECTED, PLANNED)

    answer = await ask_agent(graph, RESULTS, run_id(), make_deps(model))

    reflect_prompt, plan_prompt = model.prompts[1][1].content, model.prompts[2][1].content
    assert "# Reflect prompt" in reflect_prompt and "OpenSSH 8.9" in reflect_prompt
    assert "<reflections>\n- Port 22 is open" in plan_prompt
    assert answer.text == f"{REFLECTED['reflection']} Start with a service scan."
    assert answer.waiting


async def test_no_reflection_without_tool_results(graph) -> None:
    model = FakeModel(UNDERSTOOD, PLANNED)

    answer = await ask_agent(graph, Request(), run_id(), make_deps(model))

    assert len(model.prompts) == 2
    assert answer.text == "Start with a service scan."


async def test_looks_things_up_and_stops_after_five_reflections(graph) -> None:
    lines = [{"reflection": f"Line {n}.", "search": f"query {n}"} for n in range(1, 6)]
    model = FakeModel(UNDERSTOOD, *lines, PLANNED)
    search = LookupSearch()

    answer = await ask_agent(graph, RESULTS, run_id(), make_deps(model, search))

    # The fifth reflection is the last, so its search never runs.
    assert search.queries == ["nmap service scan", "query 1", "query 2", "query 3", "query 4"]
    assert "About query 1." in model.prompts[2][1].content  # the next reflection sees the hit
    plan_prompt = model.prompts[6][1].content
    assert all(f"- Line {n}." in plan_prompt for n in range(1, 6))
    assert answer.references == ["nmap service scan", "query 1", "query 2", "query 3", "query 4"]
    assert answer.text.startswith("Line 5.")


async def test_a_bad_reflection_still_gives_a_plan(graph) -> None:
    model = FakeModel(UNDERSTOOD, "not json", {"search": "x"}, PLANNED)

    answer = await ask_agent(graph, RESULTS, run_id(), make_deps(model))

    assert answer.text == "Start with a service scan."
    assert answer.waiting


async def test_half_the_token_budget_is_kept_for_the_plan(graph) -> None:
    model = FakeModel(UNDERSTOOD, PLANNED)
    deps = replace(make_deps(model), token_budget=200)  # understand alone uses 120

    answer = await ask_agent(graph, RESULTS, run_id(), deps)

    assert len(model.prompts) == 2
    assert answer.waiting


async def test_a_secret_in_a_reflection_is_masked(graph, saver) -> None:
    reflected = {"reflection": "The banner shows password=hunter2secret.", "search": None}
    model = FakeModel(UNDERSTOOD, reflected, PLANNED)

    answer = await ask_agent(graph, RESULTS, run_id(), make_deps(model))

    assert "hunter2secret" not in answer.text
    assert "hunter2secret" not in model.prompts[2][1].content
    assert answer.masked_count == 1
    saved = repr(list(saver.storage.items())) + repr(list(saver.writes.items())) + repr(saver.blobs)
    assert "hunter2secret" not in saved


async def test_planning_goes_on_when_a_lookup_fails(graph) -> None:
    reflected = {"reflection": "SSH is open.", "search": "openssh 8.9 cve"}
    model = FakeModel(UNDERSTOOD, reflected, PLANNED)

    answer = await ask_agent(graph, RESULTS, run_id(), make_deps(model, LookupSearch(2)))

    assert len(model.prompts) == 3  # no second reflection
    assert answer.text == f"SSH is open. Start with a service scan. {NO_KNOWLEDGE_TEXT}"
    assert answer.waiting


def test_a_reflection_is_one_short_line() -> None:
    line, query = read_reflection({"reflection": "First.\nSecond " + "x" * 400, "search": 7})

    assert (line, query) == ("First.", None)
    long_line, _ = read_reflection({"reflection": "y" * 400})
    assert len(long_line) == MAX_REFLECTION_CHARS


@pytest.mark.parametrize("data", [{}, {"reflection": "  "}, {"reflection": ["a"]}])
def test_a_missing_reflection_is_a_bad_answer(data: dict) -> None:
    with pytest.raises(BadAnswer):
        read_reflection(data)
