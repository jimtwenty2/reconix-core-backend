"""A reasoning model gets the full answer length and the budget to use it, and a big
prompt is compacted so the run goes on."""

from dataclasses import replace
from uuid import uuid4

from reconix_ai.agent import ask_agent, nodes
from reconix_ai.knowledge import KnowledgeHit, Source
from reconix_ai.providers.settings import MAX_OUTPUT_TOKENS_CEILING, ProviderConfig, ProviderType
from tests.unit.agent.fakes import (
    PLANNED,
    REFLECTED,
    UNDERSTOOD,
    FakeModel,
    FakeSearch,
    Request,
    make_deps,
)

THINKING_TOKENS = 100_000  # a long think, as a Claude 5 model may write


async def test_every_call_gets_the_configured_length_and_the_budget_allows_it(graph) -> None:
    model = FakeModel(UNDERSTOOD, REFLECTED, PLANNED)
    sent = []

    async def thinking(messages, config, json_answer=False):
        sent.append(config.max_tokens)
        done = await model.complete(messages, config, json_answer)
        return replace(done, completion_tokens=THINKING_TOKENS)

    provider = ProviderConfig(ProviderType.ANTHROPIC, "claude-sonnet-5-5", api_key="sk-fake-1")
    deps = replace(make_deps(model), complete=thinking, provider=provider)
    request = Request(tool_results=["22/tcp open ssh OpenSSH 8.9"])

    answer = await ask_agent(graph, request, str(uuid4()), deps)

    # 200,000 tokens spent before the plan: the old 60,000 budget stopped at the reflection.
    assert sent == [MAX_OUTPUT_TOKENS_CEILING] * 3
    assert answer.waiting


def big_hit(n: int) -> KnowledgeHit:
    return KnowledgeHit(Source.TOOL_GUIDE, f"guide-{n}", "guide", "k" * 1200, "", f"s{n}", 1.0)


async def test_a_big_prompt_is_compacted_and_the_run_goes_on(graph) -> None:
    model = FakeModel(UNDERSTOOD, REFLECTED, PLANNED)
    older = [f"OLDER-{n} " + "x" * 3990 for n in range(2)]
    newest = "NEWEST 22/tcp open ssh OpenSSH 8.9 " + "y" * 3900
    request = Request(
        tool_results=[*older, newest],
        recent_reasoning=[f"reasoning {n} " + "r" * 300 for n in range(6)],
    )
    search = FakeSearch([big_hit(n) for n in range(6)])

    answer = await ask_agent(graph, request, str(uuid4()), make_deps(model, search))

    reflect_prompt, plan_prompt = model.prompts[1], model.prompts[2]
    for prompt in (reflect_prompt, plan_prompt):
        text = prompt[1].content
        # Near the threshold: what compaction may not cut (the instructions, scope, newest
        # result, the 3 newest hits) sits above it, and grows when the prompt files do.
        assert nodes.prompt_tokens(prompt) <= nodes.COMPACT_AT_PROMPT_TOKENS + 1_000
        assert newest in text  # the newest result is whole
        assert "OLDER-0" in text and "[compacted:" in text  # older ones are cut, not lost
        assert "172.20.0.0/24" in text  # the scope is kept
        assert nodes.REASONING_MARKER in text and "reasoning 5 " in text
        assert "reasoning 0 " not in text and "reasoning 4 " in text
        # The 2 older results, once each (plan compacts again with no effect); the 3 hits
        # find gives are the newest, so they stay whole.
        assert text.count("[compacted:") == 2 and "k" * 1200 in text
    assert "Port 22 is open" in plan_prompt[1].content  # the reflection survives
    assert answer.waiting  # the run went on to a suggested step


async def test_a_small_prompt_is_not_compacted(graph) -> None:
    model = FakeModel(UNDERSTOOD, REFLECTED, PLANNED)
    request = Request(tool_results=["one " + "a" * 3000, "two " + "b" * 3000])

    await ask_agent(graph, request, str(uuid4()), make_deps(model))

    assert "[compacted:" not in model.sent_text()
    assert "a" * 3000 in model.sent_text()


def test_compaction_never_touches_the_scope_findings_or_reflections() -> None:
    state = {
        "scope": {"ip_ranges": ["10.0.0.0/8"]},
        "findings": [{"code": "F-1", "evidence": "e" * 5000}],
        "reflections": ["one", "two"],
        "tool_results": ["old " + "o" * 5000, "new"],
        "knowledge": [{"ref_id": str(n), "section": "", "text": "k" * 1200} for n in range(5)],
    }

    update = nodes.compaction(state, lambda s: [nodes.Message("user", "z" * 100_000)])

    assert set(update) == {"tool_results", "knowledge"}
    assert update["tool_results"][1] == "new"
    assert len(update["tool_results"][0]) < 500
    assert [len(hit["text"]) < 500 for hit in update["knowledge"]] == [
        True,
        True,
        False,
        False,
        False,
    ]
    assert nodes.compaction(
        {**state, **update}, lambda s: [nodes.Message("user", "z" * 100_000)]
    ) == {**update}  # running it again changes nothing


def test_shortened_keeps_the_head_and_the_tail_and_counts_the_cut() -> None:
    text = "a" * 300 + "m" * 1000 + "z" * 100  # 1,400 characters, 1,000 of them cut

    assert nodes.shortened(text) == "a" * 300 + "\n[compacted: 1000 chars cut]\n" + "z" * 100


def test_shortening_again_changes_nothing() -> None:
    once = nodes.shortened("a" * 300 + "m" * 1000 + "z" * 100)

    assert nodes.shortened(once) == once


def test_a_text_of_at_most_400_characters_is_unchanged() -> None:
    assert nodes.shortened("x" * 400) == "x" * 400
    assert nodes.shortened("x" * 401) != "x" * 401
