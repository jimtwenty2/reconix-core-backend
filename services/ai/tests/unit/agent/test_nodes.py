"""ask_json: a malformed answer is retried, and an empty answer (a flaky Anthropic endpoint
returns empty intermittently) is retried too instead of failing the whole run with a 502."""

import pytest

from reconix_ai.agent import nodes
from reconix_ai.agent.answers import read_understanding
from reconix_ai.agent.nodes import AgentError, ask_json
from reconix_ai.providers import Message, ProviderError

from .fakes import FakeModel, make_deps

GOAL = {"goal": "find vulns on the target", "search": []}


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch):
    monkeypatch.setattr(nodes, "EMPTY_BACKOFF_SECONDS", 0)  # no real sleeps in the tests


async def test_an_empty_answer_is_retried_not_fatal() -> None:
    # The first call returns empty (raises EMPTY_RESPONSE); the retry answers.
    model = FakeModel(ProviderError("EMPTY_RESPONSE", "The model sent back an empty answer."), GOAL)

    result, _usage = await ask_json(make_deps(model), [Message("user", "x")], read_understanding, 0)

    assert result == ("find vulns on the target", ["find vulns on the target"])
    assert len(model.prompts) == 2  # it asked again after the empty answer


async def test_a_burst_of_empties_is_ridden_through() -> None:
    # Five empties in a row (a bad burst) then an answer: the run recovers, it does not stop.
    empties = [ProviderError("EMPTY_RESPONSE", "empty") for _ in range(5)]
    model = FakeModel(*empties, GOAL)

    result, _usage = await ask_json(make_deps(model), [Message("user", "x")], read_understanding, 0)

    assert result[0] == "find vulns on the target"
    assert len(model.prompts) == 6


async def test_a_persistent_empty_answer_still_raises() -> None:
    model = FakeModel(*[ProviderError("EMPTY_RESPONSE", "empty") for _ in range(10)])

    with pytest.raises(AgentError) as exc:
        await ask_json(make_deps(model), [Message("user", "x")], read_understanding, 0)

    assert exc.value.code == "EMPTY_RESPONSE"


async def test_a_real_provider_error_is_not_retried() -> None:
    # Only an empty answer is retried; a genuine failure (e.g. auth) raises at once.
    model = FakeModel(ProviderError("PROVIDER_AUTH_FAILED", "refused"), GOAL)

    with pytest.raises(AgentError) as exc:
        await ask_json(make_deps(model), [Message("user", "x")], read_understanding, 0)

    assert exc.value.code == "PROVIDER_AUTH_FAILED"
    assert len(model.prompts) == 1  # not retried
