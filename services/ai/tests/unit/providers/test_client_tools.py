"""complete_with_tools: one agent step with tool calls, masked both ways."""

import json

import pytest

from reconix_ai.providers import client
from reconix_ai.providers.client import ProviderError, complete_with_tools
from reconix_ai.providers.settings import ProviderConfig, ProviderType, reconix_provider

litellm = client.litellm  # through the client: litellm must load after its settings

TOOLS = [{"type": "function", "function": {"name": "edit_file", "parameters": {}}}]
RECONIX_URL = "https://models.reconix.example/v1"


def reply(content: str = "", calls: list[tuple[str, dict]] | None = None) -> litellm.ModelResponse:
    tool_calls = [
        {
            "id": f"c{n}",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(args)},
        }
        for n, (name, args) in enumerate(calls or [], start=1)
    ]
    message = {"role": "assistant", "content": content, "tool_calls": tool_calls or None}
    return litellm.ModelResponse(
        choices=[{"message": message, "finish_reason": "tool_calls" if tool_calls else "stop"}],
        usage={"prompt_tokens": 50, "completion_tokens": 7, "total_tokens": 57},
    )


class FakeModel:
    def __init__(self) -> None:
        self.answer: litellm.ModelResponse | Exception = reply("ok")
        self.calls: list[dict] = []

    async def acompletion(self, **kwargs: object) -> litellm.ModelResponse:
        self.calls.append(kwargs)
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> FakeModel:
    fake = FakeModel()
    monkeypatch.setattr(client.litellm, "acompletion", fake.acompletion)
    monkeypatch.setenv("RECONIX_MODEL_URL", RECONIX_URL)
    monkeypatch.setenv("RECONIX_MODEL_API_KEY", "fake-reconix-key")
    monkeypatch.delenv("RECONIX_MODEL_NAME", raising=False)
    return fake


async def test_tool_calls_come_back_with_their_arguments(model: FakeModel) -> None:
    model.answer = reply("Fixing it.", [("edit_file", {"old_text": "a", "new_text": "b"})])

    got = await complete_with_tools([{"role": "user", "content": "fix"}], TOOLS, reconix_provider())

    assert got.text == "Fixing it."
    assert [(c.call_id, c.name, json.loads(c.arguments)) for c in got.tool_calls] == [
        ("c1", "edit_file", {"old_text": "a", "new_text": "b"})
    ]
    assert (got.prompt_tokens, got.completion_tokens) == (50, 7)
    assert model.calls[0]["tools"] == TOOLS


async def test_messages_and_earlier_tool_calls_are_masked_before_they_leave(
    model: FakeModel,
) -> None:
    messages = [
        {"role": "user", "content": "the code: password=hunter2"},
        {
            "role": "assistant",
            "content": "",
            "tool_calls": [
                {
                    "id": "c1",
                    "type": "function",
                    "function": {
                        "name": "edit_file",
                        "arguments": '{"new_text": "token=abc123secret"}',
                    },
                }
            ],
        },
        {"role": "tool", "tool_call_id": "c1", "content": "api_key=sk-zzzzzzzzzzzz"},
    ]

    got = await complete_with_tools(messages, TOOLS, reconix_provider())

    sent = json.dumps(model.calls[0]["messages"])
    for secret in ("hunter2", "abc123secret", "sk-zzzzzzzzzzzz"):
        assert secret not in sent
    assert model.calls[0]["messages"][2]["tool_call_id"] == "c1"
    assert got.masked_count == 3


async def test_secrets_in_the_answer_and_its_arguments_are_masked(model: FakeModel) -> None:
    model.answer = reply("token=abc123secret", [("edit_file", {"new_text": "password=hunter2"})])

    got = await complete_with_tools([{"role": "user", "content": "x"}], TOOLS, reconix_provider())

    assert "abc123secret" not in got.text
    assert "hunter2" not in got.tool_calls[0].arguments
    assert json.loads(got.tool_calls[0].arguments)  # still JSON
    assert got.masked_count == 2


async def test_an_empty_answer_raises(model: FakeModel) -> None:
    model.answer = reply("")

    with pytest.raises(ProviderError) as error:
        await complete_with_tools([{"role": "user", "content": "x"}], TOOLS, reconix_provider())
    assert error.value.code == "EMPTY_RESPONSE"


async def test_model_errors_use_the_same_codes(model: FakeModel) -> None:
    model.answer = litellm.exceptions.AuthenticationError("bad key sk-real", "openai", "m")

    with pytest.raises(ProviderError) as error:
        await complete_with_tools([{"role": "user", "content": "x"}], TOOLS, reconix_provider())
    assert error.value.code == "PROVIDER_AUTH_FAILED"
    assert "sk-real" not in error.value.message


async def test_no_url_is_refused_before_any_call(
    model: FakeModel, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("RECONIX_MODEL_URL")

    with pytest.raises(ProviderError) as error:
        await complete_with_tools([{"role": "user", "content": "x"}], TOOLS, reconix_provider())
    assert error.value.code == "PROVIDER_URL_MISSING"
    assert model.calls == []


async def test_a_cloud_model_gets_at_most_its_own_output_limit(model: FakeModel) -> None:
    config = ProviderConfig(ProviderType.OPENAI, "gpt-4o", api_key="fake-openai-key")

    await complete_with_tools([{"role": "user", "content": "x"}], TOOLS, config)

    assert model.calls[0]["max_tokens"] == 16_384  # gpt-4o's own limit, not the 128k default


def tool_chat(results: list[str]) -> list[dict]:
    """A fix-loop chat: the task, then one tool call and its result per entry."""
    chat: list[dict] = [{"role": "system", "content": "fix"}, {"role": "user", "content": "task"}]
    for n, result in enumerate(results):
        call = {"id": f"c{n}", "type": "function", "function": {"name": "read", "arguments": "{}"}}
        chat.append({"role": "assistant", "content": "", "tool_calls": [call]})
        chat.append({"role": "tool", "tool_call_id": f"c{n}", "content": result})
    return chat


async def test_older_tool_results_are_cut_when_the_window_fills(model: FakeModel) -> None:
    # The Reconix model holds 64,000: six 30,000-character results (~60,000 tokens) do not fit.
    chat = tool_chat([f"{n}" * 30_000 for n in range(6)])

    await complete_with_tools(chat, TOOLS, reconix_provider())

    sent = [m["content"] for m in model.calls[0]["messages"] if m["role"] == "tool"]
    assert all(text == text[:300] + client.CUT_MARKER + text[-100:] for text in sent[:-1])
    assert sent[-1] == "5" * 30_000  # the newest is kept whole
    assert [m["content"] for m in chat if m["role"] == "tool"][0] == "0" * 30_000  # not changed
    assert model.calls[0]["max_tokens"] > client.MIN_ANSWER_TOKENS


async def test_tool_results_that_fit_are_sent_whole(model: FakeModel) -> None:
    chat = tool_chat(["a" * 3_000, "b" * 3_000])

    await complete_with_tools(chat, TOOLS, reconix_provider())

    sent = [m["content"] for m in model.calls[0]["messages"] if m["role"] == "tool"]
    assert sent == ["a" * 3_000, "b" * 3_000]
