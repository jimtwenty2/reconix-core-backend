"""A "prompt too long" error: recognised, retried once, then PROMPT_TOO_LONG."""

import socket

import pytest

from reconix_ai.providers import client, window
from reconix_ai.providers.client import Message, ProviderError, complete, complete_with_tools
from reconix_ai.providers.overflow import is_overflow, learned_window
from reconix_ai.providers.settings import ProviderConfig, ProviderType, reconix_provider

litellm = client.litellm  # through the client: litellm must load after its settings

TOOLS = [{"type": "function", "function": {"name": "read", "parameters": {}}}]
VLLM_TEXT = (
    "This model's maximum context length is 8192 tokens. However, you requested 9000 "
    "tokens (4000 in the messages, 5000 in the completion)."
)


def bad_request(text: str) -> Exception:
    return litellm.exceptions.BadRequestError(text, model="m", llm_provider="openai")


def answer(text: str = "ok") -> litellm.ModelResponse:
    return litellm.ModelResponse(
        choices=[{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]
    )


class FakeModel:
    """Gives each call the next outcome: an exception is raised, a response returned."""

    def __init__(self, *outcomes: Exception | litellm.ModelResponse) -> None:
        self.outcomes = list(outcomes)
        self.calls: list[dict] = []

    async def acompletion(self, **kwargs: object) -> litellm.ModelResponse:
        self.calls.append(kwargs)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture
def served(monkeypatch: pytest.MonkeyPatch):
    def serve(*outcomes: Exception | litellm.ModelResponse) -> FakeModel:
        fake = FakeModel(*outcomes)
        monkeypatch.setattr(client.litellm, "acompletion", fake.acompletion)
        return fake

    monkeypatch.setenv("RECONIX_MODEL_URL", "https://models.reconix.example/v1")
    monkeypatch.setenv("RECONIX_MODEL_API_KEY", "fake-reconix-key")
    monkeypatch.delenv("RECONIX_MODEL_NAME", raising=False)
    return serve


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (litellm.exceptions.ContextWindowExceededError("x", model="m", llm_provider="p"), True),
        (bad_request("This model's maximum context length is 8192 tokens"), True),
        (bad_request("prompt is too long: 250000 tokens > 200000 maximum"), True),
        (bad_request("Request Entity Too Large"), True),
        (bad_request("Please reduce the length of the messages"), True),
        (bad_request("response_format json_object is not supported"), False),
        (bad_request("Rate limit reached: too many tokens per minute, context window"), False),
        (bad_request("quota exceeded, input is too long"), False),
        (litellm.exceptions.RateLimitError("context length", "p", "m"), False),
        (RuntimeError("context length exceeded"), False),
    ],
)
def test_is_overflow(error: Exception, expected: bool) -> None:
    assert is_overflow(error) is expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (VLLM_TEXT, 8192),
        ("maximum context length is 131,072 tokens", 131_072),
        ("Your maximum context window of 4096 tokens was exceeded", 4096),
        ("max context length: 16384", 16_384),
        ("prompt is too long", None),
        ("maximum context length is 12", None),  # not a window
    ],
)
def test_learned_window(text: str, expected: int | None) -> None:
    assert learned_window(bad_request(text)) == expected


async def test_complete_retries_once_with_the_window_the_server_names(served) -> None:
    fake = served(bad_request(VLLM_TEXT), answer("fits now"))

    got = await complete([Message("user", "hi")], reconix_provider())

    assert got.text == "fits now"
    assert len(fake.calls) == 2
    # 8192 window: the retry no longer asks for the default (larger) answer length.
    assert fake.calls[1]["max_tokens"] <= 8192 - 1_000
    assert fake.calls[1]["max_tokens"] < fake.calls[0]["max_tokens"]
    # The window is kept: the next call is sized to it from the start.
    next_fake = served(answer())
    await complete([Message("user", "hi")], reconix_provider())
    assert next_fake.calls[0]["max_tokens"] <= 8192 - 1_000


async def test_complete_without_a_learned_window_does_not_retry(served) -> None:
    fake = served(bad_request("prompt is too long"))

    with pytest.raises(ProviderError) as caught:
        await complete([Message("user", "hi")], reconix_provider())

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert len(fake.calls) == 1


async def test_a_second_overflow_is_prompt_too_long_without_the_provider_text(served) -> None:
    fake = served(bad_request(VLLM_TEXT), bad_request(VLLM_TEXT))

    with pytest.raises(ProviderError) as caught:
        await complete([Message("user", "hi")], reconix_provider())

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert "8192" not in caught.value.message
    assert len(fake.calls) == 2


async def test_json_answer_overflow_does_not_take_the_response_format_retry(served) -> None:
    fake = served(bad_request("prompt is too long"))

    with pytest.raises(ProviderError) as caught:
        await complete([Message("user", "hi")], reconix_provider(), json_answer=True)

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert len(fake.calls) == 1  # not asked again without response_format


async def test_json_answer_still_retries_without_response_format(served) -> None:
    fake = served(bad_request("json_object is not supported"), answer('{"a": 1}'))

    await complete([Message("user", "hi")], reconix_provider(), json_answer=True)

    assert fake.calls[1]["response_format"] is None


def tool_chat(results: list[str]) -> list[dict]:
    chat: list[dict] = [{"role": "system", "content": "fix"}, {"role": "user", "content": "go"}]
    for n, result in enumerate(results):
        call = {"id": f"c{n}", "type": "function", "function": {"name": "read", "arguments": "{}"}}
        chat.append({"role": "assistant", "content": "", "tool_calls": [call]})
        chat.append({"role": "tool", "tool_call_id": f"c{n}", "content": result})
    return chat


async def test_tool_loop_retry_cuts_every_result_even_without_a_learned_number(served) -> None:
    fake = served(bad_request("prompt is too long"), answer("done"))
    chat = tool_chat(["a" * 5_000, "b" * 5_000])  # small enough that nothing is cut at first

    got = await complete_with_tools(chat, TOOLS, reconix_provider())

    assert got.text == "done"
    first = [m["content"] for m in fake.calls[0]["messages"] if m["role"] == "tool"]
    retry = [m["content"] for m in fake.calls[1]["messages"] if m["role"] == "tool"]
    assert first == ["a" * 5_000, "b" * 5_000]
    assert all(len(text) < 600 and client.CUT_MARKER in text for text in retry)  # newest too


async def test_tool_loop_retry_uses_the_learned_window(served) -> None:
    fake = served(bad_request(VLLM_TEXT), answer("done"))

    await complete_with_tools(tool_chat(["a" * 5_000]), TOOLS, reconix_provider())

    assert fake.calls[1]["max_tokens"] <= 8192 - 1_000


async def test_tool_loop_second_overflow_is_prompt_too_long(served) -> None:
    fake = served(bad_request("prompt is too long"), bad_request("prompt is too long"))

    with pytest.raises(ProviderError) as caught:
        await complete_with_tools(tool_chat(["a" * 5_000]), TOOLS, reconix_provider())

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert len(fake.calls) == 2


async def test_a_remembered_window_comes_first_for_every_provider_type() -> None:
    config = reconix_provider()
    window.remember_window(config, "https://x/v1", 4_096)
    assert await window.context_window(config, "openai/m", "https://x/v1", {}) == 4_096

    other = ProviderConfig(ProviderType.OLLAMA, "llama3")
    window.remember_window(other, "http://ollama:11434", 2_048)
    assert await window.context_window(other, "m", "http://ollama:11434", {}) == 2_048


def test_a_cut_keeps_head_and_tail_and_is_idempotent() -> None:
    text = "H" * 300 + "m" * 5_000 + "T" * 100
    chat = tool_chat([text])

    once = client.fitted_tool_results(chat, TOOLS, 64_000, force=True)
    twice = client.fitted_tool_results(once, TOOLS, 64_000, force=True)

    assert once[-1]["content"] == "H" * 300 + client.CUT_MARKER + "T" * 100
    assert twice == once
    assert client.fitted_tool_results(chat, TOOLS, 64_000) == chat  # fits: left alone


@pytest.mark.parametrize("name", ["gpt-4o", "llama3:8b", "qwen2.5-coder:7b", "ollama/llama3"])
async def test_the_bundled_lookup_makes_no_network_call(
    monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("network call")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    config = ProviderConfig(ProviderType.OPENAI_API_COMPATIBLE, name)

    got = await window.context_window(config, f"openai/{name}", "https://proxy.example/v1", {})

    assert got == (128_000 if name == "gpt-4o" else window.BASELINE_WINDOW)


async def test_ollama_uses_the_bundled_window_capped_at_the_baseline() -> None:
    small = ProviderConfig(ProviderType.OLLAMA, "gpt-4")  # bundled: 8,192
    big = ProviderConfig(ProviderType.OLLAMA, "gpt-4o")  # bundled: 128,000

    assert await window.context_window(small, "m", "http://ollama:11434", {}) == 8_192
    assert await window.context_window(big, "m", "http://ollama:11434", {}) == 32_000
