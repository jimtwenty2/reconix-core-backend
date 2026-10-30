import os

import pytest

from reconix_ai.providers import client
from reconix_ai.providers.client import Message, ProviderError, complete
from reconix_ai.providers.settings import ProviderConfig, ProviderType, reconix_provider

# Through the client, never a direct import: litellm must load after its settings.
litellm = client.litellm

QUESTION = [Message(role="user", content="Which ports are open on 172.20.0.5?")]


class FakeModel:
    """Stands in for litellm.acompletion and remembers what it was sent."""

    def __init__(self, answer: str | Exception = "Port 3000 is open.") -> None:
        self.answer = answer
        self.calls: list[dict] = []

    async def acompletion(self, **kwargs: object) -> litellm.ModelResponse:
        self.calls.append(kwargs)
        return await REAL_ACOMPLETION(**kwargs, mock_response=self.answer)


REAL_ACOMPLETION = litellm.acompletion


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> FakeModel:
    fake = FakeModel()
    monkeypatch.setattr(client.litellm, "acompletion", fake.acompletion)
    monkeypatch.delenv("RECONIX_OLLAMA_URL", raising=False)
    return fake


async def test_reconix_calls_the_local_ollama_model(model: FakeModel) -> None:
    completion = await complete(QUESTION, reconix_provider())

    assert completion.text == "Port 3000 is open."
    assert completion.provider_type == ProviderType.RECONIX
    assert completion.model_name == "reconix"
    assert model.calls[0]["model"] == "ollama_chat/reconix"
    assert model.calls[0]["api_base"] == "http://127.0.0.1:11434"


async def test_json_answer_asks_for_a_json_object(model: FakeModel) -> None:
    await complete([Message("user", "plan")], reconix_provider())
    await complete([Message("user", "plan")], reconix_provider(), json_answer=True)

    assert model.calls[0]["response_format"] is None
    assert model.calls[1]["response_format"] == {"type": "json_object"}


async def test_every_call_caps_the_answer_length(model: FakeModel) -> None:
    short = ProviderConfig(ProviderType.RECONIX, "reconix", max_tokens=300)

    await complete(QUESTION, reconix_provider())
    await complete(QUESTION, short)

    assert model.calls[0]["max_tokens"] == 2000
    assert model.calls[1]["max_tokens"] == 300


async def test_ollama_url_comes_from_the_environment(
    model: FakeModel, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECONIX_OLLAMA_URL", "http://ollama:11434")

    await complete(QUESTION, reconix_provider())

    assert model.calls[0]["api_base"] == "http://ollama:11434"


async def test_ollama_provider_uses_its_own_model_and_url(model: FakeModel) -> None:
    config = ProviderConfig(
        provider_type=ProviderType.OLLAMA,
        model_name="llama3.1:8b",
        base_url="http://127.0.0.1:11500",
    )

    completion = await complete(QUESTION, config)

    assert completion.model_name == "llama3.1:8b"
    assert model.calls[0]["model"] == "ollama_chat/llama3.1:8b"
    assert model.calls[0]["api_base"] == "http://127.0.0.1:11500"


async def test_secrets_are_masked_before_the_model_sees_them(model: FakeModel) -> None:
    messages = [Message(role="user", content="Login with password=hunter2 please")]

    completion = await complete(messages, reconix_provider())

    sent = model.calls[0]["messages"][0]["content"]
    assert "hunter2" not in sent
    assert "[MASKED:password]" in sent
    assert completion.masked_count == 1


async def test_secrets_in_the_answer_are_masked(model: FakeModel) -> None:
    model.answer = "Found token=abc123secret in the config."

    completion = await complete(QUESTION, reconix_provider())

    assert "abc123secret" not in completion.text
    assert completion.masked_count == 1


async def test_token_counts_are_returned(model: FakeModel) -> None:
    completion = await complete(QUESTION, reconix_provider())

    assert completion.prompt_tokens > 0
    assert completion.completion_tokens > 0


async def test_model_down_raises_model_unavailable(model: FakeModel) -> None:
    model.answer = litellm.exceptions.APIConnectionError(
        message="Cannot connect to host", llm_provider="ollama_chat", model="reconix"
    )

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, reconix_provider())

    assert raised.value.code == "MODEL_UNAVAILABLE"


async def test_missing_model_raises_model_not_found(model: FakeModel) -> None:
    model.answer = litellm.exceptions.NotFoundError(
        message="model 'reconix' not found", llm_provider="ollama_chat", model="reconix"
    )

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, reconix_provider())

    assert raised.value.code == "MODEL_NOT_FOUND"


async def test_error_message_never_shows_the_key(model: FakeModel) -> None:
    model.answer = litellm.exceptions.APIConnectionError(
        message="failed with api_key=sk-live-1234567890abcdefghij",
        llm_provider="ollama_chat",
        model="reconix",
    )

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, reconix_provider())

    assert "sk-live-1234567890abcdefghij" not in raised.value.message
    assert raised.value.__cause__ is None
    assert raised.value.__context__ is None


async def test_error_message_never_shows_the_provider_text(model: FakeModel) -> None:
    model.answer = litellm.exceptions.APIConnectionError(
        message="OllamaException: cannot reach http://127.0.0.1:11434/api/chat",
        llm_provider="ollama_chat",
        model="reconix",
    )

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, reconix_provider())

    assert raised.value.code == "MODEL_UNAVAILABLE"
    assert raised.value.message == "The RECONIX model reconix could not answer. Is it running?"


async def test_error_message_hides_the_exact_key_of_any_shape(model: FakeModel) -> None:
    config = ProviderConfig(
        provider_type=ProviderType.OLLAMA,
        model_name="llama3.1:8b",
        base_url="https://models.example.com",
        api_key="Zq9plainlookingvalue",
    )
    model.answer = litellm.exceptions.AuthenticationError(
        message="invalid key Zq9plainlookingvalue", llm_provider="ollama_chat", model="x"
    )

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, config)

    assert raised.value.code == "PROVIDER_AUTH_FAILED"
    assert "Zq9plainlookingvalue" not in raised.value.message


@pytest.mark.parametrize(
    "base_url",
    [
        "http://10.0.0.5:11434",
        "http://127.0.0.1:11434/admin?",
        "https://169.254.169.254",
        "file:///etc/passwd",
    ],
)
async def test_unsafe_base_url_is_refused_before_any_call(model: FakeModel, base_url: str) -> None:
    config = ProviderConfig(
        provider_type=ProviderType.OLLAMA, model_name="llama3.1:8b", base_url=base_url
    )

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, config)

    assert raised.value.code == "PROVIDER_URL_NOT_ALLOWED"
    assert model.calls == []


def test_litellm_settings_are_pinned() -> None:
    for name, value in client.LITELLM_ENV.items():
        assert os.environ[name] == value
    assert os.environ["LITELLM_MODE"] == "PRODUCTION"  # never loads .env
    assert litellm.turn_off_message_logging is True


async def test_empty_answer_raises(model: FakeModel) -> None:
    model.answer = "   "

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, reconix_provider())

    assert raised.value.code == "EMPTY_RESPONSE"


async def test_provider_types_not_built_yet_are_refused(model: FakeModel) -> None:
    config = ProviderConfig(provider_type=ProviderType.OPENAI, model_name="gpt-4o", api_key="x")

    with pytest.raises(ProviderError) as raised:
        await complete(QUESTION, config)

    assert raised.value.code == "PROVIDER_NOT_SUPPORTED"
    assert model.calls == []


def test_api_key_is_not_in_the_config_repr() -> None:
    config = ProviderConfig(
        provider_type=ProviderType.OPENAI, model_name="gpt-4o", api_key="sk-secret"
    )

    assert "sk-secret" not in repr(config)


@pytest.mark.skipif(
    os.environ.get("RECONIX_OLLAMA_SMOKE") != "1",
    reason="Set RECONIX_OLLAMA_SMOKE=1 with the reconix model on a running Ollama.",
)
async def test_smoke_real_reconix_model_answers() -> None:
    completion = await complete(
        [Message(role="user", content="Reply with the single word: ready")],
        reconix_provider(),
    )

    assert completion.text.strip()
