import pytest

from reconix_ai.providers import client, embeddings
from reconix_ai.providers.client import ProviderError
from reconix_ai.providers.embeddings import EmbeddingConfig, embed_texts

litellm = client.litellm  # never imported directly: it must load after its settings


class FakeEmbeddingModel:
    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.error: Exception | None = None

    async def aembedding(self, **kwargs: object) -> object:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        data = [{"embedding": [float(i), 0.0]} for i, _ in enumerate(kwargs["input"])]
        return type("Response", (), {"data": data})()


@pytest.fixture
def model(monkeypatch: pytest.MonkeyPatch) -> FakeEmbeddingModel:
    fake = FakeEmbeddingModel()
    monkeypatch.setattr(embeddings.litellm, "aembedding", fake.aembedding)
    monkeypatch.delenv("RECONIX_EMBEDDINGS_URL", raising=False)
    return fake


async def test_uses_bge_m3_on_the_embedding_server(model: FakeEmbeddingModel) -> None:
    vectors = await embed_texts(["sql injection"])

    assert vectors == [[0.0, 0.0]]
    assert model.calls[0]["model"] == "openai/bge-m3"
    assert model.calls[0]["api_base"] == "http://127.0.0.1:8081/v1"


async def test_the_compose_service_comes_from_the_environment(
    model: FakeEmbeddingModel, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RECONIX_EMBEDDINGS_URL", "http://embeddings:8080/v1")

    await embed_texts(["x"])

    assert model.calls[0]["api_base"] == "http://embeddings:8080/v1"


async def test_texts_are_masked_before_they_leave(model: FakeEmbeddingModel) -> None:
    await embed_texts(["token=abc123secret in the config"])

    assert "abc123secret" not in model.calls[0]["input"][0]


async def test_large_input_is_sent_in_batches(model: FakeEmbeddingModel) -> None:
    vectors = await embed_texts([f"text {i}" for i in range(70)])

    assert len(vectors) == 70
    assert [len(call["input"]) for call in model.calls] == [32, 32, 6]


async def test_model_down_gives_a_clear_error(model: FakeEmbeddingModel) -> None:
    model.error = litellm.exceptions.APIConnectionError(
        message="Cannot connect", llm_provider="openai", model="bge-m3"
    )

    with pytest.raises(ProviderError) as raised:
        await embed_texts(["x"])

    assert raised.value.code == "MODEL_UNAVAILABLE"
    assert raised.value.__context__ is None


async def test_unsafe_address_is_refused(model: FakeEmbeddingModel) -> None:
    with pytest.raises(ProviderError) as raised:
        await embed_texts(["x"], EmbeddingConfig(base_url="http://10.0.0.5:8080/v1"))

    assert raised.value.code == "PROVIDER_URL_NOT_ALLOWED"
    assert model.calls == []
