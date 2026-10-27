"""Text to vectors for the knowledge search, with BGE-M3 on the local Ollama.

Same rules as client.py: texts are masked before they leave, and errors come
back as a masked ProviderError.
"""

from dataclasses import dataclass

from reconix_ai.harness import mask_secrets
from reconix_ai.providers.client import (
    ProviderError,
    checked_base_url,
    litellm,
    openai,
    provider_error,
)
from reconix_ai.providers.settings import DEFAULT_TIMEOUT_SECONDS, ProviderConfig, ProviderType

EMBEDDING_MODEL_NAME = "bge-m3"
EMBEDDING_SIZE = 1024  # BGE-M3 dense vectors
BATCH_SIZE = 32


@dataclass(frozen=True)
class EmbeddingConfig:
    model_name: str = EMBEDDING_MODEL_NAME
    base_url: str | None = None  # None: RECONIX_OLLAMA_URL or the local default
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


async def embed_texts(texts: list[str], config: EmbeddingConfig | None = None) -> list[list[float]]:
    """One vector per text, in the same order."""
    config = config or EmbeddingConfig()
    vectors: list[list[float]] = []
    for start in range(0, len(texts), BATCH_SIZE):
        vectors.extend(await embed_batch(texts[start : start + BATCH_SIZE], config))
    return vectors


async def embed_batch(texts: list[str], config: EmbeddingConfig) -> list[list[float]]:
    # Reuse the chat client's URL check and error masking.
    provider = ProviderConfig(
        provider_type=ProviderType.OLLAMA,
        model_name=config.model_name,
        base_url=config.base_url,
    )
    base_url = checked_base_url(provider)
    masked = [mask_secrets(text)[0] for text in texts]
    failure = None
    try:
        response = await litellm.aembedding(
            model=f"ollama/{config.model_name}",
            input=masked,
            api_base=base_url,
            timeout=config.timeout_seconds,
        )
    except openai.OpenAIError as error:
        failure = provider_error(error, provider)
    if failure is not None:
        raise failure  # outside the except block, so the original error is not attached

    vectors = [item["embedding"] for item in response.data]
    if len(vectors) != len(texts):
        raise ProviderError("EMPTY_RESPONSE", "The embedding model skipped some texts.")
    return vectors
