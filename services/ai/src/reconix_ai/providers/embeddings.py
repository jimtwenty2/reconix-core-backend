"""Text to vectors for the knowledge search, with BGE-M3.

BGE-M3 runs on CPU in the `embeddings` container (Hugging Face text-embeddings-inference,
deploy/docker-compose.yml), which answers OpenAI-style at /v1/embeddings. No Ollama needed.
Same rules as client.py: texts are masked before they leave, and errors come back as a
masked ProviderError.
"""

import os
from dataclasses import dataclass

from reconix_ai.harness import mask_secrets
from reconix_ai.providers.base_url import BaseUrlError, check_base_url
from reconix_ai.providers.client import (
    NO_KEY,
    ProviderError,
    litellm,
    openai,
    provider_error,
)
from reconix_ai.providers.settings import DEFAULT_TIMEOUT_SECONDS, ProviderConfig, ProviderType

EMBEDDING_MODEL_NAME = "bge-m3"
EMBEDDING_SIZE = 1024  # BGE-M3 dense vectors
BATCH_SIZE = 32
# The embedding server when RECONIX_EMBEDDINGS_URL is not set: one on this computer.
DEFAULT_EMBEDDINGS_URL = "http://127.0.0.1:8081/v1"


@dataclass(frozen=True)
class EmbeddingConfig:
    model_name: str = EMBEDDING_MODEL_NAME
    base_url: str | None = None  # None: RECONIX_EMBEDDINGS_URL or the local default
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


async def embed_texts(texts: list[str], config: EmbeddingConfig | None = None) -> list[list[float]]:
    """One vector per text, in the same order."""
    config = config or EmbeddingConfig()
    vectors: list[list[float]] = []
    for start in range(0, len(texts), BATCH_SIZE):
        vectors.extend(await embed_batch(texts[start : start + BATCH_SIZE], config))
    return vectors


def embeddings_url() -> str:
    """RECONIX_EMBEDDINGS_URL, or the local default."""
    return os.environ.get("RECONIX_EMBEDDINGS_URL") or DEFAULT_EMBEDDINGS_URL


async def embed_batch(texts: list[str], config: EmbeddingConfig) -> list[list[float]]:
    base_url = config.base_url or embeddings_url()
    try:
        check_base_url(base_url)  # the same address rules as a model call
    except BaseUrlError as error:
        raise ProviderError("PROVIDER_URL_NOT_ALLOWED", str(error)) from None
    # Only for the error message, which reuses the chat client's masking.
    provider = ProviderConfig(ProviderType.OPENAI_API_COMPATIBLE, config.model_name, base_url)
    masked = [mask_secrets(text)[0] for text in texts]
    failure = None
    try:
        response = await litellm.aembedding(
            model=f"openai/{config.model_name}",  # the server only serves BGE-M3
            input=masked,
            api_base=base_url,
            api_key=NO_KEY,
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
