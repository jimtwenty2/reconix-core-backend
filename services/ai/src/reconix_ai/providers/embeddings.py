"""Text to vectors for the knowledge search, with BGE-small (bge-small-en-v1.5).

The model runs on CPU in the `embeddings` container (Hugging Face text-embeddings-inference,
deploy/docker-compose.yml), which answers OpenAI-style at /v1/embeddings. No Ollama needed.
It is a small 384-dim English model that stays under ~1 GB of memory. Same rules as
client.py: texts are masked before they leave, and errors come back as a masked ProviderError.
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

EMBEDDING_MODEL_NAME = "bge-small-en-v1.5"
EMBEDDING_SIZE = 384  # BAAI/bge-small-en-v1.5 dense vectors
BATCH_SIZE = 32
# bge-small reads at most 512 tokens, and dense text (ids, code, links) reaches that
# well under 1200 characters. Only the vector input is cut: the full text stays in the
# Qdrant payload and in the keyword vector. A token-limit refusal halves the cut and
# retries, so even the densest piece gets a vector instead of failing the ingest.
EMBED_CHAR_LIMIT = 2000
MAX_EMBED_RETRIES = 4
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
    limit = EMBED_CHAR_LIMIT
    for attempt in range(MAX_EMBED_RETRIES + 1):
        try:
            response = await litellm.aembedding(
                model=f"openai/{config.model_name}",  # the server only serves one model
                input=[text[:limit] for text in masked],
                api_base=base_url,
                api_key=NO_KEY,
                timeout=config.timeout_seconds,
            )
            break
        except openai.OpenAIError as error:
            if attempt < MAX_EMBED_RETRIES and over_token_limit(error):
                limit //= 2
                continue
            failure = provider_error(error, provider)
            break
    if failure is not None:
        raise failure  # outside the except block, so the original error is not attached

    vectors = [item["embedding"] for item in response.data]
    if len(vectors) != len(texts):
        raise ProviderError("EMPTY_RESPONSE", "The embedding model skipped some texts.")
    return vectors


def over_token_limit(error: Exception) -> bool:
    """The server refused an input longer than its token window
    (text-embeddings-inference answers 413). Its text is only read here, never shown."""
    status = getattr(error, "status_code", None)
    return status in (400, 413) and "token" in str(error).lower()
