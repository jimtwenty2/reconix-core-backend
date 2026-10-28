"""Which model to call, and where.

The API reads the active row of llm_providers, decrypts the key and passes a
ProviderConfig in. The AI Service never reads the database itself.
"""

import os
from dataclasses import dataclass, field
from enum import StrEnum

# Where Ollama listens. deploy/docker-compose.yml publishes it on this port.
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"
# The built-in model, created from services/ai/models/Modelfile.
RECONIX_MODEL_NAME = "reconix"
DEFAULT_TIMEOUT_SECONDS = 120


class ProviderType(StrEnum):
    """Same values as llm_providers.provider_type in ERD V3."""

    RECONIX = "RECONIX"
    OLLAMA = "OLLAMA"
    OPENAI = "OPENAI"
    ANTHROPIC = "ANTHROPIC"
    DEEPSEEK = "DEEPSEEK"
    OPENAI_API_COMPATIBLE = "OPENAI_API_COMPATIBLE"


@dataclass(frozen=True)
class ProviderConfig:
    provider_type: ProviderType
    model_name: str
    base_url: str | None = None  # empty for the built-in provider
    api_key: str | None = field(default=None, repr=False)  # never printed
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS


def reconix_provider() -> ProviderConfig:
    """The built-in RECONIX model on the local Ollama."""
    return ProviderConfig(
        provider_type=ProviderType.RECONIX,
        model_name=RECONIX_MODEL_NAME,
        base_url=ollama_url(),
    )


def ollama_url() -> str:
    """RECONIX_OLLAMA_URL, or the local default."""
    return os.environ.get("RECONIX_OLLAMA_URL") or DEFAULT_OLLAMA_URL
