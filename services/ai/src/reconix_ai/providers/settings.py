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
# A reasoning model writes ~80-90 tokens a second, so a long think needs minutes.
DEFAULT_TIMEOUT_SECONDS = 300
# The longest answer one call may write. A reasoning model (e.g. Qwen3) counts its
# thinking in it too: a plan took 1,600 to 5,000 tokens with a Qwen3.6 model and once
# ran past 8,000, so a lower limit cut it off before it wrote the answer. A plan's JSON
# alone fits well under it.
DEFAULT_MAX_TOKENS = 16_000


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
    max_tokens: int = DEFAULT_MAX_TOKENS


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
