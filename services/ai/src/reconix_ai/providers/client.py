"""The only place that calls a model, through LiteLLM.

Every message is masked before it leaves, and the answer is masked before it
comes back, so no secret reaches a model, a log or the database from here.
"""

import os
from dataclasses import dataclass

# Use LiteLLM's bundled price list instead of downloading it at import time.
# Reconix runs on the tester's computer and must not call out on its own.
os.environ.setdefault("LITELLM_LOCAL_MODEL_COST_MAP", "True")

import litellm  # noqa: E402
import openai  # noqa: E402  (installed with LiteLLM; all LiteLLM errors extend openai.OpenAIError)

from reconix_ai.harness import mask_secrets  # noqa: E402
from reconix_ai.providers.settings import ProviderConfig, ProviderType, ollama_url  # noqa: E402

litellm.suppress_debug_info = True  # no "Give Feedback" banner on every error

# How LiteLLM names each provider type. The other 4 types come with task 5.
LITELLM_PREFIX = {
    ProviderType.RECONIX: "ollama_chat",
    ProviderType.OLLAMA: "ollama_chat",
}


@dataclass(frozen=True)
class Message:
    role: str  # "system", "user" or "assistant"
    content: str


@dataclass(frozen=True)
class Completion:
    text: str  # already masked
    provider_type: ProviderType
    model_name: str
    prompt_tokens: int
    completion_tokens: int
    masked_count: int  # secrets hidden in the messages and the answer


class ProviderError(Exception):
    """A model call failed. code is UPPERCASE, e.g. MODEL_UNAVAILABLE."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


async def complete(messages: list[Message], config: ProviderConfig) -> Completion:
    """Send masked messages to the configured model and return its masked answer."""
    masked_messages, masked_count = mask_messages(messages)
    try:
        response = await litellm.acompletion(
            model=litellm_model(config),
            messages=masked_messages,
            api_base=config.base_url or default_base_url(config),
            api_key=config.api_key,
            timeout=config.timeout_seconds,
        )
    except openai.OpenAIError as error:
        # from None: the original error may carry the request, with its key.
        raise provider_error(error) from None

    text, answer_count = mask_secrets(response.choices[0].message.content or "")
    if not text.strip():
        raise ProviderError("EMPTY_RESPONSE", "The model sent back an empty answer.")
    return Completion(
        text=text,
        provider_type=config.provider_type,
        model_name=config.model_name,
        prompt_tokens=response.usage.prompt_tokens,
        completion_tokens=response.usage.completion_tokens,
        masked_count=masked_count + answer_count,
    )


def mask_messages(messages: list[Message]) -> tuple[list[dict[str, str]], int]:
    masked, total = [], 0
    for message in messages:
        content, count = mask_secrets(message.content)
        masked.append({"role": message.role, "content": content})
        total += count
    return masked, total


def litellm_model(config: ProviderConfig) -> str:
    prefix = LITELLM_PREFIX.get(config.provider_type)
    if prefix is None:
        raise ProviderError(
            "PROVIDER_NOT_SUPPORTED",
            f"Provider type {config.provider_type} is not supported yet.",
        )
    return f"{prefix}/{config.model_name}"


def default_base_url(config: ProviderConfig) -> str | None:
    if config.provider_type in (ProviderType.RECONIX, ProviderType.OLLAMA):
        return ollama_url()
    return None


def provider_error(error: Exception) -> ProviderError:
    """A clear, masked error for the API to show."""
    reason, _ = mask_secrets(str(error))
    if isinstance(error, litellm.exceptions.NotFoundError):
        return ProviderError("MODEL_NOT_FOUND", f"The model was not found: {reason}")
    if isinstance(error, litellm.exceptions.AuthenticationError):
        return ProviderError("PROVIDER_AUTH_FAILED", f"The provider refused the key: {reason}")
    return ProviderError("MODEL_UNAVAILABLE", f"The model could not answer: {reason}")
