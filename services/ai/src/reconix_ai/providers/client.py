"""The only place that calls a model, through LiteLLM.

Every message is masked before it leaves, and the answer is masked before it
comes back, so no secret reaches a model, a log or the database from here.
"""

import os
import sys
from dataclasses import dataclass

# LiteLLM reads these once, when it is imported, so they are forced here and
# litellm must not be imported anywhere before this module.
LITELLM_ENV = {
    # In its default DEV mode LiteLLM loads the nearest .env into os.environ,
    # which would hand the API's master secrets to this process.
    "LITELLM_MODE": "PRODUCTION",
    # Use the bundled price list and headers: Reconix must not call out on its own.
    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
    "LITELLM_LOCAL_ANTHROPIC_BETA_HEADERS": "True",
    # Debug logs would print the model's raw answer before it is masked.
    "LITELLM_LOG": "ERROR",
}
if "litellm" in sys.modules:
    raise RuntimeError("Import reconix_ai.providers before litellm, so its settings apply.")
os.environ.update(LITELLM_ENV)

import litellm  # noqa: E402
import openai  # noqa: E402  (all LiteLLM errors extend openai.OpenAIError)

from reconix_ai.harness import mask_secrets  # noqa: E402
from reconix_ai.providers.base_url import BaseUrlError, check_base_url  # noqa: E402
from reconix_ai.providers.settings import ProviderConfig, ProviderType, ollama_url  # noqa: E402

litellm.suppress_debug_info = True  # no "Give Feedback" banner on every error
litellm.turn_off_message_logging = True

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


async def complete(
    messages: list[Message], config: ProviderConfig, json_answer: bool = False
) -> Completion:
    """Send masked messages to the configured model and return its masked answer.

    json_answer asks the model for one JSON object. The caller still parses it.
    """
    model = litellm_model(config)
    base_url = checked_base_url(config)
    masked_messages, masked_count = mask_messages(messages)
    failure = None
    try:
        response = await litellm.acompletion(
            model=model,
            messages=masked_messages,
            api_base=base_url,
            api_key=config.api_key,
            timeout=config.timeout_seconds,
            max_tokens=config.max_tokens,
            response_format={"type": "json_object"} if json_answer else None,
        )
    except openai.OpenAIError as error:
        failure = provider_error(error, config)
    if failure is not None:
        # Raised outside the except block, so the original error (which may
        # carry the request and its key) is not attached to it at all.
        raise failure

    if not response.choices:
        raise ProviderError("EMPTY_RESPONSE", "The model sent back an empty answer.")
    text, answer_count = mask_secrets(response.choices[0].message.content or "")
    if not text.strip():
        raise ProviderError("EMPTY_RESPONSE", "The model sent back an empty answer.")
    usage = getattr(response, "usage", None)
    return Completion(
        text=text,
        provider_type=config.provider_type,
        model_name=config.model_name,
        prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
        completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
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


def checked_base_url(config: ProviderConfig) -> str:
    base_url = config.base_url or ollama_url()
    try:
        check_base_url(base_url)
    except BaseUrlError as error:
        raise ProviderError("PROVIDER_URL_NOT_ALLOWED", str(error)) from None
    return base_url


def provider_error(error: Exception, config: ProviderConfig) -> ProviderError:
    """A clear error for the API to show. The provider's own text never goes out: it can
    carry the endpoint URL, the request or an echoed key, so only fixed words are used."""
    model = f"{config.provider_type} model {config.model_name}"
    if isinstance(error, litellm.exceptions.NotFoundError):
        return ProviderError("MODEL_NOT_FOUND", f"The {model} was not found. Pull or create it.")
    if isinstance(error, litellm.exceptions.AuthenticationError):
        return ProviderError("PROVIDER_AUTH_FAILED", f"The {model} refused the API key.")
    return ProviderError("MODEL_UNAVAILABLE", f"The {model} could not answer. Is it running?")
