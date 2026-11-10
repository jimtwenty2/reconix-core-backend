"""The only place that calls a model, through LiteLLM.

Every message is masked before it leaves, and the answer is masked before it
comes back, so no secret reaches a model, a log or the database from here.
"""

import json
import os
import sys
from collections.abc import Awaitable, Callable
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
# LiteLLM falls back to these when a call gives no address or key, which would send a
# provider key to an address check_base_url() never saw, or a host's key to a server
# the operator entered. Reconix keys and addresses come only from llm_providers.
PROVIDER_ENV = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_API_BASE",
    "ANTHROPIC_BASE_URL",
    "DEEPSEEK_API_KEY",
    "DEEPSEEK_API_BASE",
]
if "litellm" in sys.modules:
    raise RuntimeError("Import reconix_ai.providers before litellm, so its settings apply.")
os.environ.update(LITELLM_ENV)
for name in PROVIDER_ENV:
    os.environ.pop(name, None)

import litellm  # noqa: E402
import openai  # noqa: E402  (all LiteLLM errors extend openai.OpenAIError)

from reconix_ai.harness import StreamMasker, mask_secrets, mask_value  # noqa: E402
from reconix_ai.providers.base_url import BaseUrlError, check_base_url  # noqa: E402
from reconix_ai.providers.settings import ProviderConfig, ProviderType, ollama_url  # noqa: E402

litellm.suppress_debug_info = True  # no "Give Feedback" banner on every error
litellm.turn_off_message_logging = True

# How LiteLLM names each provider type.
LITELLM_PREFIX = {
    ProviderType.RECONIX: "openai",  # the Reconix team's OpenAI-compatible server
    ProviderType.OLLAMA: "ollama_chat",
    ProviderType.OPENAI: "openai",
    ProviderType.ANTHROPIC: "anthropic",
    ProviderType.DEEPSEEK: "deepseek",
    ProviderType.OPENAI_API_COMPATIBLE: "openai",  # any server that speaks the OpenAI API
}
NO_KEY = "none"  # sent instead of an empty key, so LiteLLM never looks one up itself
# Ollama runs on this computer (or the compose service) and needs no key.
LOCAL_TYPES = {ProviderType.OLLAMA}
# The 3 cloud services: their own address unless one is set, and always a key.
CLOUD_TYPES = {ProviderType.OPENAI, ProviderType.ANTHROPIC, ProviderType.DEEPSEEK}


OnPiece = Callable[[str], Awaitable[None]]
"""Gets the answer in masked pieces while the model writes it, for showing only."""


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
    messages: list[Message],
    config: ProviderConfig,
    json_answer: bool = False,
    on_piece: OnPiece | None = None,
) -> Completion:
    """Send masked messages to the configured model and return its masked answer.

    json_answer asks the model for one JSON object. The caller still parses it.
    With on_piece the answer is streamed: on_piece gets what StreamMasker lets through,
    and the whole answer is still masked once here and returned as usual.
    """
    model = litellm_model(config)
    base_url = checked_base_url(config)
    check_key(config)
    masked_messages, masked_count = mask_messages(messages)
    request = {
        "model": model,
        "messages": masked_messages,
        "api_base": base_url,
        "api_key": config.api_key or NO_KEY,
        "timeout": config.timeout_seconds,
        "max_tokens": config.max_tokens,
        "response_format": {"type": "json_object"} if json_answer else None,
    }

    def fail(code: str, message: str) -> ProviderError:
        return ProviderError(code, message)

    failure = None
    try:
        if on_piece is None:
            response = await litellm.acompletion(**request)
        else:
            response = await streamed(request, on_piece)
    except openai.OpenAIError as error:
        failure = provider_error(error, config)
    if failure is not None:
        # Raised outside the except block, so the original error (which may
        # carry the request and its key) is not attached to it at all.
        raise fail(failure.code, failure.message)

    if response is None or not response.choices:
        raise fail("EMPTY_RESPONSE", "The model sent back an empty answer.")
    choice = response.choices[0]
    raw = choice.message.content or ""
    text, answer_count = mask_json(raw) if json_answer else mask_secrets(raw)
    if not text.strip():
        if choice.finish_reason == "length":
            # A reasoning model can spend the whole length on thinking.
            raise fail(
                "ANSWER_CUT_OFF",
                f"The model reached its {config.max_tokens}-token limit before it answered.",
            )
        raise fail("EMPTY_RESPONSE", "The model sent back an empty answer.")
    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
    completion_tokens = getattr(usage, "completion_tokens", 0) or 0
    return Completion(
        text=text,
        provider_type=config.provider_type,
        model_name=config.model_name,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        masked_count=masked_count + answer_count,
    )


def mask_json(text: str) -> tuple[str, int]:
    """A JSON answer masked value by value (and whole under a secret key name), then
    written out again. Masking the whole text can eat a closing quote (password = ?"
    inside a value) and break the JSON. An answer that is not JSON is masked as text.
    A model may wrap the object in ```json fences or a sentence, so the outer braces
    are taken first (as json_object does) before parsing."""
    start, end = text.find("{"), text.rfind("}")
    snippet = text[start : end + 1] if 0 <= start < end else text
    try:
        data = json.loads(snippet)
    except json.JSONDecodeError:
        return mask_secrets(text)
    data, count = mask_value(data)
    return json.dumps(data, ensure_ascii=False), count


async def streamed(request: dict, on_piece: OnPiece) -> litellm.ModelResponse | None:
    """The answer as it arrives, built back into one response (None when nothing came)."""
    masker = StreamMasker()
    chunks = []
    async for chunk in await litellm.acompletion(**request, stream=True):
        chunks.append(chunk)
        piece = chunk.choices[0].delta.content if chunk.choices else None
        if piece and (shown := masker.feed(piece)):
            await on_piece(shown)
    return litellm.stream_chunk_builder(chunks, messages=request["messages"])


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


def checked_base_url(config: ProviderConfig) -> str | None:
    """The address to call, checked. None means the cloud service's own address, which
    LiteLLM knows; a custom OpenAI-compatible server must give one."""
    base_url = config.base_url
    if not base_url and config.provider_type in LOCAL_TYPES:
        base_url = ollama_url()
    if not base_url:
        if config.provider_type == ProviderType.RECONIX:
            raise ProviderError(
                "PROVIDER_URL_MISSING", "Set RECONIX_MODEL_URL to use the built-in RECONIX model."
            )
        if config.provider_type == ProviderType.OPENAI_API_COMPATIBLE:
            raise ProviderError(
                "PROVIDER_URL_MISSING", "An OpenAI-compatible provider needs its address."
            )
        return None
    try:
        check_base_url(base_url)
    except BaseUrlError as error:
        raise ProviderError("PROVIDER_URL_NOT_ALLOWED", str(error)) from None
    return base_url


def check_key(config: ProviderConfig) -> None:
    if config.provider_type in CLOUD_TYPES and not config.api_key:
        raise ProviderError(
            "PROVIDER_KEY_MISSING", f"The {config.provider_type} provider needs an API key."
        )


def provider_error(error: Exception, config: ProviderConfig) -> ProviderError:
    """A clear error for the API to show. The provider's own text never goes out: it can
    carry the endpoint URL, the request or an echoed key, so only fixed words are used."""
    model = f"{config.provider_type} model {config.model_name}"
    if isinstance(error, litellm.exceptions.NotFoundError):
        return ProviderError("MODEL_NOT_FOUND", f"The {model} was not found. Pull or create it.")
    if isinstance(error, litellm.exceptions.AuthenticationError):
        return ProviderError("PROVIDER_AUTH_FAILED", f"The {model} refused the API key.")
    return ProviderError("MODEL_UNAVAILABLE", f"The {model} could not answer. Is it running?")
