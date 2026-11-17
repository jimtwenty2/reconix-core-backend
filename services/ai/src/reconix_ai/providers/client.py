"""The only place that calls a model, through LiteLLM.

Every message is masked before it leaves, and the answer is masked before it
comes back, so no secret reaches a model, a log or the database from here.
"""

import json
import os
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

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
from reconix_ai.providers.base_url import BaseUrlError, call_address, check_base_url  # noqa: E402
from reconix_ai.providers.overflow import is_overflow, learned_window  # noqa: E402
from reconix_ai.providers.settings import ProviderConfig, ProviderType, ollama_url  # noqa: E402
from reconix_ai.providers.window import context_window, remember_window  # noqa: E402

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
# Servers that may refuse response_format json_object (LM Studio takes only json_schema or
# text): asked again without it once, since the caller parses the JSON itself.
JSON_FORMAT_OPTIONAL = {ProviderType.OPENAI_API_COMPATIBLE, ProviderType.RECONIX}
# Fitting a call into the model's window. The prompt is estimated at 3 characters a token
# (code and JSON run denser than prose's 4, and too high is the safe side).
CHARS_PER_TOKEN = 3
# Dense text (ids, hex, base64, scan output) measured about 1.8 characters a token.
DENSE_CHARS_PER_TOKEN = 1.7
DENSE_SHARE = 0.1  # symbols and digits above this share of a text make it dense
MIN_SPACE_SHARE = 0.05  # base64 and long ids have almost no spaces
WINDOW_MARGIN_TOKENS = 1_000  # the estimate's error and the chat template's own tokens
MIN_ANSWER_TOKENS = 1_024
CUT_TOKEN_SLACK = 8  # Ollama's cut prompt counts window // 2 + 2; allow a few more
# A tool loop whose prompt is above window - ANSWER_RESERVE_TOKENS has its older tool
# results cut to their first TOOL_RESULT_HEAD_CHARS and last TOOL_RESULT_TAIL_CHARS (as Pi
# keeps 16,384 for the answer). After a "prompt too long" error every result is cut.
ANSWER_RESERVE_TOKENS = 16_384
TOOL_RESULT_HEAD_CHARS = 300
TOOL_RESULT_TAIL_CHARS = 100
CUT_MARKER = "\n[tool result cut to fit the model's context window]\n"


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
    info = cloud_info(model, config)
    window = await context_window(config, model, base_url, info)
    estimate = estimated_tokens(masked_messages)
    check_ollama_fit(config, window, estimate)
    request = {
        "model": model,
        "messages": masked_messages,
        "api_base": base_url,
        "api_key": config.api_key or NO_KEY,
        "timeout": config.timeout_seconds,
        "max_tokens": answer_limit(config, info, window, estimated_tokens(masked_messages)),
        "response_format": {"type": "json_object"} if json_answer else None,
        **ollama_options(config, window),
    }

    def fail(code: str, message: str) -> ProviderError:
        return ProviderError(code, message)

    async def attempt(request: dict) -> litellm.ModelResponse | None:
        try:
            return await send(request, on_piece)
        except openai.BadRequestError as error:
            # Some OpenAI-compatible servers (LM Studio) refuse response_format
            # json_object. The caller parses the JSON itself, so ask once without it.
            # A prompt that is too long is not that: it goes to the window retry below.
            if is_overflow(error) or not (
                json_answer and config.provider_type in JSON_FORMAT_OPTIONAL
            ):
                raise
            return await send({**request, "response_format": None}, on_piece)

    failure = None
    try:
        try:
            response = await attempt(request)
        except openai.BadRequestError as error:
            # Nothing here can be cut, so retry only when the server names its window.
            learned = learned_window(error) if is_overflow(error) else None
            # An overflow can only mean the window is smaller than the one used.
            if learned is None or learned >= window:
                raise
            remember_window(config, base_url, learned)
            request = {
                **request,
                "max_tokens": answer_limit(
                    config, info, learned, estimated_tokens(masked_messages)
                ),
                **ollama_options(config, learned),
            }
            response = await attempt(request)
    except openai.OpenAIError as error:
        failure = provider_error(error, config)
    if failure is not None:
        # Raised outside the except block, so the original error (which may
        # carry the request and its key) is not attached to it at all.
        raise fail(failure.code, failure.message)

    if response is None or not response.choices:
        raise fail("EMPTY_RESPONSE", "The model sent back an empty answer.")
    choice = response.choices[0]
    raw = answer_text(choice.message, json_answer)
    text, answer_count = mask_json(raw) if json_answer else mask_secrets(raw)
    if not text.strip():
        if choice.finish_reason == "length":
            # A reasoning model can spend the whole length on thinking.
            raise fail(
                "ANSWER_CUT_OFF",
                f"The model reached its {request['max_tokens']}-token limit before it answered.",
            )
        raise fail("EMPTY_RESPONSE", "The model sent back an empty answer.")
    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
    completion_tokens = getattr(usage, "completion_tokens", 0) or 0
    check_ollama_cut(config, window, estimate, prompt_tokens)
    return Completion(
        text=text,
        provider_type=config.provider_type,
        model_name=config.model_name,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        masked_count=masked_count + answer_count,
    )


@dataclass(frozen=True)
class ToolCall:
    call_id: str
    name: str
    arguments: str  # the model's JSON text, masked value by value


@dataclass(frozen=True)
class ToolReply:
    text: str  # already masked; may be empty when the model only called tools
    tool_calls: list[ToolCall]
    prompt_tokens: int
    completion_tokens: int
    masked_count: int


async def complete_with_tools(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    config: ProviderConfig,
    on_piece: OnPiece | None = None,
    on_thinking: OnPiece | None = None,
) -> ToolReply:
    """One step of a tool-using agent: masked messages and OpenAI-style tool definitions
    in, the masked answer and the tools it wants to call out.

    messages are OpenAI chat messages: role "system", "user", "assistant" (with
    "tool_calls") or "tool" (with "tool_call_id"). Every content and every tool call's
    arguments are masked before they leave, and the answer's text and arguments are
    masked before they come back. With on_piece / on_thinking the answer and the model's
    reasoning are streamed in masked pieces, for showing only. Errors are the same
    ProviderError codes as complete(). When the prompt grows past the model's window less
    ANSWER_RESERVE_TOKENS, older tool results are cut in what is sent (not in messages)."""
    model = litellm_model(config)
    base_url = checked_base_url(config)
    check_key(config)
    masked_messages, masked_count = mask_chat(messages)
    info = cloud_info(model, config)
    window = await context_window(config, model, base_url, info)

    def build_request(window: int, force: bool) -> dict:
        fitted = fitted_tool_results(masked_messages, tools, window, force)
        return {
            "model": model,
            "messages": fitted,
            "tools": tools,
            "api_base": base_url,
            "api_key": config.api_key or NO_KEY,
            "timeout": config.timeout_seconds,
            "max_tokens": answer_limit(config, info, window, estimated_tokens(fitted, tools)),
            **ollama_options(config, window),
        }

    async def attempt(request: dict) -> litellm.ModelResponse | None:
        if on_piece is None and on_thinking is None:
            return await litellm.acompletion(**request)
        return await streamed(request, on_piece, on_thinking)

    request = build_request(window, force=False)
    if config.provider_type == ProviderType.OLLAMA:
        if estimated_tokens(request["messages"], tools) > prompt_room(window):
            request = build_request(window, force=True)
        check_ollama_fit(config, window, estimated_tokens(request["messages"], tools))
    failure = None
    try:
        try:
            response = await attempt(request)
        except openai.BadRequestError as error:
            if not is_overflow(error):
                raise
            # One more try with every tool result cut, and the window the server named.
            learned = learned_window(error)
            if learned is not None and learned < window:
                remember_window(config, base_url, learned)
                window = learned
            retry = build_request(window, force=True)
            if retry == request:
                raise  # nothing left to cut: an identical request would fail the same way
            request = retry
            response = await attempt(request)
    except openai.OpenAIError as error:
        failure = provider_error(error, config)
    if failure is not None:
        raise failure  # outside the except block: the original error is not attached

    if response is None or not response.choices:
        raise ProviderError("EMPTY_RESPONSE", "The model sent back an empty answer.")
    choice = response.choices[0]
    text, answer_count = mask_secrets(choice.message.content or "")
    calls = []
    for call in getattr(choice.message, "tool_calls", None) or []:
        arguments, count = mask_json(call.function.arguments or "{}")
        answer_count += count
        calls.append(ToolCall(call.id or "", call.function.name or "", arguments))
    if not text.strip() and not calls:
        if choice.finish_reason == "length":
            raise ProviderError(
                "ANSWER_CUT_OFF",
                f"The model reached its {request['max_tokens']}-token limit before it answered.",
            )
        raise ProviderError("EMPTY_RESPONSE", "The model sent back an empty answer.")
    usage = getattr(response, "usage", None)
    prompt_tokens = getattr(usage, "prompt_tokens", 0) or 0
    check_ollama_cut(config, window, estimated_tokens(masked_messages, tools), prompt_tokens)
    return ToolReply(
        text=text,
        tool_calls=calls,
        prompt_tokens=prompt_tokens,
        completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        masked_count=masked_count + answer_count,
    )


def mask_chat(messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Chat messages with tool calls, masked: every content and every call's arguments."""
    masked, total = [], 0
    for message in messages:
        out = dict(message)
        content, count = mask_secrets(str(message.get("content") or ""))
        out["content"] = content
        total += count
        if message.get("tool_calls"):
            out["tool_calls"] = []
            for call in message["tool_calls"]:
                function = call["function"]
                arguments, count = mask_json(function.get("arguments") or "{}")
                total += count
                out["tool_calls"].append(
                    {**call, "function": {"name": function["name"], "arguments": arguments}}
                )
        masked.append(out)
    return masked, total


def answer_text(message: object, json_answer: bool) -> str:
    """The answer, from content; when that is empty, from where a reasoning model left it.

    Under JSON mode LiteLLM may leave the object in the first tool call's arguments
    (Anthropic's emulated json_object), and a thinking model may leave its only text in
    reasoning_content. For a JSON answer the tool call goes first: it is the structured
    answer, while reasoning_content is thinking that may hold a draft object.
    """
    content = getattr(message, "content", None)
    if isinstance(content, str) and content.strip():
        return content
    reasoning = getattr(message, "reasoning_content", None)
    reasoning = reasoning if isinstance(reasoning, str) and reasoning.strip() else ""
    arguments = tool_call_arguments(message)
    for text in (arguments, reasoning) if json_answer else (reasoning, arguments):
        if text:
            return text
    return ""


def tool_call_arguments(message: object) -> str:
    """The first tool call's arguments as text, or "" when there are none."""
    calls = getattr(message, "tool_calls", None) or []
    function = getattr(calls[0], "function", None) if calls else None
    arguments = getattr(function, "arguments", None)
    if isinstance(arguments, dict):
        return json.dumps(arguments, ensure_ascii=False)
    return arguments if isinstance(arguments, str) and arguments.strip() else ""


def cloud_info(model: str, config: ProviderConfig) -> dict[str, Any]:
    """LiteLLM's bundled entry for a cloud model, {} when unknown. Only cloud types are
    looked up: for Ollama LiteLLM would ask the server."""
    if config.provider_type not in CLOUD_TYPES:
        return {}
    try:
        return dict(litellm.get_model_info(model))
    except Exception:  # not mapped: LiteLLM raises its own error for an unknown model
        return {}


def answer_limit(config: ProviderConfig, info: dict[str, Any], window: int, prompt: int) -> int:
    """max_tokens: as set, lowered to a cloud model's own output limit (gpt-4o: 16,384),
    then to what the window leaves after the prompt, so a 64k model is never asked for
    a 128k answer. The window never takes it below MIN_ANSWER_TOKENS: a prompt that big
    fails at the server either way."""
    max_tokens = config.max_tokens
    known = info.get("max_output_tokens")
    if isinstance(known, int) and known > 0:
        max_tokens = min(max_tokens, known)
    room = window - prompt - WINDOW_MARGIN_TOKENS
    return min(max_tokens, max(MIN_ANSWER_TOKENS, room))


def ollama_options(config: ProviderConfig, window: int) -> dict[str, int]:
    """Ollama's num_ctx: without it Ollama runs its own small default and quietly drops
    the start of a longer prompt."""
    return {"num_ctx": window} if config.provider_type == ProviderType.OLLAMA else {}


def text_tokens(text: str) -> float:
    """One text's tokens: prose at CHARS_PER_TOKEN, dense text (many digits and symbols, or
    hardly any spaces) at DENSE_CHARS_PER_TOKEN, since it tokenizes into far more pieces."""
    if not text:
        return 0
    spaces = text.count(" ")
    other = sum(1 for char in text if not char.isalpha() and char != " ")
    dense = other > DENSE_SHARE * len(text) or spaces < MIN_SPACE_SHARE * len(text)
    return len(text) / (DENSE_CHARS_PER_TOKEN if dense else CHARS_PER_TOKEN)


def estimated_tokens(
    messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None
) -> int:
    """A prompt's tokens, estimated high enough to fit a call into the window."""
    total = text_tokens(json.dumps(tools)) if tools else 0
    for message in messages:
        total += text_tokens(str(message.get("content") or ""))
        if message.get("tool_calls"):
            total += text_tokens(json.dumps(message["tool_calls"]))
    return int(total)


def prompt_room(window: int) -> int:
    """The prompt tokens Ollama can take whole: the window less the margin and the answer."""
    return window - WINDOW_MARGIN_TOKENS - MIN_ANSWER_TOKENS


def check_ollama_fit(config: ProviderConfig, window: int, estimate: int) -> None:
    """Ollama cuts a too-long prompt silently (no error to retry on), so refuse it here."""
    if config.provider_type == ProviderType.OLLAMA and estimate > prompt_room(window):
        raise ProviderError("PROMPT_TOO_LONG", "The prompt is longer than the model's window.")


def check_ollama_cut(config: ProviderConfig, window: int, estimate: int, used: int) -> None:
    """Ollama keeps window // 2 + 2 tokens of a too-long prompt and answers anyway: a count
    that low while we sent far more means the middle was dropped, so the answer is wrong."""
    cut_size = window // 2 + CUT_TOKEN_SLACK
    if config.provider_type == ProviderType.OLLAMA and estimate > window and used <= cut_size:
        raise ProviderError("PROMPT_TOO_LONG", "The prompt is longer than the model's window.")


def fitted_tool_results(
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    window: int,
    force: bool = False,
) -> list[dict[str, Any]]:
    """messages with every tool result but the newest cut down to its head and tail, when
    the prompt is above window - ANSWER_RESERVE_TOKENS; else messages as they are. With
    force (after a "prompt too long" error) the newest is cut too, whatever the estimate.
    The system and user messages and the model's own turns are kept whole. A result that
    is already cut is left alone."""
    limit = max(window - ANSWER_RESERVE_TOKENS, window // 2)
    if not force and estimated_tokens(messages, tools) <= limit:
        return messages
    tool_turns = [n for n, message in enumerate(messages) if message.get("role") == "tool"]
    cut = set(tool_turns if force else tool_turns[:-1])
    fitted = []
    for n, message in enumerate(messages):
        content = str(message.get("content") or "")
        if n in cut and len(content) > TOOL_RESULT_HEAD_CHARS + TOOL_RESULT_TAIL_CHARS:
            if CUT_MARKER not in content:
                tail = content[-TOOL_RESULT_TAIL_CHARS:]
                head = content[:TOOL_RESULT_HEAD_CHARS]
                message = {**message, "content": head + CUT_MARKER + tail}
        fitted.append(message)
    return fitted


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


async def send(request: dict, on_piece: OnPiece | None) -> litellm.ModelResponse | None:
    """One call: the whole answer, or streamed to on_piece."""
    if on_piece is None:
        return await litellm.acompletion(**request)
    return await streamed(request, on_piece)


async def streamed(
    request: dict, on_piece: OnPiece | None, on_thinking: OnPiece | None = None
) -> litellm.ModelResponse | None:
    """The answer as it arrives, built back into one response (None when nothing came).
    on_thinking gets the model's reasoning, when it sends any, masked the same way."""
    masker, thinking_masker = StreamMasker(), StreamMasker()
    chunks = []
    async for chunk in await litellm.acompletion(**request, stream=True):
        chunks.append(chunk)
        delta = chunk.choices[0].delta if chunk.choices else None
        piece = delta.content if delta else None
        if on_piece and piece and (shown := masker.feed(piece)):
            await on_piece(shown)
        thought = getattr(delta, "reasoning_content", None) if delta else None
        if on_thinking and thought and (shown := thinking_masker.feed(thought)):
            await on_thinking(shown)
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
    return call_address(base_url)


def check_key(config: ProviderConfig) -> None:
    if config.provider_type in CLOUD_TYPES and not config.api_key:
        raise ProviderError(
            "PROVIDER_KEY_MISSING", f"The {config.provider_type} provider needs an API key."
        )


def provider_error(error: Exception, config: ProviderConfig) -> ProviderError:
    """A clear error for the API to show. The provider's own text never goes out: it can
    carry the endpoint URL, the request or an echoed key, so only fixed words are used."""
    model = f"{config.provider_type} model {config.model_name}"
    if is_overflow(error):
        return ProviderError(
            "PROMPT_TOO_LONG", f"The prompt is too long for the {model}'s context window."
        )
    if isinstance(error, litellm.exceptions.NotFoundError):
        return ProviderError("MODEL_NOT_FOUND", f"The {model} was not found. Pull or create it.")
    if isinstance(error, litellm.exceptions.AuthenticationError):
        return ProviderError("PROVIDER_AUTH_FAILED", f"The {model} refused the API key.")
    return ProviderError("MODEL_UNAVAILABLE", f"The {model} could not answer. Is it running?")
