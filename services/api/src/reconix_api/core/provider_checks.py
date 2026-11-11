"""Checking an AI provider from the API, through the AI Service's own model call.

try_provider sends one fixed prompt with no Reconix data in it, so nothing about an
assessment leaves this computer, even for a provider that is not approved yet.
local_models asks an Ollama on this computer which models it has, and
compatible_models an OpenAI-compatible server on this computer (LM Studio, vLLM...);
cloud_models a cloud service (OpenAI, Anthropic, DeepSeek) at its own fixed address, with
the key already saved for it. Custom servers off this computer are not asked.
"""

import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from reconix_ai.providers import Message, ProviderConfig, ProviderError, complete
from reconix_ai.providers.base_url import BaseUrlError, call_address, check_base_url
from reconix_ai.providers.settings import ollama_url
from reconix_api.core.errors import ApiError
from reconix_api.core.provider_urls import HOST_GATEWAY_NAME

TEST_PROMPT = "Reply with the single word OK."
LIST_TIMEOUT_SECONDS = 5
MAX_LIST_BYTES = 1024 * 1024  # a model list is a few KB

# A cloud service's model list: its fixed address and how it takes the key. Never a typed
# address, so a saved key only ever goes to the service it was saved for.
CLOUD_MODEL_LISTS = {
    "OPENAI": ("https://api.openai.com/v1", "bearer"),
    "ANTHROPIC": ("https://api.anthropic.com/v1", "anthropic"),
    "DEEPSEEK": ("https://api.deepseek.com", "bearer"),
}
ANTHROPIC_VERSION = "2023-06-01"


@dataclass(frozen=True)
class ProviderTest:
    ok: bool
    latency_ms: int
    code: str | None = None  # e.g. MODEL_UNAVAILABLE, PROVIDER_KEY_MISSING
    message: str | None = None  # masked by the AI Service


async def try_provider(config: ProviderConfig) -> ProviderTest:
    started = time.monotonic()
    try:
        await complete([Message(role="user", content=TEST_PROMPT)], config)
    except ProviderError as error:
        return ProviderTest(False, elapsed_ms(started), error.code, error.message)
    return ProviderTest(True, elapsed_ms(started))


async def local_models(base_url: str | None) -> list[str]:
    """The model names an Ollama on this computer has, e.g. ["reconix:latest"]."""
    url = (base_url or ollama_url()).rstrip("/").removesuffix("/v1")
    body = await _model_list(url, f"{url}/api/tags", "Ollama")
    models = body.get("models", []) if isinstance(body, dict) else []
    return sorted(str(model.get("name")) for model in models if isinstance(model, dict))


async def compatible_models(base_url: str, api_key: str | None) -> list[str]:
    """The model ids an OpenAI-compatible server on this computer lists at /models, e.g.
    LM Studio's ["google/gemma-4-e4b"]. Only a loopback address is asked."""
    url = base_url.rstrip("/")
    if not _is_loopback(url):
        raise ApiError(
            422,
            "MODEL_LIST_NOT_SUPPORTED",
            "Only a server on this computer can list its models.",
        )
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    body = await _model_list(url, f"{url}/models", "The server", headers)
    models = body.get("data", []) if isinstance(body, dict) else []
    return sorted(str(model.get("id")) for model in models if isinstance(model, dict))


async def cloud_models(provider_type: str, api_key: str | None) -> list[str]:
    """The model ids a cloud service lists for the saved key, e.g. OpenAI's ["gpt-4o", ...].
    Only the service's own address is asked."""
    known = CLOUD_MODEL_LISTS.get(provider_type)
    if known is None:
        raise ApiError(422, "MODEL_LIST_NOT_SUPPORTED", "This provider cannot list its models.")
    if not api_key:
        raise ApiError(422, "PROVIDER_KEY_MISSING", "Save the provider's API key first.")
    base_url, style = known
    if style == "anthropic":
        headers = {"x-api-key": api_key, "anthropic-version": ANTHROPIC_VERSION}
    else:
        headers = {"Authorization": f"Bearer {api_key}"}
    body = await _model_list(base_url, f"{base_url}/models", "The provider", headers)
    models = body.get("data", []) if isinstance(body, dict) else []
    return sorted(str(model.get("id")) for model in models if isinstance(model, dict))


async def _model_list(
    base_url: str, list_url: str, who: str, headers: dict[str, str] | None = None
) -> object:
    """GET a model list as JSON: the address checked first, no redirects, at most
    MAX_LIST_BYTES. Any failure is one fixed 503 that never repeats the address."""
    try:
        check_base_url(base_url)
    except BaseUrlError as error:
        raise ApiError(422, "PROVIDER_URL_NOT_ALLOWED", str(error)) from None
    try:
        async with httpx.AsyncClient(timeout=LIST_TIMEOUT_SECONDS) as client:
            async with client.stream(
                "GET", call_address(list_url), headers=headers or {}
            ) as response:
                response.raise_for_status()
                body = b""
                async for part in response.aiter_bytes():
                    body += part
                    if len(body) > MAX_LIST_BYTES:
                        raise ValueError("too large")
        return json.loads(body)
    except (httpx.HTTPError, ValueError, AttributeError):
        raise ApiError(503, "MODEL_UNAVAILABLE", f"{who} did not answer with its models.") from None


def _is_loopback(url: str) -> bool:
    host = urlsplit(url).hostname or ""
    if host in ("localhost", HOST_GATEWAY_NAME):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def ensure_public_host(base_url: str) -> None:
    """A custom address off this computer: every address its name resolves to must be
    public, so /test cannot reach a private network (10.x, 192.168.x, 169.254.x ...)."""
    host = urlsplit(base_url).hostname or ""
    try:
        addresses = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except (socket.gaierror, UnicodeError):
        raise ApiError(
            422, "PROVIDER_URL_NOT_ALLOWED", "The provider's address does not resolve."
        ) from None
    for address in addresses:
        if not ipaddress.ip_address(address.split("%")[0]).is_global:
            raise ApiError(
                422,
                "PROVIDER_URL_NOT_ALLOWED",
                "The provider's address is on a private network, so it cannot be tested.",
            )


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)
