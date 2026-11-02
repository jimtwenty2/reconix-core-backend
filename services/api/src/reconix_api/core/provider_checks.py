"""Checking an AI provider from the API, through the AI Service's own model call.

try_provider sends one fixed prompt with no Reconix data in it, so nothing about an
assessment leaves this computer, even for a provider that is not approved yet.
local_models asks an Ollama on this computer which models it has; cloud providers
are not asked (that would be a new kind of outside call).
"""

import ipaddress
import json
import socket
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

from reconix_ai.providers import Message, ProviderConfig, ProviderError, complete
from reconix_ai.providers.base_url import BaseUrlError, check_base_url
from reconix_ai.providers.settings import ollama_url
from reconix_api.core.errors import ApiError

TEST_PROMPT = "Reply with the single word OK."
LIST_TIMEOUT_SECONDS = 5
MAX_LIST_BYTES = 1024 * 1024  # an Ollama model list is a few KB


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
    try:
        check_base_url(url)
    except BaseUrlError as error:
        raise ApiError(422, "PROVIDER_URL_NOT_ALLOWED", str(error)) from None
    try:
        async with httpx.AsyncClient(timeout=LIST_TIMEOUT_SECONDS) as client:
            async with client.stream("GET", f"{url}/api/tags") as response:
                response.raise_for_status()
                body = b""
                async for part in response.aiter_bytes():
                    body += part
                    if len(body) > MAX_LIST_BYTES:
                        raise ValueError("too large")
        models = json.loads(body).get("models", [])
    except (httpx.HTTPError, ValueError, AttributeError):
        raise ApiError(503, "MODEL_UNAVAILABLE", "Ollama did not answer with its models.") from None
    return sorted(str(model.get("name")) for model in models if isinstance(model, dict))


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
