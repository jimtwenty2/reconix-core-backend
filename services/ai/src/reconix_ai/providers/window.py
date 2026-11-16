"""How many tokens a model can hold, prompt and answer together (its context window).

RECONIX is our own model: RECONIX_CONTEXT_WINDOW, else 64,000. Anthropic, Ollama and an
OpenAI-compatible server are asked once (cached while the API runs). OpenAI and DeepSeek
do not list windows, so theirs come from LiteLLM's bundled list. When nothing says,
BASELINE_WINDOW is used.
"""

import os
from typing import Any
from urllib.parse import quote

import httpx

from reconix_ai.providers.settings import ProviderConfig, ProviderType

PROBED_TYPES = {ProviderType.OLLAMA, ProviderType.OPENAI_API_COMPATIBLE, ProviderType.ANTHROPIC}
ANTHROPIC_URL = "https://api.anthropic.com"
RECONIX_WINDOW = 64_000
BASELINE_WINDOW = 32_000  # Ollama, OpenAI-compatible or an unknown cloud model
PROBE_TIMEOUT_SECONDS = 5.0
# What OpenAI-compatible servers call the window in their /models entry (vLLM and SGLang,
# OpenRouter and others, LM Studio). llama.cpp lists only its training length: baseline.
WINDOW_FIELDS = (
    "max_model_len",
    "context_length",
    "context_window",
    "loaded_context_length",
    "max_context_length",
)

# (provider type, address, model) -> window; a failed probe is kept too (as the baseline),
# so a server without the answer is not asked again on every call.
_probed: dict[tuple[str, str, str], int] = {}


def reconix_window() -> int:
    """RECONIX_CONTEXT_WINDOW, or 64,000 when unset."""
    value = os.environ.get("RECONIX_CONTEXT_WINDOW", "").strip()
    if not value:
        return RECONIX_WINDOW
    try:
        window = int(value)
    except ValueError:
        raise ValueError("RECONIX_CONTEXT_WINDOW must be a whole number.") from None
    if window < 1_000:
        raise ValueError("RECONIX_CONTEXT_WINDOW must be at least 1000.")
    return window


async def context_window(
    config: ProviderConfig, model: str, base_url: str | None, model_info: dict[str, Any]
) -> int:
    """The model's window. model_info is LiteLLM's entry for a cloud model ({} if unknown);
    base_url is the checked address the call goes to."""
    if config.provider_type == ProviderType.RECONIX:
        return reconix_window()
    known = model_info.get("max_input_tokens")
    listed = known if isinstance(known, int) and known > 0 else None
    if config.provider_type not in PROBED_TYPES:
        return listed or BASELINE_WINDOW  # OpenAI and DeepSeek do not list windows
    if config.provider_type != ProviderType.ANTHROPIC and not base_url:
        return BASELINE_WINDOW
    key = (config.provider_type.value, base_url or "", config.model_name)
    if key not in _probed:
        # A new Claude model is known to its API before LiteLLM's bundled list.
        _probed[key] = await probe(config, base_url) or listed or BASELINE_WINDOW
    return _probed[key]


async def probe(config: ProviderConfig, base_url: str | None) -> int | None:
    """What the server says the model's window is, or None when it does not say. Only the
    address the model call itself goes to is asked, with the same key."""
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT_SECONDS) as http:
            if config.provider_type == ProviderType.ANTHROPIC:
                root = (base_url or ANTHROPIC_URL).rstrip("/").removesuffix("/v1")
                headers = {"x-api-key": config.api_key or "", "anthropic-version": "2023-06-01"}
                name = quote(config.model_name, safe="")
                response = await http.get(f"{root}/v1/models/{name}", headers=headers)
                response.raise_for_status()
                return positive(response.json().get("max_input_tokens"))
            if base_url is None:
                return None
            if config.provider_type == ProviderType.OLLAMA:
                root = base_url.rstrip("/").removesuffix("/v1")
                response = await http.post(f"{root}/api/show", json={"model": config.model_name})
                response.raise_for_status()
                return ollama_window(response.json())
            headers = {"Authorization": f"Bearer {config.api_key}"} if config.api_key else {}
            response = await http.get(f"{base_url.rstrip('/')}/models", headers=headers)
            response.raise_for_status()
            return listed_window(response.json(), config.model_name)
    except (httpx.HTTPError, ValueError, AttributeError):  # down, refused or not JSON
        return None


def positive(value: Any) -> int | None:
    return value if isinstance(value, int) and value > 0 else None


def ollama_window(body: Any) -> int | None:
    """The num_ctx the Modelfile sets, else the model's trained length capped at the
    baseline: Ollama reserves memory for the whole num_ctx it is sent, so a 128k model
    is not run at 128k unless its owner set that."""
    if not isinstance(body, dict):
        return None
    for line in str(body.get("parameters") or "").splitlines():
        name, _, value = line.strip().partition(" ")
        if name == "num_ctx" and value.strip().isdigit():
            return int(value.strip())
    info = body.get("model_info")
    if isinstance(info, dict):
        for name, value in info.items():
            if name.endswith(".context_length") and isinstance(value, int) and value > 0:
                return min(value, BASELINE_WINDOW)
    return None


def listed_window(body: Any, model_name: str) -> int | None:
    """The window of model_name in an OpenAI-style /models answer, when it gives one."""
    entries = body.get("data") if isinstance(body, dict) else None
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict) or entry.get("id") != model_name:
            continue
        meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
        for name in WINDOW_FIELDS:
            value = entry.get(name, meta.get(name))
            if isinstance(value, int) and value > 0:
                return value
    return None
