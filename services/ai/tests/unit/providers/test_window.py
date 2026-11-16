"""What a server says about a model's context window."""

import httpx
import pytest

from reconix_ai.providers import window
from reconix_ai.providers.settings import ProviderConfig, ProviderType

REAL_PROBE = window.probe  # conftest swaps window.probe out for every test
CLAUDE = ProviderConfig(ProviderType.ANTHROPIC, "claude-new-6", api_key="sk-fake-1")


def fake_server(monkeypatch: pytest.MonkeyPatch, answer: httpx.Response) -> list[httpx.Request]:
    """httpx answers every request with answer; returns what was asked."""
    asked: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        asked.append(request)
        return answer

    real_client = httpx.AsyncClient
    monkeypatch.setattr(
        window.httpx,
        "AsyncClient",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    )
    return asked


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"parameters": "stop <eos>\nnum_ctx 16384", "model_info": {}}, 16_384),
        ({"model_info": {"llama.context_length": 131_072}}, 32_000),  # capped: memory
        ({"model_info": {"qwen2.context_length": 8_192}}, 8_192),
        ({"model_info": {}}, None),
        ("not json", None),
    ],
)
def test_ollama_window(body: object, expected: int | None) -> None:
    assert window.ollama_window(body) == expected


@pytest.mark.parametrize(
    ("entry", "expected"),
    [
        ({"id": "qwen3", "max_model_len": 65_536}, 65_536),  # vLLM, SGLang
        ({"id": "qwen3", "context_length": 40_960}, 40_960),  # OpenRouter and others
        ({"id": "qwen3", "loaded_context_length": 8_192}, 8_192),  # LM Studio
        ({"id": "qwen3"}, None),
        ({"id": "other", "max_model_len": 65_536}, None),  # another model's window
    ],
)
def test_listed_window(entry: dict, expected: int | None) -> None:
    assert window.listed_window({"data": [entry]}, "qwen3") == expected


async def test_a_server_that_cannot_be_reached_is_a_failed_probe() -> None:
    config = ProviderConfig(ProviderType.OPENAI_API_COMPATIBLE, "qwen3", "http://127.0.0.1:9/v1")

    with pytest.raises(window.ProbeFailed):
        await REAL_PROBE(config, "http://127.0.0.1:9/v1")


async def test_anthropic_says_a_new_models_window(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = fake_server(monkeypatch, httpx.Response(200, json={"max_input_tokens": 2_000_000}))

    assert await REAL_PROBE(CLAUDE, None) == 2_000_000
    assert str(asked[0].url) == "https://api.anthropic.com/v1/models/claude-new-6"
    assert asked[0].headers["x-api-key"] == "sk-fake-1"


async def test_a_model_name_cannot_leave_the_models_path(monkeypatch: pytest.MonkeyPatch) -> None:
    asked = fake_server(monkeypatch, httpx.Response(404))
    config = ProviderConfig(ProviderType.ANTHROPIC, "../../admin?x=1", api_key="sk-fake-1")

    with pytest.raises(window.ProbeFailed):  # a 404 is an error status
        await REAL_PROBE(config, None)
    assert asked[0].url.raw_path == b"/v1/models/..%2F..%2Fadmin%3Fx%3D1"


async def test_the_openai_compatible_probe_reads_models(monkeypatch: pytest.MonkeyPatch) -> None:
    body = {"data": [{"id": "qwen3", "max_model_len": 65_536}]}
    asked = fake_server(monkeypatch, httpx.Response(200, json=body))
    config = ProviderConfig(ProviderType.OPENAI_API_COMPATIBLE, "qwen3", "http://127.0.0.1:8000/v1")

    assert await REAL_PROBE(config, "http://127.0.0.1:8000/v1") == 65_536
    assert str(asked[0].url) == "http://127.0.0.1:8000/v1/models"


async def test_a_probed_anthropic_window_beats_litellms(monkeypatch: pytest.MonkeyPatch) -> None:
    async def says(config: ProviderConfig, base_url: str | None) -> int:
        return 2_000_000

    monkeypatch.setattr(window, "probe", says)

    assert await window.context_window(CLAUDE, "m", None, {"max_input_tokens": 200_000}) == (
        2_000_000
    )


async def test_a_cloud_model_uses_litellm_and_unknown_ones_the_baseline() -> None:
    config = ProviderConfig(ProviderType.ANTHROPIC, "claude-sonnet-5-5", api_key="sk-fake-1")

    assert await window.context_window(config, "m", None, {"max_input_tokens": 1_000_000}) == (
        1_000_000
    )
    unknown = ProviderConfig(ProviderType.ANTHROPIC, "claude-unknown", api_key="sk-fake-1")
    assert await window.context_window(unknown, "m", None, {}) == window.BASELINE_WINDOW
