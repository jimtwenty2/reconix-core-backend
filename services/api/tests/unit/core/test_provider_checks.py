import pytest

from reconix_api.core import provider_checks
from reconix_api.core.errors import ApiError


@pytest.mark.parametrize("url", ["http://10.0.0.5:11434", "http://169.254.169.254"])
async def test_models_are_never_asked_off_this_computer(url):
    with pytest.raises(ApiError) as raised:
        await provider_checks.local_models(url)
    assert raised.value.code == "PROVIDER_URL_NOT_ALLOWED"


async def test_an_ollama_that_does_not_answer_is_503():
    with pytest.raises(ApiError) as raised:
        await provider_checks.local_models("http://127.0.0.1:1")  # nothing listens on port 1
    assert (raised.value.status, raised.value.code) == (503, "MODEL_UNAVAILABLE")


@pytest.fixture
def compatible_server():
    """An OpenAI-compatible server on 127.0.0.1 (as LM Studio is): /models lists two ids and
    remembers the Authorization header it got."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    seen: dict[str, str | None] = {}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - the http.server name
            seen["path"] = self.path
            seen["auth"] = self.headers.get("Authorization")
            body = json.dumps({"data": [{"id": "qwen:7b"}, {"id": "google/gemma-4-e4b"}]})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body.encode())

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/v1", seen
    server.shutdown()


async def test_a_compatible_server_on_this_computer_lists_its_models(compatible_server):
    url, seen = compatible_server
    models = await provider_checks.compatible_models(url, "fake-key-0000")
    assert models == ["google/gemma-4-e4b", "qwen:7b"]
    assert seen == {"path": "/v1/models", "auth": "Bearer fake-key-0000"}


@pytest.mark.parametrize("url", ["https://llm.example.com/v1", "http://10.0.0.5:1234/v1"])
async def test_a_compatible_server_off_this_computer_is_never_asked(url):
    with pytest.raises(ApiError) as raised:
        await provider_checks.compatible_models(url, None)
    assert raised.value.code == "MODEL_LIST_NOT_SUPPORTED"


async def test_a_compatible_server_that_does_not_answer_is_503():
    with pytest.raises(ApiError) as raised:
        await provider_checks.compatible_models("http://127.0.0.1:1/v1", None)
    assert (raised.value.status, raised.value.code) == (503, "MODEL_UNAVAILABLE")
    assert "127.0.0.1" not in raised.value.message  # never repeats the address


@pytest.mark.parametrize(
    ("provider_type", "list_url", "headers"),
    [
        ("OPENAI", "https://api.openai.com/v1/models", {"Authorization": "Bearer fake-key-0000"}),
        ("DEEPSEEK", "https://api.deepseek.com/models", {"Authorization": "Bearer fake-key-0000"}),
        (
            "ANTHROPIC",
            "https://api.anthropic.com/v1/models",
            {"x-api-key": "fake-key-0000", "anthropic-version": "2023-06-01"},
        ),
    ],
)
async def test_a_cloud_service_lists_its_models_at_its_own_address(
    monkeypatch, provider_type, list_url, headers
):
    seen = {}

    async def model_list(base_url, url, who, sent=None):
        seen.update(url=url, headers=sent)
        return {"data": [{"id": "model-b"}, {"id": "model-a"}]}

    monkeypatch.setattr(provider_checks, "_model_list", model_list)
    models = await provider_checks.cloud_models(provider_type, "fake-key-0000")
    assert models == ["model-a", "model-b"]
    assert seen == {"url": list_url, "headers": headers}


async def test_a_cloud_service_without_a_saved_key_is_not_asked():
    with pytest.raises(ApiError) as raised:
        await provider_checks.cloud_models("OPENAI", None)
    assert (raised.value.status, raised.value.code) == (422, "PROVIDER_KEY_MISSING")


@pytest.mark.parametrize("provider_type", ["RECONIX", "OLLAMA", "OPENAI_API_COMPATIBLE"])
async def test_only_cloud_services_list_through_cloud_models(provider_type):
    with pytest.raises(ApiError) as raised:
        await provider_checks.cloud_models(provider_type, "fake-key-0000")
    assert raised.value.code == "MODEL_LIST_NOT_SUPPORTED"
