"""The attached OpenAPI spec stays on this computer: a chat line goes to the Core API with
where the flow is, never the spec's endpoints (the spec is for the API template's plan)."""

import json

import pytest

from reconix import store

from .support import run_to

API_REQUEST = "test the API at https://api.example.com/v1"
SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Orders API", "version": "1.0"},
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/orders": {"post": {"summary": "Create an order",
                             "requestBody": {"content": {"application/json": {"schema": {
                                 "type": "object", "required": ["sku"],
                                 "properties": {"sku": {"type": "string"}}}}}},
                             "responses": {"201": {}}}},
        "/health": {"get": {"summary": "Health check", "responses": {"200": {}}}},
    },
}


@pytest.fixture
def api_ok(model_active):
    store.core_api_approve()


def _chats(fake_api) -> list:
    return [body["content"] for m, path, body, _ in fake_api.calls
            if m == "POST" and path.endswith("/chat")]


def test_a_matching_question_goes_without_the_spec(api_ok, fake_api, tmp_path):
    run_to("scope", API_REQUEST)
    path = tmp_path / "spec.json"
    path.write_text(json.dumps(SPEC), encoding="utf-8")
    store.attach_api_spec(str(path))
    store.say_to_assistant("how do I create an order with a sku?")
    [sent] = _chats(fake_api)
    assert sent.startswith("how do I create an order with a sku?")
    assert "POST /orders" not in sent and "API schema" not in sent
    assert store.get_api_spec() is not None            # still attached here
