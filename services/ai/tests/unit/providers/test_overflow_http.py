"""The window probe and the overflow retry over real HTTP, with no mock of LiteLLM.

A small vLLM-style server runs on 127.0.0.1. LiteLLM really sends its requests to it, so
these tests prove that a real "too long" answer becomes an error is_overflow() recognises.
"""

import json
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from reconix_ai.providers import ProviderConfig, ProviderType, window
from reconix_ai.providers.client import (
    CUT_MARKER,
    ProviderError,
    complete,
    complete_with_tools,
)

REAL_PROBE = window.probe  # imported before any fixture replaces it
SERVER_TEXT = "SERVER-SECRET-WORDING-7731"  # must never reach a ProviderError message


class FakeVllm:
    """Answers /v1/models and /v1/chat/completions like vLLM and records every request."""

    def __init__(self) -> None:
        self.reported: int | None = 8192  # max_model_len in /v1/models
        self.limit = 8192  # the window the server really enforces (4 chars a token)
        self.named_window: int | None = None  # the number the 400 text names (default: limit)
        self.error_status = 400
        self.error_prefix = ""  # extra words in front of the 400/429 text
        self.hang_models = threading.Event()  # set: /v1/models never answers (until released)
        self.release = threading.Event()
        self.requests: list[tuple[str, str, dict[str, Any]]] = []
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.handler())
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/v1"

    @property
    def chats(self) -> list[dict[str, Any]]:
        return [body for method, path, body in self.requests if path.endswith("/chat/completions")]

    def overflow_body(self, prompt: int, max_tokens: int) -> dict[str, Any]:
        named = self.named_window or self.limit
        message = (
            f"{self.error_prefix}This model's maximum context length is {named} tokens. "
            f"However, you requested {prompt + max_tokens} tokens ({prompt} in the messages, "
            f"{max_tokens} in the completion). Please reduce the length of the messages or "
            f"completion. {SERVER_TEXT}"
        )
        return {
            "object": "error",
            "message": message,
            "type": "BadRequestError",
            "param": None,
            "code": self.error_status,
        }

    def handler(self) -> type[BaseHTTPRequestHandler]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return None

            def send_json(self, status: int, body: dict[str, Any]) -> None:
                data = json.dumps(body).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                fake.requests.append(("GET", self.path, {}))
                if fake.hang_models.is_set():
                    fake.release.wait(30)
                    return
                entry: dict[str, Any] = {"id": "fake-vllm"}
                if fake.reported is not None:
                    entry["max_model_len"] = fake.reported
                self.send_json(200, {"object": "list", "data": [entry]})

            def do_POST(self) -> None:
                size = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(size) or b"{}")
                fake.requests.append(("POST", self.path, body))
                chars = 0
                for message in body.get("messages", []):
                    chars += len(str(message.get("content") or ""))
                    chars += len(json.dumps(message.get("tool_calls") or []))
                prompt, max_tokens = chars // 4, int(body.get("max_tokens") or 0)
                if prompt + max_tokens > fake.limit:
                    status = fake.error_status
                    self.send_json(status, fake.overflow_body(prompt, max_tokens))
                    return
                self.send_json(
                    200,
                    {
                        "id": "chatcmpl-1",
                        "object": "chat.completion",
                        "created": 1,
                        "model": "fake-vllm",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "all good"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": prompt,
                            "completion_tokens": 2,
                            "total_tokens": prompt + 2,
                        },
                    },
                )

        return Handler


@pytest.fixture
def vllm() -> Iterator[FakeVllm]:
    fake = FakeVllm()
    fake.thread.start()
    yield fake
    fake.release.set()  # let a hung /models handler go
    fake.server.shutdown()
    fake.server.server_close()
    fake.thread.join(timeout=5)


@pytest.fixture(autouse=True)
def real_probe(no_window_probe: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """The conftest turns the probe off; these tests need the real one, with clean caches."""
    monkeypatch.setattr(window, "probe", REAL_PROBE)
    monkeypatch.setattr(window, "_probed", {})
    monkeypatch.setattr(window, "_remembered", {})
    monkeypatch.setattr(window, "_failed", {})


def config(vllm: FakeVllm) -> ProviderConfig:
    return ProviderConfig(ProviderType.OPENAI_API_COMPATIBLE, "fake-vllm", base_url=vllm.url)


def user(text: str) -> list[Any]:
    from reconix_ai.providers import Message

    return [Message("user", text)]


def asked(vllm: FakeVllm, window_size: int) -> bool:
    """Every chat request the server saw fits window_size (4 chars a token)."""
    return all(
        sum(len(str(m.get("content") or "")) for m in body["messages"]) // 4 + body["max_tokens"]
        <= window_size
        for body in vllm.chats
    )


async def test_probe_reads_max_model_len_and_first_request_fits_it(vllm: FakeVllm) -> None:
    got = await complete(user("hello"), config(vllm))

    assert got.text == "all good"
    assert [path for method, path, _ in vllm.requests if method == "GET"] == ["/v1/models"]
    assert len(vllm.chats) == 1
    # 8192 less the tiny prompt and the 1,000 margin: far below the 128,000 default
    assert 6_000 < vllm.chats[0]["max_tokens"] <= 8192 - 1_000
    assert asked(vllm, 8192)
    assert list(window._probed.values()) == [8192]


async def test_a_smaller_real_window_gets_one_retry_and_is_remembered(vllm: FakeVllm) -> None:
    vllm.limit = 4096  # /v1/models still says 8192

    got = await complete(user("hello"), config(vllm))

    assert got.text == "all good"
    assert len(vllm.chats) == 2  # exactly one retry
    first, retry = vllm.chats[0]["max_tokens"], vllm.chats[1]["max_tokens"]
    assert first > 4096 and retry <= 4096 - 1_000 and retry >= 1_024
    assert asked(vllm, 4096) is False  # the first one did not fit...
    assert vllm.chats[1]["max_tokens"] + 1 <= 4096  # ...the retry does
    assert list(window._remembered.values()) == [4096]

    await complete(user("again"), config(vllm))
    assert len(vllm.chats) == 3  # no retry this time
    assert vllm.chats[2]["max_tokens"] <= 4096 - 1_000
    assert [p for m, p, _ in vllm.requests if m == "GET"] == ["/v1/models"]  # probed once


async def test_a_prompt_that_cannot_fit_is_prompt_too_long_without_server_text(
    vllm: FakeVllm,
) -> None:
    vllm.limit = 4096
    huge = "x" * 40_000  # about 10,000 tokens by the server's count

    with pytest.raises(ProviderError) as caught:
        await complete(user(huge), config(vllm))

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert len(vllm.chats) <= 2
    assert SERVER_TEXT not in caught.value.message
    assert "maximum context length" not in caught.value.message
    assert "4096" not in caught.value.message


@pytest.mark.parametrize("status", [429, 400])
async def test_a_rate_limit_that_sounds_like_overflow_is_not_an_overflow(
    vllm: FakeVllm, status: int
) -> None:
    vllm.limit = 4096
    vllm.error_status = status
    vllm.error_prefix = "Rate limit reached, too many requests. "

    with pytest.raises(ProviderError) as caught:
        await complete(user("hello"), config(vllm))

    assert caught.value.code != "PROMPT_TOO_LONG"
    assert window._remembered == {}
    # no cut and no smaller window: every request that went out asked for the same answer
    assert {body["max_tokens"] for body in vllm.chats} == {vllm.chats[0]["max_tokens"]}
    assert vllm.chats[0]["max_tokens"] > 4096


def tool_loop(sizes: list[int]) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = [{"role": "user", "content": "scan it"}]
    for n, size in enumerate(sizes, start=1):
        messages.append(
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": f"call_{n}",
                        "type": "function",
                        "function": {"name": "read", "arguments": json.dumps({"n": n})},
                    }
                ],
            }
        )
        body = f"HEAD{n}-" + "m" * size + f"-TAIL{n}"
        messages.append({"role": "tool", "tool_call_id": f"call_{n}", "content": body})
    return messages


async def test_tool_loop_retry_cuts_every_tool_result_and_keeps_pairs(vllm: FakeVllm) -> None:
    # LiteLLM imports mcp as soon as a call carries tools; only the api package installs it.
    pytest.importorskip(
        "mcp", reason="litellm needs mcp for tool calls: run with --package reconix-api"
    )
    vllm.limit = 4096  # /v1/models says 8192
    tools = [{"type": "function", "function": {"name": "read", "parameters": {}}}]

    reply = await complete_with_tools(tool_loop([3_000, 3_000, 3_000]), tools, config(vllm))

    assert reply.text == "all good"
    assert len(vllm.chats) == 2
    first, retry = vllm.chats[0], vllm.chats[1]
    first_tools = [m for m in first["messages"] if m["role"] == "tool"]
    retry_tools = [m for m in retry["messages"] if m["role"] == "tool"]
    assert all(CUT_MARKER not in m["content"] for m in first_tools)
    assert len(retry_tools) == 3
    for n, message in enumerate(retry_tools, start=1):
        assert CUT_MARKER in message["content"]
        assert message["content"].startswith(f"HEAD{n}-")
        assert message["content"].endswith(f"-TAIL{n}")
        assert len(message["content"]) < 500
    # every tool call still has its result, in order, under the same id
    calls = [c["id"] for m in retry["messages"] for c in m.get("tool_calls") or []]
    results = [m["tool_call_id"] for m in retry_tools]
    assert calls == results == ["call_1", "call_2", "call_3"]
    roles = [m["role"] for m in retry["messages"]]
    assert roles == ["user", "assistant", "tool", "assistant", "tool", "assistant", "tool"]
    assert retry["max_tokens"] < first["max_tokens"] and retry["max_tokens"] <= 4096 - 1_000
    assert list(window._remembered.values()) == [4096]


async def test_a_larger_number_in_an_error_never_raises_a_remembered_window(
    vllm: FakeVllm,
) -> None:
    vllm.limit = 4096
    await complete(user("hello"), config(vllm))
    assert list(window._remembered.values()) == [4096]

    vllm.named_window = 131_072  # now the error names a bigger number than we know
    with pytest.raises(ProviderError) as caught:
        await complete(user("y" * 40_000), config(vllm))

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert list(window._remembered.values()) == [4096]


async def test_a_larger_number_in_an_error_does_not_raise_the_probed_window(
    vllm: FakeVllm,
) -> None:
    vllm.limit = 4096
    vllm.named_window = 131_072  # the first answer names more than the probe said (8192)

    with pytest.raises(ProviderError) as caught:
        await complete(user("hello"), config(vllm))

    assert caught.value.code == "PROMPT_TOO_LONG"
    assert window._remembered == {}
    assert list(window._probed.values()) == [8192]
    assert len(vllm.chats) == 1  # nothing to retry with: no smaller window was named


async def test_a_hanging_models_endpoint_costs_only_the_probe_timeout(
    vllm: FakeVllm, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(window, "PROBE_TIMEOUT_SECONDS", 1.0)
    vllm.hang_models.set()
    vllm.limit = 1_000_000

    started = time.monotonic()
    await complete(user("hello"), config(vllm))
    first = time.monotonic() - started

    assert first < 1.0 + 2.5  # the probe timeout plus the call itself
    assert 30_000 < vllm.chats[0]["max_tokens"] <= 32_000 - 1_000  # the 32k baseline
    assert window._probed == {}  # a failure is not remembered for good
    assert len(window._failed) == 1

    started = time.monotonic()
    await complete(user("again"), config(vllm))
    assert time.monotonic() - started < 1.0  # not asked again for 5 minutes
    assert [p for m, p, _ in vllm.requests if m == "GET"] == ["/v1/models"]
