import json
from uuid import uuid4

import httpx
import pytest

from reconix_api.clients.mcp import McpError, make_call_tool, to_tool_result, tool_call
from reconix_api.core.interfaces import ToolJob, ToolName, ToolRunStatus

URL = "http://kali:8096/mcp"


def job(tool: ToolName = ToolName.NMAP, target: str = "172.20.0.5", arguments=None) -> ToolJob:
    return ToolJob(
        tool_run_id=uuid4(),
        tool=tool,
        target=target,
        arguments=arguments if arguments is not None else ["-sV", "-p", "22,80"],
        job_token="job-token",
        timeout_seconds=60,
    )


def envelope(**fields) -> str:
    base = {"ok": True, "status": "ok", "exit_code": 0, "stdout": "<nmaprun/>", "stderr": ""}
    return json.dumps({**base, "duration_ms": 1500, "truncated": False, **fields})


class FakeKali:
    """Answers like the Kali MCP server over Streamable HTTP; records what it was sent."""

    def __init__(self, text: str = "", error: dict | None = None, sse: bool = False) -> None:
        self.text = text or envelope()
        self.error = error
        self.sse = sse
        self.requests: list[tuple[dict, dict]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        self.requests.append((dict(request.headers), body))
        if body["method"] == "initialize":
            return self.reply(body, {"protocolVersion": "2025-06-18"}, {"mcp-session-id": "s1"})
        if "id" not in body:
            return httpx.Response(202)
        if self.error:
            return self.reply(body, error=self.error)
        content = [{"type": "text", "text": self.text}]
        return self.reply(body, {"content": content, "isError": False})

    def reply(self, body, result=None, headers=None, error=None) -> httpx.Response:
        message = {"jsonrpc": "2.0", "id": body["id"]}
        message.update({"error": error} if error else {"result": result})
        if self.sse:
            text = f"event: message\ndata: {json.dumps(message)}\n\n"
            headers = {**(headers or {}), "content-type": "text/event-stream"}
            return httpx.Response(200, text=text, headers=headers)
        return httpx.Response(200, json=message, headers=headers)

    def call(self) -> tuple[dict, dict]:
        return self.requests[-1]


async def run(kali: FakeKali, the_job: ToolJob):
    call_tool = make_call_tool(URL, "access-key", transport=httpx.MockTransport(kali))
    return await call_tool(the_job)


def test_arguments_go_back_as_the_same_list():
    name, arguments = tool_call(job(arguments=["-sV", "-p", "22,80", "a b"]))
    assert name == "nmap"
    assert arguments["opts"] == "-sV -p 22,80 'a b'"
    assert arguments["target"] == "172.20.0.5"


def test_opts_is_sent_even_when_empty():
    # Leaving it out would make the server run its own unchecked default options.
    _, arguments = tool_call(job(arguments=[]))
    assert arguments["opts"] == ""


def test_source_tools_send_a_path():
    name, arguments = tool_call(job(ToolName.SEMGREP, "/workspace/app", []))
    assert name == "semgrep"
    assert arguments["path"] == "/workspace/app"


def test_zap_refuses_extra_arguments():
    with pytest.raises(McpError):
        tool_call(job(ToolName.ZAP, "http://juice-shop:3000/", ["-x"]))


async def test_call_sends_the_key_session_and_job_token():
    kali = FakeKali()
    result = await run(kali, job())

    assert result.status == ToolRunStatus.COMPLETED
    assert result.stdout == "<nmaprun/>"
    assert result.duration_ms == 1500
    headers, body = kali.call()
    assert headers["authorization"] == "Bearer access-key"
    assert headers["mcp-session-id"] == "s1"
    assert body["method"] == "tools/call"
    assert body["params"]["name"] == "nmap"
    assert body["params"]["_meta"] == {"job_token": "job-token"}
    assert [b["method"] for _, b in kali.requests] == [
        "initialize",
        "notifications/initialized",
        "tools/call",
    ]


async def test_sse_answers_are_read_too():
    result = await run(FakeKali(sse=True), job())
    assert result.status == ToolRunStatus.COMPLETED


async def test_rpc_error_raises():
    kali = FakeKali(error={"code": -32001, "message": "Unauthorized"})
    with pytest.raises(McpError, match="Unauthorized"):
        await run(kali, job())


def test_status_values_map_to_ours():
    assert to_tool_result(envelope(status="timeout", ok=False)).status == ToolRunStatus.TIMED_OUT
    assert to_tool_result(envelope(status="error", ok=False)).status == ToolRunStatus.FAILED
    assert to_tool_result(envelope(status="blocked", ok=False)).status == ToolRunStatus.FAILED


def test_container_path_is_not_taken_as_output():
    result = to_tool_result(envelope(output_file="/var/kali/result-1.txt", truncated=True))
    assert result.output_file is None
    assert result.truncated is True


def test_plain_text_results_from_zap():
    assert to_tool_result("Spider: 3 URL(s)").status == ToolRunStatus.COMPLETED
    failed = to_tool_result("[error] url is required")
    assert failed.status == ToolRunStatus.FAILED
    assert failed.stderr == "[error] url is required"


def test_no_access_key_is_refused():
    with pytest.raises(ValueError):
        make_call_tool(URL, "")
