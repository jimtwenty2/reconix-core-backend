"""The real call_tool: runs one tool in the Kali container through MCP.

The Kali MCP server speaks JSON-RPC over Streamable HTTP at `RECONIX_KALI_MCP_URL`:
initialize -> notifications/initialized -> tools/call. It checks the shared
access key in the Authorization header.

Each tool takes its options as one string (`opts`), which the server splits with
shlex. We build it with shlex.join, so the server gets back exactly the argument
list the checks approved. `opts` is always sent, even when empty: leaving it out
makes the server use its own default options, which were never checked.
"""

import json
import shlex
from typing import Any

import httpx

from reconix_api.core.interfaces import CallTool, ToolJob, ToolName, ToolResult, ToolRunStatus

PROTOCOL_VERSION = "2025-06-18"
NETWORK_MARGIN_SECONDS = 30  # on top of the tool's own timeout

KALI_STATUS = {
    "ok": ToolRunStatus.COMPLETED,
    "timeout": ToolRunStatus.TIMED_OUT,
}


class McpError(Exception):
    """The MCP server refused the call or answered with something we cannot read."""


def tool_call(job: ToolJob) -> tuple[str, dict[str, Any]]:
    """Our ToolJob -> the Kali tool name and its arguments."""
    opts = shlex.join(job.arguments)
    timeout = job.timeout_seconds
    if job.tool == ToolName.NMAP:
        return "nmap", {"target": job.target, "opts": opts, "timeout": timeout}
    if job.tool == ToolName.NUCLEI:
        return "nuclei", {"target": job.target, "opts": opts, "timeout": timeout}
    if job.tool == ToolName.SEMGREP:
        return "semgrep", {"path": job.target, "opts": opts, "timeout": timeout}
    if job.tool == ToolName.GITLEAKS:
        return "gitleaks", {"path": job.target, "opts": opts, "timeout": timeout}
    if job.tool == ToolName.ZAP:
        if job.arguments:
            raise McpError("ZAP_TAKES_NO_ARGUMENTS")
        return "zap_scan", {"url": job.target, "timeout": timeout}
    raise McpError(f"UNKNOWN_TOOL: {job.tool}")


def to_tool_result(text: str) -> ToolResult:
    """The text of a tools/call result -> ToolResult.

    Most tools return a JSON envelope (status, exit_code, stdout, ...). The zap_* tools
    return plain text, which starts with "[error]" when they fail.
    """
    try:
        envelope = json.loads(text)
    except json.JSONDecodeError:
        envelope = None
    if not isinstance(envelope, dict):
        failed = text.startswith("[error]")
        return ToolResult(
            status=ToolRunStatus.FAILED if failed else ToolRunStatus.COMPLETED,
            stdout="" if failed else text,
            stderr=text if failed else "",
        )
    return ToolResult(
        status=KALI_STATUS.get(envelope.get("status"), ToolRunStatus.FAILED),
        exit_code=envelope.get("exit_code"),
        stdout=envelope.get("stdout") or "",
        stderr=envelope.get("stderr") or "",
        # The envelope's output_file is a path inside the container, not the output.
        duration_ms=envelope.get("duration_ms") or 0,
        truncated=bool(envelope.get("truncated")),
    )


def read_message(response: httpx.Response) -> dict[str, Any]:
    """One JSON-RPC message, sent as plain JSON or as the last event of an SSE stream."""
    response.raise_for_status()
    if response.headers.get("content-type", "").startswith("text/event-stream"):
        events = [
            line[5:].strip() for line in response.text.splitlines() if line.startswith("data:")
        ]
        if not events:
            raise McpError("EMPTY_RESPONSE")
        return json.loads(events[-1])
    return response.json()


def rpc_result(message: dict[str, Any]) -> dict[str, Any]:
    if "error" in message:
        raise McpError(f"MCP_ERROR: {message['error'].get('message', '')}")
    return message.get("result") or {}


async def start_session(client: httpx.AsyncClient, url: str, headers: dict[str, str]) -> None:
    """initialize, then notifications/initialized. Adds the session id to `headers`."""
    initialize = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "reconix-api", "version": "0.0.0"},
        },
    }
    response = await client.post(url, headers=headers, json=initialize)
    rpc_result(read_message(response))
    session_id = response.headers.get("mcp-session-id")
    if session_id:
        headers["Mcp-Session-Id"] = session_id
    headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
    initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    (await client.post(url, headers=headers, json=initialized)).raise_for_status()


def make_call_tool(
    url: str, access_key: str, transport: httpx.AsyncBaseTransport | None = None
) -> CallTool:
    """`transport` is only for tests."""
    if not access_key:
        raise ValueError("RECONIX_MCP_ACCESS_KEY is not set")

    async def call_tool(job: ToolJob) -> ToolResult:
        name, arguments = tool_call(job)
        headers = {
            "Authorization": f"Bearer {access_key}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        call = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            # The job token travels with the call so the Kali side can check it.
            "params": {"name": name, "arguments": arguments, "_meta": {"job_token": job.job_token}},
        }
        timeout = job.timeout_seconds + NETWORK_MARGIN_SECONDS
        async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
            await start_session(client, url, headers)
            result = rpc_result(read_message(await client.post(url, headers=headers, json=call)))
        text = "".join(part.get("text", "") for part in result.get("content", []))
        return to_tool_result(text)

    return call_tool
