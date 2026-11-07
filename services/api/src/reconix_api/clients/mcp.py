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
import os
import shlex
from typing import Any
from urllib.parse import urlsplit

import httpx

from reconix_ai.harness.catalog import canonical, input_schema, is_known_tool
from reconix_api.core.interfaces import CallTool, ToolJob, ToolResult, ToolRunStatus

PROTOCOL_VERSION = "2025-06-18"
NETWORK_MARGIN_SECONDS = 30  # on top of the tool's own timeout

# The path brute-forcers' wordlist: fixed by Core, never chosen by the model. It ships
# with the Kali image (wfuzz's general list, about 950 common paths).
WORDLIST = "/usr/share/wfuzz/wordlist/general/common.txt"
WORDLIST_TOOLS = ("ffuf", "gobuster", "wfuzz")
FUZZ_TOOLS = ("ffuf", "wfuzz")  # these need the FUZZ keyword where the word goes
# A Reconix-controlled Interactsh server for nuclei_dast OOB callbacks. When unset, nuclei
# uses its public default; deploy SHOULD point this at a self-hosted server so a target's
# out-of-band interactions are not sent to a third party.
INTERACTSH_SERVER = os.environ.get("RECONIX_INTERACTSH_SERVER", "")

KALI_STATUS = {
    "ok": ToolRunStatus.COMPLETED,
    "timeout": ToolRunStatus.TIMED_OUT,
}


class McpError(Exception):
    """The MCP server refused the call or answered with something we cannot read."""


def tool_call(job: ToolJob) -> tuple[str, dict[str, Any]]:
    """Our ToolJob -> the Kali tool name and its arguments, from the tool's inputSchema.

    The tool name is the catalog name (lowercased). The job's target fills the
    tool's primary input param (the first required param that is not opts/timeout);
    the approved arguments go in `opts` when the tool takes it, always sent (even
    empty) so the server never falls back to its own unchecked defaults; arguments for
    a tool without `opts` are refused, never dropped. `timeout` is sent when the tool
    takes it.
    """
    name = canonical(str(job.tool))
    schema = input_schema(name)
    if not is_known_tool(name) or not schema:
        raise McpError(f"UNKNOWN_TOOL: {job.tool}")
    props = schema.get("properties", {}) or {}
    if job.arguments and "opts" not in props:
        raise McpError(f"TOOL_TAKES_NO_OPTIONS: {job.tool}")  # never drop approved arguments
    args: dict[str, Any] = {}
    primary = _primary_param(schema.get("required", []), props)
    if primary:
        args[primary] = job.target
    if "opts" in props:
        args["opts"] = shlex.join(job.arguments)
    if "timeout" in props:
        args["timeout"] = job.timeout_seconds
    args.update(_fixed_inputs(name, job.target, props))
    if primary and name in FUZZ_TOOLS:
        args[primary] = _with_fuzz(job.target)
    return name, args


def _fixed_inputs(name: str, target: str, props: dict[str, Any]) -> dict[str, Any]:
    """Required inputs other than the target, which the model never supplies: fixed by
    Core, or read from the approved target itself.

    - ffuf, gobuster, wfuzz: Core's own wordlist.
    - nikto: the port of the target URL (https without one: 443), so nikto does not
      scan port 80 of an https or :3000 site.
    - schemathesis: the base URL is the scheme+host of the schema URL (the target), so
      the tests hit the API the schema came from and nothing wider.
    - nuclei_dast: a Reconix-controlled Interactsh server for OOB callbacks, when set.
    """
    fixed: dict[str, Any] = {}
    if name in WORDLIST_TOOLS and "wordlist" in props:
        fixed["wordlist"] = WORDLIST
    if name == "nikto" and "port" in props:
        port = _url_port(target)
        if port:
            fixed["port"] = str(port)
    if name == "schemathesis" and "base_url" in props:
        base = _origin(target)
        if base:
            fixed["base_url"] = base
    if name == "nuclei_dast" and INTERACTSH_SERVER and "interactsh_server" in props:
        fixed["interactsh_server"] = INTERACTSH_SERVER
    return fixed


def _origin(url: str) -> str:
    """The scheme://host[:port] of a URL (no path), or "" when it is not a URL."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return ""
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return ""


def _with_fuzz(target: str) -> str:
    """The URL with FUZZ where each word goes: after the path, at call time only.

    The approved action (its hash and the scope check) keeps the plain URL. A target
    that already holds FUZZ is sent as it is.
    """
    if "FUZZ" in target:
        return target
    parts = urlsplit(target)
    path = parts.path if parts.path.endswith("/") else parts.path + "/"
    return parts._replace(path=path + "FUZZ", fragment="").geturl()


def _url_port(target: str) -> int | None:
    """The port a URL names, or its scheme's default; None for a bare host."""
    try:
        parts = urlsplit(target)
        port = parts.port
    except ValueError:
        return None
    if port:
        return port
    return {"http": 80, "https": 443}.get(parts.scheme.lower())


def _primary_param(required: list[str], props: dict[str, Any]) -> str | None:
    """The tool's main input (target/url/path/command/...): the first required
    param that is not opts/timeout, else the first such property."""
    for name in [*required, *props]:
        if name not in ("opts", "timeout"):
            return name
    return None


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
    url: str, auth_token: str, transport: httpx.AsyncBaseTransport | None = None
) -> CallTool:
    """`auth_token` (RECONIX_MCP_AUTH_TOKEN) is optional: when empty, no Authorization
    header is sent. The one-time job token is sent on every call either way.
    `transport` is only for tests."""

    async def call_tool(job: ToolJob) -> ToolResult:
        name, arguments = tool_call(job)
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if auth_token:
            headers["Authorization"] = f"Bearer {auth_token}"
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
