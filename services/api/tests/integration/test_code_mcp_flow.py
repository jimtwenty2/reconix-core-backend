"""The core MCP server at /mcp: the real app in uvicorn (in a thread), the mcp client, a real
database, the fake Kali MCP and the fake review model."""

import json
import socket
import threading
import time
from collections.abc import Iterator
from contextlib import asynccontextmanager

import httpx
import httpx2
import pytest
import uvicorn
from mcp import Client
from mcp.client.streamable_http import streamable_http_client

from reconix_api.api import code_mcp
from reconix_api.services import code_scans
from tests.integration.test_code_scan_flow import entries, slow_tools, tar_gz
from tests.integration.test_session_code_scan_flow import CODE, kali_tools

TOOLS = {
    "sync_code",
    "clone_repo",
    "copy_folder",
    "start_code_scan",
    "get_code_scan",
    "watch_code_scan",
    "cancel_code_scan",
    "list_code_findings",
    "get_code_scan_log",
}
GITHUB_TOKEN = "ghp_not-a-real-token-123456"  # noqa: S105


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def base_url(db_app, code_dir, monkeypatch) -> Iterator[str]:
    monkeypatch.setattr(code_mcp, "POLL_SECONDS", 0.05)
    port = free_port()
    server = uvicorn.Server(
        uvicorn.Config(db_app, host="127.0.0.1", port=port, log_level="warning")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}"
    for _ in range(200):
        try:
            if httpx.get(f"{url}/api/v1/health").status_code == 200:
                break
        except httpx.HTTPError:
            time.sleep(0.05)
    else:
        raise RuntimeError("the server did not start")
    yield url
    for _ in range(200):  # a cancelled scan still ends its running tool call
        if not code_scans._running:
            break
        time.sleep(0.05)
    server.should_exit = True
    thread.join(10)


def open_session(base_url: str) -> tuple[str, str]:
    """A vscode session: (token, session_id)."""
    created = httpx.post(f"{base_url}/api/v1/sessions", json={"interface": "vscode"})
    assert created.status_code == 201, created.json()
    return created.json()["token"], created.json()["session_id"]


@asynccontextmanager
async def connect(base_url: str, token: str):
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {token}"}, timeout=60)
    async with http, Client(streamable_http_client(f"{base_url}/mcp", http_client=http)) as client:
        yield client


async def call(client, name: str, args: dict | None = None, **kwargs):
    """The tool's result; a tool error raises RuntimeError with its text."""
    result = await client.call_tool(name, args or {}, **kwargs)
    text = result.content[0].text if result.content else ""
    if result.is_error:
        raise RuntimeError(text)
    content = result.structured_content
    if content is None:
        return json.loads(text)
    return content["result"] if set(content) == {"result"} else content


def upload(base_url: str, token: str, session_id: str, files: dict[str, bytes]) -> None:
    uploaded = httpx.put(
        f"{base_url}/api/v1/sessions/{session_id}/code",
        content=tar_gz(files),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/gzip"},
    )
    assert uploaded.status_code == 200, uploaded.json()


async def test_the_server_lists_the_9_code_tools(base_url):
    token, _ = open_session(base_url)
    async with connect(base_url, token) as client:
        listed = await client.list_tools()
    assert {tool.name for tool in listed.tools} == TOOLS


@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer wrong"}, {"Authorization": "x"}])
def test_mcp_needs_a_valid_session_token(base_url, headers):
    response = httpx.post(f"{base_url}/mcp", json={}, headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "UNAUTHORIZED"


def test_mcp_still_checks_the_host(base_url):
    token, _ = open_session(base_url)
    headers = {"Authorization": f"Bearer {token}", "Host": "evil.example"}
    response = httpx.post(f"{base_url}/mcp", json={}, headers=headers)
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_HOST"


async def test_a_whole_scan_through_mcp(base_url, db_app, code_dir):
    kali_tools(db_app, code_dir)
    slow_tools(db_app, 0.1)  # the stage and progress change while the scan is watched
    token, session_id = open_session(base_url)
    async with connect(base_url, token) as client:
        synced = await call(client, "sync_code", {"session_id": session_id, "files": entries(CODE)})
        assert sorted(synced["missing"]) == sorted(CODE)
        upload(base_url, token, session_id, CODE)

        started = await call(client, "start_code_scan", {"session_id": session_id})
        assert started["agent_runs_status"] == "RUNNING"
        scan_id = started["agent_run_id"]
        progress = []

        async def on_progress(done: float, total: float | None, message: str | None) -> None:
            progress.append((done, total, message))

        ended = await call(
            client, "watch_code_scan", {"scan_id": scan_id}, progress_callback=on_progress
        )
        assert ended["agent_runs_status"] == "COMPLETED", ended
        assert len(progress) >= 2, progress
        assert progress[-1][1] == 100 and progress[-1][2].startswith("DONE")

        scan = await call(client, "get_code_scan", {"scan_id": scan_id})
        assert scan["counts"]["HIGH"] >= 1
        found = await call(client, "list_code_findings", {"scan_id": scan_id})
        assert {finding["path"] for finding in found} >= {"src/app.py", "settings.py"}
        assert {finding["verdict"] for finding in found} == {"LIKELY_TRUE_POSITIVE"}
        log = await call(client, "get_code_scan_log", {"scan_id": scan_id, "tool": "sonar_scan"})
        assert "ANALYSIS SUCCESSFUL" in log

        with pytest.raises(RuntimeError, match="SCAN_ENDED"):
            await call(client, "cancel_code_scan", {"scan_id": scan_id})
        with pytest.raises(RuntimeError, match="TOOL_LOG_NOT_FOUND"):
            await call(client, "get_code_scan_log", {"scan_id": scan_id, "tool": "nmap"})


async def test_watch_sends_a_heartbeat_while_nothing_changes(
    base_url, db_app, code_dir, monkeypatch
):
    monkeypatch.setattr(code_mcp, "HEARTBEAT_SECONDS", 0.1)
    kali_tools(db_app, code_dir)
    slow_tools(db_app, 0.6)  # one tool call: the scan stays at the same step meanwhile
    token, session_id = open_session(base_url)
    upload(base_url, token, session_id, CODE)
    async with connect(base_url, token) as client:
        args = {"session_id": session_id, "tools": ["SEMGREP"], "analyze": False}
        started = await call(client, "start_code_scan", args)
        messages = []

        async def on_progress(done: float, total: float | None, message: str | None) -> None:
            messages.append(message)

        await call(
            client,
            "watch_code_scan",
            {"scan_id": started["agent_run_id"]},
            progress_callback=on_progress,
        )
    repeated = [a for a, b in zip(messages, messages[1:], strict=False) if a == b]
    assert len(repeated) >= 2, messages


async def test_a_running_scan_can_be_cancelled(base_url, db_app, code_dir):
    kali_tools(db_app, code_dir)
    slow_tools(db_app, 0.3)
    token, session_id = open_session(base_url)
    upload(base_url, token, session_id, CODE)
    async with connect(base_url, token) as client:
        started = await call(client, "start_code_scan", {"session_id": session_id})
        cancelled = await call(client, "cancel_code_scan", {"scan_id": started["agent_run_id"]})
    assert cancelled["agent_runs_status"] == "CANCELLED"


async def test_another_session_cannot_use_my_code_or_scans(base_url, db_app, code_dir):
    kali_tools(db_app, code_dir)
    token, session_id = open_session(base_url)
    other_token, _ = open_session(base_url)
    upload(base_url, token, session_id, CODE)
    async with connect(base_url, token) as client:
        scan_id = (await call(client, "start_code_scan", {"session_id": session_id}))[
            "agent_run_id"
        ]
        await call(client, "watch_code_scan", {"scan_id": scan_id})
    async with connect(base_url, other_token) as other:
        with pytest.raises(RuntimeError, match="NOT_YOUR_SESSION"):
            await call(other, "sync_code", {"session_id": session_id, "files": []})
        with pytest.raises(RuntimeError, match="NOT_YOUR_SESSION"):
            await call(other, "start_code_scan", {"session_id": session_id})
        for name in ["get_code_scan", "watch_code_scan", "cancel_code_scan", "list_code_findings"]:
            with pytest.raises(RuntimeError, match="NOT_YOUR_SCAN"):
                await call(other, name, {"scan_id": scan_id})
        with pytest.raises(RuntimeError, match="NOT_YOUR_SCAN"):
            await call(other, "get_code_scan_log", {"scan_id": scan_id, "tool": "SEMGREP"})


async def test_tool_errors_carry_the_code_and_never_the_github_token(base_url, db_app, caplog):
    token, session_id = open_session(base_url)
    async with connect(base_url, token) as client:
        with pytest.raises(RuntimeError, match="INVALID_REPO_URL") as refused:
            args = {
                "session_id": session_id,
                "url": "https://evil.example/x",
                "token": GITHUB_TOKEN,
            }
            await call(client, "clone_repo", args)
        assert GITHUB_TOKEN not in str(refused.value)
        with pytest.raises(RuntimeError, match="VALIDATION_ERROR: .*token") as too_long:
            args = {"session_id": session_id, "url": "https://github.com/a/b", "token": "t" * 1001}
            await call(client, "clone_repo", args)
        assert "t" * 1001 not in str(too_long.value)
        with pytest.raises(RuntimeError, match="VALIDATION_ERROR: .*paths"):
            await call(client, "start_code_scan", {"session_id": session_id, "paths": ["../x"]})
    assert GITHUB_TOKEN not in caplog.text
    assert all(GITHUB_TOKEN not in json.dumps(event.details) for event in audit_events(db_app))


async def test_copy_folder_through_mcp(base_url, tmp_path_factory):
    folder = tmp_path_factory.mktemp("project")
    (folder / "app.py").write_text("print('hi')\n")
    token, session_id = open_session(base_url)
    async with connect(base_url, token) as client:
        copied = await call(client, "copy_folder", {"session_id": session_id, "path": str(folder)})
        assert copied["files"] == 1
        with pytest.raises(RuntimeError, match="FOLDER_NOT_FOUND"):
            await call(client, "copy_folder", {"session_id": session_id, "path": "relative/x"})


def audit_events(db_app) -> list:
    return db_app.state.parts["audit"].events
