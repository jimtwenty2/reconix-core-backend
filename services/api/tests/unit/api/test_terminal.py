"""WS /terminal with a fake terminal app (a small Python script) and the fakes."""

import asyncio
import sys
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.terminal import QUEUE_SIZE, Terminal, child_environment, default_command
from reconix_api.main import create_app
from reconix_api.services.terminal import BadMessage, parse_message
from tests.fakes import OPERATOR_TOKEN, build_fake_interfaces, fake_mask_secrets

ORIGIN = {"Origin": "http://127.0.0.1:3000"}
AUTH = {"Authorization": f"Bearer {OPERATOR_TOKEN}", **ORIGIN}

# Says READY, reads one line, then prints what it got, its size and two environment values.
ECHO_APP = """
import os, sys
print("READY", flush=True)
line = sys.stdin.readline().strip()
cols, rows = os.get_terminal_size(0)
print(f"GOT:{line} SIZE:{cols}x{rows} TERM:{os.environ.get('TERM')}"
      f" KEY:{os.environ.get('RECONIX_FERNET_KEY', 'none')}"
      f" DATA:{os.environ.get('RECONIX_DATA_DIR', 'none')}", flush=True)
"""
SLEEPY_APP = "import time; print('READY', flush=True); time.sleep(60)"


@pytest.fixture
def make_app(monkeypatch):
    """An app whose terminal runs `script` instead of the real terminal app."""

    def build(script: str, command: list[str] | None = None):
        command = command or [sys.executable, "-c", script]
        monkeypatch.setattr("reconix_api.api.terminal.default_command", lambda: command)
        interfaces, parts = build_fake_interfaces()
        app = create_app(interfaces, mask_secrets=fake_mask_secrets)
        settings = Settings(stream_heartbeat_seconds=0.05)
        app.dependency_overrides[get_settings] = lambda: settings
        app.state.parts = parts
        return app

    return build


def connect(app, headers: dict, host: str = "127.0.0.1", subprotocols=None):
    """The test client ignores base_url for WebSockets, so the URL is given whole."""
    url = f"ws://{host}/api/v1/terminal"
    return TestClient(app).websocket_connect(url, headers=dict(headers), subprotocols=subprotocols)


def read_until(websocket, marker: str) -> str:
    seen = ""
    while marker not in seen:
        seen += websocket.receive_bytes().decode(errors="replace")
    return seen


def audit_types(app) -> list[str]:
    return [event.event_type for event in app.state.parts["audit"].events]


def test_keys_go_in_and_the_screen_comes_out(monkeypatch, make_app):
    monkeypatch.setenv("RECONIX_FERNET_KEY", "fake-api-only-secret")
    monkeypatch.setenv("RECONIX_DATA_DIR", "tui-data-folder")  # the TUI's own setting
    app = make_app(ECHO_APP)
    with connect(app, AUTH) as websocket:
        read_until(websocket, "READY")
        websocket.send_json({"type": "resize", "cols": 100, "rows": 40})
        websocket.send_json({"type": "input", "data": "hello\r"})
        screen = read_until(websocket, "DATA:")
        with pytest.raises(WebSocketDisconnect):  # the app exits, so the terminal closes
            while True:
                screen += websocket.receive_bytes().decode(errors="replace")

    assert "GOT:hello SIZE:100x40 TERM:xterm-256color KEY:none DATA:tui-data-folder" in screen
    assert audit_types(app) == ["TERMINAL_OPENED", "TERMINAL_CLOSED"]
    closed = app.state.parts["audit"].events[-1]
    assert (closed.details["reason"], closed.details["exit_code"]) == ("TUI_EXITED", 0)


def test_a_browser_sends_its_token_as_a_subprotocol(make_app):
    app = make_app(ECHO_APP)
    protocols = ["reconix.terminal", f"token.{OPERATOR_TOKEN}"]
    with connect(app, ORIGIN, subprotocols=protocols) as ws:
        assert ws.accepted_subprotocol == "reconix.terminal"  # never the token
        read_until(ws, "READY")


@pytest.mark.parametrize(
    ("headers", "host", "code"),
    [
        (ORIGIN, "127.0.0.1", 4401),  # no token
        ({**ORIGIN, "Authorization": "Bearer wrong"}, "127.0.0.1", 4401),
        ({"Authorization": f"Bearer {OPERATOR_TOKEN}"}, "127.0.0.1", 4403),  # no Origin
        ({**AUTH, "Origin": "http://evil.example"}, "127.0.0.1", 4403),
        (AUTH, "evil.example", 4403),  # DNS rebinding: the Host check covers WebSockets too
    ],
)
def test_the_handshake_refuses(make_app, headers, host, code):
    app = make_app(ECHO_APP)
    with pytest.raises(WebSocketDisconnect) as refused:
        with connect(app, headers, host):
            pass
    assert refused.value.code == code
    assert audit_types(app) == []


def test_one_terminal_per_session(make_app):
    app = make_app(SLEEPY_APP)
    with connect(app, AUTH) as first:
        read_until(first, "READY")
        with pytest.raises(WebSocketDisconnect) as refused:
            with connect(app, AUTH):
                pass
        assert refused.value.code == 4409
    assert ("TERMINAL_REFUSED", "ALREADY_OPEN") in [
        (event.event_type, event.details.get("reason")) for event in app.state.parts["audit"].events
    ]


def test_closing_the_session_ends_the_terminal(make_app):
    app = make_app(SLEEPY_APP)
    with connect(app, AUTH) as websocket:
        read_until(websocket, "READY")
        app.state.parts["operators"].tokens.pop(OPERATOR_TOKEN)
        with pytest.raises(WebSocketDisconnect) as closed:
            while True:
                websocket.receive_bytes()
    assert closed.value.code == 4401
    reason = app.state.parts["audit"].events[-1].details["reason"]
    assert reason == "SESSION_CLOSED"


def test_a_bad_message_closes_the_terminal(make_app):
    app = make_app(SLEEPY_APP)
    with connect(app, AUTH) as websocket:
        read_until(websocket, "READY")
        websocket.send_text("not json")
        with pytest.raises(WebSocketDisconnect) as closed:
            while True:
                websocket.receive_bytes()
    assert closed.value.code == 1003


def test_leaving_the_page_stops_the_app(make_app):
    app = make_app(SLEEPY_APP)
    with connect(app, AUTH) as websocket:
        read_until(websocket, "READY")
    deadline = time.monotonic() + 10  # the server cleans up after the page has gone
    while audit_types(app)[-1] != "TERMINAL_CLOSED" and time.monotonic() < deadline:
        time.sleep(0.05)
    closed = app.state.parts["audit"].events[-1]
    assert closed.event_type == "TERMINAL_CLOSED"
    assert closed.details["reason"] == "PAGE_CLOSED"
    assert closed.details["exit_code"] is not None  # stopped, not left running


@pytest.mark.parametrize(
    "message",
    [
        {"text": "[1, 2]"},
        {"text": '{"type": "shell", "data": "ls"}'},
        {"text": '{"type": "resize", "cols": 0, "rows": 10}'},
        {"text": '{"type": "resize", "cols": true, "rows": 10}'},
        {"text": '{"type": "resize", "cols": 9999, "rows": 10}'},
        {"bytes": b"x" * 70000},
    ],
)
def test_parse_message_refuses(message):
    with pytest.raises(BadMessage):
        parse_message(message)


def test_parse_message_reads_keys_and_sizes():
    assert parse_message({"bytes": b"ls\r"}) == ("input", b"ls\r")
    assert parse_message({"text": '{"type": "input", "data": "q"}'}) == ("input", b"q")
    assert parse_message({"text": '{"type": "resize", "cols": 80, "rows": 24}'}) == (
        "resize",
        (80, 24),
    )


def test_a_missing_terminal_app_says_so(monkeypatch, make_app):
    app = make_app(ECHO_APP)
    monkeypatch.setattr("reconix_api.api.terminal.default_command", default_command)
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    monkeypatch.setattr("shutil.which", lambda name: None)
    with connect(app, AUTH) as websocket:
        with pytest.raises(WebSocketDisconnect) as closed:
            websocket.receive_bytes()
    assert (closed.value.code, closed.value.reason) == (1011, "TERMINAL_APP_MISSING")
    assert audit_types(app) == ["TERMINAL_REFUSED"]


def test_a_command_that_cannot_start_is_refused_and_audited(make_app):
    app = make_app("", command=["/nonexistent/reconix"])
    with connect(app, AUTH) as websocket:
        with pytest.raises(WebSocketDisconnect) as closed:
            websocket.receive_bytes()
    assert (closed.value.code, closed.value.reason) == (1011, "START_FAILED")
    assert audit_types(app) == ["TERMINAL_REFUSED"]


def test_the_api_settings_never_reach_the_terminal_app(monkeypatch):
    monkeypatch.setenv("RECONIX_JOB_TOKEN_SECRET", "fake-secret")
    monkeypatch.setenv("RECONIX_DATABASE_URL", "postgresql://fake")
    monkeypatch.setenv("RECONIX_DATA_DIR", "tui-data-folder")
    env = child_environment(80, 24)
    assert "RECONIX_JOB_TOKEN_SECRET" not in env and "RECONIX_DATABASE_URL" not in env
    assert env["RECONIX_DATA_DIR"] == "tui-data-folder"


def test_the_default_command_ignores_files_in_the_home_folder():
    command = default_command()
    assert command[0] != sys.executable or "-I" in command


async def test_a_page_that_stops_reading_does_not_fill_memory():
    flood = "import sys\nwhile True: sys.stdout.write('x' * 65536); sys.stdout.flush()"
    terminal = Terminal([sys.executable, "-c", flood], 80, 24)
    await terminal.start()
    try:
        await asyncio.sleep(1)  # nobody reads: the TUI fills the queue, then has to wait
        assert terminal.output.qsize() <= QUEUE_SIZE
        assert not terminal.reading
        await terminal.read()  # the page catches up a little: reading starts again
        assert terminal.reading
    finally:
        await terminal.stop()
