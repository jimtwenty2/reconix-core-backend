"""GET /stream end to end in one process, with the fakes."""

import threading
import time
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from reconix_api.core.config import Settings, get_settings
from reconix_api.core.interfaces import AuditEvent
from reconix_api.main import create_app
from tests.fakes import OPERATOR_TOKEN, build_fake_interfaces, fake_mask_secrets

HEADERS = {"Authorization": f"Bearer {OPERATOR_TOKEN}"}


@pytest.fixture
def stream_app():
    """Its own app: this folder's `client` fixture is the knowledge one."""
    interfaces, parts = build_fake_interfaces()
    app = create_app(interfaces, mask_secrets=fake_mask_secrets)
    app.dependency_overrides[get_settings] = lambda: Settings(stream_heartbeat_seconds=0.02)
    app.state.parts = parts
    return app


@pytest.fixture
def stream_client(stream_app):
    return TestClient(stream_app, base_url="http://127.0.0.1/api/v1")


def write_then_sign_out(app, operators, events: list[AuditEvent]) -> threading.Thread:
    """Waits for the stream to listen, writes the events, then closes the session."""

    def run() -> None:
        live = app.state.live_events
        deadline = time.monotonic() + 5
        while not live._listeners and time.monotonic() < deadline:
            time.sleep(0.01)
        for event in events:
            app.state.interfaces.write_audit(event)
        time.sleep(0.05)
        operators.tokens.pop(OPERATOR_TOKEN)

    thread = threading.Thread(target=run)
    thread.start()
    return thread


def make_event(event_type: str, assessment_id=None) -> AuditEvent:
    return AuditEvent(
        event_type=event_type,
        assessment_id=assessment_id,
        session_id=uuid4(),
        actor="operator",
        at=datetime.now(UTC),
        details={},
    )


def test_the_stream_sends_audit_events_until_the_session_closes(stream_app, stream_client):
    parts = stream_app.state.parts
    assessment_id = uuid4()
    events = [make_event("APPROVAL_REQUESTED", assessment_id), make_event("SESSION_OPENED")]
    thread = write_then_sign_out(stream_app, parts["operators"], events)

    response = stream_client.get("/stream", headers=HEADERS)
    thread.join()

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert "event: APPROVAL_REQUESTED" in response.text
    assert "event: SESSION_OPENED" in response.text
    assert len(parts["audit"].events) == 2  # still one audit line per event


def test_the_assessment_filter(stream_app, stream_client):
    parts = stream_app.state.parts
    wanted = uuid4()
    events = [make_event("TOOL_RUN_STARTED", uuid4()), make_event("TOOL_RUN_FINISHED", wanted)]
    thread = write_then_sign_out(stream_app, parts["operators"], events)

    response = stream_client.get("/stream", params={"assessment_id": str(wanted)}, headers=HEADERS)
    thread.join()

    assert "TOOL_RUN_FINISHED" in response.text
    assert "TOOL_RUN_STARTED" not in response.text


def test_no_token_gets_401(stream_client):
    assert stream_client.get("/stream").status_code == 401
