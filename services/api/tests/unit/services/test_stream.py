import asyncio
import json
from uuid import uuid4

from reconix_api.core.interfaces import Operator
from reconix_api.services import stream

TOKEN = "fake-stream-token"  # noqa: S105


def record(assessment_id=None) -> dict:
    return {
        "event_type": "TOOL_RUN_FINISHED",
        "assessment_id": str(assessment_id) if assessment_id else None,
        "session_id": str(uuid4()),
        "actor": "operator",
        "at": "2026-11-02T10:00:00+00:00",
        "details": {"status": "COMPLETED"},
    }


class Tokens:
    def __init__(self) -> None:
        self.valid = True

    def get_operator(self, token: str) -> Operator:
        if not self.valid or token != TOKEN:
            raise PermissionError("UNKNOWN_TOKEN")
        return Operator(session_id=uuid4(), actor="operator")


async def still_connected() -> bool:
    return False


async def collect(listener, tokens, assessment_id=None, heartbeat=0.01, limit=10) -> list[str]:
    parts = []
    frames = stream.frames(
        listener, tokens.get_operator, TOKEN, assessment_id, heartbeat, still_connected
    )
    async for part in frames:
        parts.append(part)
        if len(parts) >= limit:
            break
    return parts


def test_a_frame_names_the_event_and_holds_one_json_line():
    event = record()
    event["details"] = {"note": "two\nlines"}
    text = stream.frame(event)
    event_line, data_line, end = text.split("\n", 2)
    assert event_line == "event: TOOL_RUN_FINISHED"
    assert json.loads(data_line.removeprefix("data: ")) == event
    assert end == "\n"


async def test_events_are_sent_and_the_stream_ends_when_dropped():
    listener = asyncio.Queue()
    listener.put_nowait(record())
    listener.put_nowait(None)
    parts = await collect(listener, Tokens())
    assert len(parts) == 1
    assert parts[0].startswith("event: TOOL_RUN_FINISHED\n")


async def test_only_the_wanted_assessment_is_sent():
    wanted = uuid4()
    listener = asyncio.Queue()
    for event in (record(uuid4()), record(None), record(wanted), None):
        listener.put_nowait(event)
    parts = await collect(listener, Tokens(), assessment_id=wanted)
    assert len(parts) == 1
    assert str(wanted) in parts[0]


async def test_a_quiet_stream_sends_pings():
    parts = await collect(asyncio.Queue(), Tokens(), limit=2)
    assert parts == [stream.PING, stream.PING]


async def test_the_stream_ends_when_the_session_closes():
    tokens = Tokens()
    tokens.valid = False
    listener = asyncio.Queue()
    listener.put_nowait(record())
    assert await collect(listener, tokens) == []


async def test_the_stream_ends_when_the_client_leaves():
    async def gone() -> bool:
        return True

    frames = stream.frames(asyncio.Queue(), Tokens().get_operator, TOKEN, None, 0.01, gone)
    assert [part async for part in frames] == []
