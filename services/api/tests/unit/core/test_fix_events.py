"""The in-memory transcript of code fix runs: order, replay after a seq, waiting, limits."""

import asyncio
from uuid import uuid4

from reconix_api.core import fix_events
from reconix_api.core.fix_events import FixEvents


async def test_events_are_numbered_and_replayed_after_a_seq():
    events, run_id = FixEvents(), uuid4()
    events.open(run_id)
    for kind in ("START", "TOOL", "DONE"):
        events.add(run_id, "a.py", kind, kind.lower())
    got = await events.wait(run_id, 0, 0.01)
    assert [(e["seq"], e["kind"]) for e in got] == [(1, "START"), (2, "TOOL"), (3, "DONE")]
    assert got[0] == {
        "agent_run_id": str(run_id),
        "seq": 1,
        "file": "a.py",
        "kind": "START",
        "text": "start",
    }
    assert [e["seq"] for e in await events.wait(run_id, 2, 0.01)] == [3]


async def test_a_reader_waits_for_the_next_event():
    events, run_id = FixEvents(), uuid4()
    events.open(run_id)
    reader = asyncio.create_task(events.wait(run_id, 0, 5))
    await asyncio.sleep(0)
    events.add(run_id, None, "STATUS", "Checking")
    assert [e["text"] for e in await reader] == ["Checking"]
    assert await events.wait(run_id, 1, 0.01) == []  # nothing new: a heartbeat


async def test_an_ended_run_takes_no_more_events_and_wakes_its_readers():
    events, run_id = FixEvents(), uuid4()
    events.open(run_id)
    reader = asyncio.create_task(events.wait(run_id, 0, 5))
    await asyncio.sleep(0)
    events.end(run_id)
    assert await reader == []
    events.add(run_id, None, "STATUS", "late")
    assert events.get(run_id).events == []
    assert await events.wait(uuid4(), 0, 0.01) == []  # an unknown run


async def test_stop_is_safe_from_another_thread():
    events, run_id = FixEvents(), uuid4()
    run = events.open(run_id)
    await asyncio.to_thread(events.stop, run_id)
    await asyncio.wait_for(run.stop.wait(), 1)
    events.stop(uuid4())  # an unknown run: nothing happens


async def test_only_the_last_ended_runs_are_kept(monkeypatch):
    monkeypatch.setattr(fix_events, "KEEP_RUNS", 2)
    events = FixEvents()
    ids = [uuid4() for _ in range(4)]
    for run_id in ids:
        events.open(run_id)
    running = ids[0]
    for run_id in ids[1:]:
        events.end(run_id)
    assert events.get(running) is not None  # a running run is never dropped
    assert events.get(ids[1]) is None
    assert events.get(ids[2]) is not None and events.get(ids[3]) is not None


async def test_streamed_text_is_dropped_past_the_limit(monkeypatch):
    monkeypatch.setattr(fix_events, "MAX_EVENTS", 2)
    events, run_id = FixEvents(), uuid4()
    events.open(run_id)
    for kind in ("TEXT", "TEXT", "THINKING", "TEXT", "DONE"):
        events.add(run_id, "a.py", kind, "x")
    assert [e["kind"] for e in events.get(run_id).events] == ["TEXT", "TEXT", "DONE"]
