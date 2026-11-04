import asyncio
import threading
from datetime import UTC, datetime
from uuid import uuid4

from reconix_api.core.interfaces import AuditEvent
from reconix_api.core.live_events import QUEUE_SIZE, LiveEvents


def make_event(**details) -> AuditEvent:
    return AuditEvent(
        event_type="APPROVAL_REQUESTED",
        assessment_id=uuid4(),
        session_id=uuid4(),
        actor="operator",
        at=datetime.now(UTC),
        details=details,
    )


async def test_an_event_from_another_thread_reaches_the_listener():
    live = LiveEvents()
    listener = live.add()
    event = make_event(approval_type="ACTION")
    thread = threading.Thread(target=live.publish, args=(event,))
    thread.start()
    thread.join()
    record = await asyncio.wait_for(listener.get(), 1)
    assert record["event_type"] == "APPROVAL_REQUESTED"
    assert record["assessment_id"] == str(event.assessment_id)
    assert record["details"] == {"approval_type": "ACTION"}


async def test_details_are_masked_again():
    live = LiveEvents()
    listener = live.add()
    live.publish(make_event(output="password=hunter2-not-real"))
    record = await asyncio.wait_for(listener.get(), 1)
    assert "hunter2-not-real" not in str(record)


async def test_publishing_writes_the_line_first_then_publishes():
    live = LiveEvents()
    listener = live.add()
    written = []
    write_audit = live.publishing(written.append)
    event = make_event()
    write_audit(event)
    assert written == [event]
    assert (await asyncio.wait_for(listener.get(), 1))["event_type"] == "APPROVAL_REQUESTED"


async def test_a_failed_write_publishes_nothing():
    live = LiveEvents()
    listener = live.add()

    def broken(_: AuditEvent) -> None:
        raise OSError("disk full")

    try:
        live.publishing(broken)(make_event())
    except OSError:
        pass
    await asyncio.sleep(0)
    assert listener.empty()


async def test_a_listener_that_falls_behind_is_dropped():
    live = LiveEvents()
    listener = live.add()
    for _ in range(QUEUE_SIZE + 1):
        live.publish(make_event())
    await asyncio.sleep(0)
    assert await listener.get() is None  # the stream must end
    live.publish(make_event())
    await asyncio.sleep(0)
    assert listener.empty()


async def test_a_removed_listener_gets_nothing():
    live = LiveEvents()
    listener = live.add()
    live.remove(listener)
    live.publish(make_event())
    await asyncio.sleep(0)
    assert listener.empty()


def test_publish_without_listeners_does_nothing():
    LiveEvents().publish(make_event())
