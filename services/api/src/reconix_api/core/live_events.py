"""Live updates: every audit event, sent to the screens listening on GET /stream.

The API is one process, so the listeners live in memory. Routes run on threadpool threads,
so publish() hands each event to the event loop that serves the streams.

A listener that falls too far behind is dropped: its stream ends, and the screen
reconnects and reloads its lists.
"""

import asyncio
import json
import logging
import threading
from typing import Any

from reconix_ai.harness.audit import audit_line
from reconix_api.core.interfaces import AuditEvent, WriteAudit

logger = logging.getLogger(__name__)

QUEUE_SIZE = 100  # events a listener may fall behind before it is dropped

Listener = asyncio.Queue[dict[str, Any] | None]  # None: the stream must end


class LiveEvents:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._listeners: set[Listener] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def add(self) -> Listener:
        """A queue of masked audit records; None in it means the listener was dropped.
        Call on the event loop, and always remove() it when the stream ends."""
        listener: Listener = asyncio.Queue(maxsize=QUEUE_SIZE)
        with self._lock:
            self._loop = asyncio.get_running_loop()
            self._listeners.add(listener)
        return listener

    def remove(self, listener: Listener) -> None:
        with self._lock:
            self._listeners.discard(listener)

    def publish(self, event: AuditEvent) -> None:
        """Safe from any thread. Masked again by the same code that writes the audit log."""
        with self._lock:
            listeners = list(self._listeners)
            loop = self._loop
        if not listeners or loop is None:
            return
        record = json.loads(audit_line(event))
        for listener in listeners:
            try:
                loop.call_soon_threadsafe(self._deliver, listener, record)
            except RuntimeError:
                # The loop has closed (the server is stopping): nobody is listening.
                return

    def publishing(self, write_audit: WriteAudit) -> WriteAudit:
        """write_audit that also publishes, only after the line was written."""

        def write_and_publish(event: AuditEvent) -> None:
            write_audit(event)
            try:
                self.publish(event)
            except Exception:
                # The line is written: a live update must never fail the decision.
                logger.exception("Could not publish an audit event to the live stream")

        return write_and_publish

    def _deliver(self, listener: Listener, record: dict[str, Any]) -> None:
        """Runs on the event loop."""
        try:
            listener.put_nowait(record)
        except asyncio.QueueFull:
            with self._lock:
                self._listeners.discard(listener)
            while not listener.empty():
                listener.get_nowait()
            listener.put_nowait(None)
