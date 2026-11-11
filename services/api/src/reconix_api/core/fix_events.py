"""The live transcript of each code fix run, kept in memory for GET /code-fixes/{id}/events.

The API is one process and a fix run is a task in it, so its events live here, not in the
database: they are streamed text, not decisions, and the audit log keeps only the start
and the end. A reader that connects late, or reconnects, gets every event again from the
start (or after the last seq it saw). The events of the last KEEP_RUNS ended runs are
kept; a restart loses them (the run itself ends FAILED INTERRUPTED).

Everything here runs on the event loop, except stop(), which a route on a threadpool
thread may call.
"""

import asyncio
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

KEEP_RUNS = 20  # ended runs whose events are kept
MAX_EVENTS = 20_000  # per run; past it streamed text is dropped, past twice it all is
STREAMED = {"TEXT", "THINKING"}


@dataclass
class FixRun:
    events: list[dict[str, Any]] = field(default_factory=list)
    ended: bool = False
    stop: asyncio.Event = field(default_factory=asyncio.Event)  # set: the run must stop
    changed: asyncio.Event = field(default_factory=asyncio.Event)  # set on each new event
    loop: asyncio.AbstractEventLoop | None = None


class FixEvents:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._runs: OrderedDict[UUID, FixRun] = OrderedDict()

    def open(self, run_id: UUID) -> FixRun:
        run = FixRun(loop=asyncio.get_running_loop())
        with self._lock:
            self._runs[run_id] = run
        return run

    def get(self, run_id: UUID) -> FixRun | None:
        with self._lock:
            return self._runs.get(run_id)

    def add(self, run_id: UUID, file: str | None, kind: str, text: str) -> None:
        """text must already be masked."""
        run = self.get(run_id)
        if run is None or run.ended:
            return
        if len(run.events) >= MAX_EVENTS and (
            kind in STREAMED or len(run.events) >= 2 * MAX_EVENTS
        ):
            return  # past the limit: streamed text first, then everything
        seq = len(run.events) + 1
        run.events.append(
            {"agent_run_id": str(run_id), "seq": seq, "file": file, "kind": kind, "text": text}
        )
        self._wake(run)

    def end(self, run_id: UUID) -> None:
        run = self.get(run_id)
        if run is None:
            return
        run.ended = True
        self._wake(run)
        with self._lock:
            ended = [key for key, value in self._runs.items() if value.ended]
            for key in ended[:-KEEP_RUNS]:
                del self._runs[key]

    def stop(self, run_id: UUID) -> None:
        """Safe from any thread: tells the run to stop at once."""
        run = self.get(run_id)
        if run is None or run.loop is None:
            return
        try:
            run.loop.call_soon_threadsafe(run.stop.set)
        except RuntimeError:
            pass  # the loop has closed: the server is stopping, nothing is running

    async def wait(self, run_id: UUID, after: int, timeout: float) -> list[dict[str, Any]]:
        """The events after seq `after`; waits up to timeout seconds for one when there
        is none yet. Empty: nothing new (or the run is unknown or ended)."""
        run = self.get(run_id)
        if run is None:
            return []
        if len(run.events) <= after and not run.ended:
            run.changed.clear()
            try:
                await asyncio.wait_for(run.changed.wait(), timeout)
            except TimeoutError:
                return []
        return run.events[after:]

    def _wake(self, run: FixRun) -> None:
        run.changed.set()


FIX_EVENTS = FixEvents()
