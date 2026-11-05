"""The live output's grouping: messages stay, the steps between them fold into thinking blocks.

The web ports `group_stream` (web/src/lib/data/thinking.ts); both test suites check the same
cases (web/tests/thinking-vectors.json), so the two stay in step.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

import pytest

from reconix import store
from reconix.models import ActivityEntry, ChatEntry, Entry, MessageItem, ThinkingItem

from .support import decide, play_until_gate
from .support import DEMO_REQUEST

VECTORS = json.loads(
    (Path(__file__).parents[2] / "web" / "tests" / "thinking-vectors.json").read_text("utf-8")
)


def _entry(row: Dict[str, Any]) -> Entry:
    """A saved timeline row (the snapshot's shape) as the store's entry."""
    at = datetime.fromisoformat(row["at"])
    if row["type"] == "activity":
        return ActivityEntry(row["who"], row["text"], row["tone"], created_at=at, seq=row["seq"])
    return ChatEntry(
        row["kind"],
        row["who"],
        row["text"],
        row["tone"],
        tuple(tuple(r) for r in row["rows"]),
        created_at=at,
        seq=row["seq"],
    )


def _shape(items) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, MessageItem):
            out.append({"type": "message", "seq": item.entry.seq})
        else:
            out.append(
                {
                    "type": "block",
                    "key": item.key,
                    "seqs": [s.seq for s in item.steps],
                    "state": item.state,
                    "verb": item.verb,
                    "seconds": item.seconds,
                    "blocked": item.blocked,
                }
            )
    return out


@pytest.mark.parametrize("case", VECTORS, ids=[case["name"] for case in VECTORS])
def test_the_web_port_groups_the_same_way(case):
    items = store.group_stream(
        [_entry(r) for r in case["entries"]], case["live"], now=datetime.fromisoformat(case["now"])
    )
    assert _shape(items) == case["expected"]


def test_an_unknown_run_state_is_refused():
    with pytest.raises(store.StoreValidationError):
        store.group_stream([], "thinking")


def test_a_demo_run_reads_as_messages_with_folded_work():
    store.start_run(DEMO_REQUEST)
    gate = play_until_gate()
    while gate:
        decide(gate)
        gate = play_until_gate()
    items = store.group_stream(store.stream(), "done")
    blocks = [i for i in items if isinstance(i, ThinkingItem)]
    messages = [i for i in items if isinstance(i, MessageItem)]
    assert blocks and messages
    assert all(b.state == "done" for b in blocks)
    assert sum(len(b.steps) for b in blocks) + len(messages) == len(store.stream())
    assert any(b.verb == "Worked" for b in blocks)


def test_a_running_block_counts_its_time_up_to_now():
    first = ActivityEntry(
        "TOOL", "scan", created_at=datetime.fromisoformat("2026-10-28T07:00:00+00:00"), seq=1
    )
    (block,) = store.group_stream(
        [first], "running", now=datetime.fromisoformat("2026-10-28T07:00:09+00:00")
    )
    later = datetime.fromisoformat("2026-10-28T07:01:00+00:00")
    assert block.seconds == 9 and store.block_seconds(block, later) == 60
    block.state = "done"
    assert store.block_seconds(block, later) == 9
