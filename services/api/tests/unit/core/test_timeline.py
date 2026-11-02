"""core/timeline.py over lines written by the real harness writer, so a change to the
audit line format fails here."""

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest

from reconix_ai.harness import make_audit_writer
from reconix_api.core import timeline
from reconix_api.core.errors import ApiError

ASSESSMENT = uuid4()
START = datetime(2026, 10, 30, 9, 0, tzinfo=UTC)


@dataclass(frozen=True)
class Event:
    event_type: str
    assessment_id: UUID | None
    session_id: UUID = field(default_factory=uuid4)
    actor: str = "operator"
    at: datetime = START
    details: dict[str, Any] = field(default_factory=dict)


def write(path, count: int, assessment_id: UUID | None = ASSESSMENT, **fields) -> None:
    write_audit = make_audit_writer(path)
    for n in range(count):
        at = START + timedelta(seconds=n)
        write_audit(Event("TOOL_RUN_STARTED", assessment_id, at=at, details={"n": n}, **fields))


def test_the_real_writers_lines_come_back_oldest_first(tmp_path):
    log = tmp_path / "audit.jsonl"
    write(log, 3)
    write(log, 2, assessment_id=uuid4())  # another assessment's
    write(log, 1, assessment_id=None)  # a session's, before any assessment

    events, has_older = timeline.read(log, ASSESSMENT, [], limit=10)

    assert [event["details"]["n"] for event in events] == [0, 1, 2]
    assert set(events[0]) == {"event_type", "assessment_id", "session_id", "actor", "at", "details"}
    assert has_older is False


def test_the_newest_are_kept_and_has_older_says_so(tmp_path):
    log = tmp_path / "audit.jsonl"
    write(log, 5)

    events, has_older = timeline.read(log, ASSESSMENT, [], limit=2)

    assert [event["details"]["n"] for event in events] == [3, 4]
    assert has_older is True


def test_secrets_are_masked(tmp_path):
    log = tmp_path / "audit.jsonl"
    write(log, 1, actor="password=hunter2-actor")
    log.write_text(log.read_text().replace('"n": 0', '"password": "hunter2-detail"'))

    events, _ = timeline.read(log, ASSESSMENT, [], limit=10)

    assert "hunter2" not in str(events)


def test_no_log_yet_is_no_events(tmp_path):
    assert timeline.read(tmp_path / "missing.jsonl", ASSESSMENT, [], limit=10) == ([], False)


def test_a_symlink_at_the_log_path_is_a_503_not_a_crash(tmp_path):
    real = tmp_path / "real.jsonl"
    write(real, 1)
    link = tmp_path / "audit.jsonl"
    link.symlink_to(real)

    with pytest.raises(ApiError) as raised:
        timeline.read(link, ASSESSMENT, [], limit=10)

    assert (raised.value.status, raised.value.code) == (503, "AUDIT_LOG_UNREADABLE")
