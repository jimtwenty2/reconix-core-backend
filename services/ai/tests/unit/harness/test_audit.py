import json
import stat
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

from reconix_ai.harness.audit import audit_line, make_audit_writer

ASSESSMENT_ID = UUID("11111111-1111-1111-1111-111111111111")
SESSION_ID = UUID("22222222-2222-2222-2222-222222222222")
AT = datetime(2026, 10, 26, 14, 0, tzinfo=UTC)


class Role(StrEnum):
    OPERATOR = "OPERATOR"


@dataclass(frozen=True)
class Event:
    """Same fields as the shared AuditEvent."""

    event_type: str = "ACTION_BLOCKED"
    assessment_id: UUID | None = ASSESSMENT_ID
    session_id: UUID = SESSION_ID
    role: str = Role.OPERATOR
    actor: str = "pojim"
    at: datetime = AT
    details: dict[str, Any] = field(default_factory=dict)


def read_lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_line_has_every_field() -> None:
    record = json.loads(audit_line(Event(details={"reason": "TARGET_OUT_OF_SCOPE"})))
    assert record == {
        "event_type": "ACTION_BLOCKED",
        "assessment_id": "11111111-1111-1111-1111-111111111111",
        "session_id": "22222222-2222-2222-2222-222222222222",
        "role": "OPERATOR",
        "actor": "pojim",
        "at": "2026-10-26T14:00:00+00:00",
        "details": {"reason": "TARGET_OUT_OF_SCOPE"},
    }


def test_event_without_assessment() -> None:
    record = json.loads(audit_line(Event(event_type="SESSION_STARTED", assessment_id=None)))
    assert record["assessment_id"] is None


def test_secrets_in_details_are_masked() -> None:
    line = audit_line(Event(details={"arguments": ["--auth", "password=hunter22"]}))
    assert "hunter22" not in line
    assert json.loads(line)["details"]["arguments"] == [
        "--auth",
        "password=[MASKED:password]",
    ]


def test_newlines_never_break_a_record() -> None:
    line = audit_line(Event(actor="pojim\nFAKE_EVENT", details={"text": "a\nb\r\nc"}))
    assert "\n" not in line
    assert json.loads(line)["details"]["text"] == "a\nb\r\nc"


def test_non_json_values_are_written_as_text() -> None:
    details = {"finding_id": UUID(int=5), "when": AT, "path": Path("/lab/repo")}
    record = json.loads(audit_line(Event(details=details)))
    assert record["details"]["finding_id"] == str(UUID(int=5))
    assert record["details"]["path"] == "/lab/repo"


def test_writer_appends_one_line_per_event(tmp_path: Path) -> None:
    path = tmp_path / "audit" / "audit.jsonl"
    write_audit = make_audit_writer(path)
    write_audit(Event(event_type="ACTION_ALLOWED"))
    write_audit(Event(event_type="ACTION_BLOCKED"))
    assert [record["event_type"] for record in read_lines(path)] == [
        "ACTION_ALLOWED",
        "ACTION_BLOCKED",
    ]


def test_writer_keeps_earlier_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    make_audit_writer(path)(Event(event_type="FIRST"))
    make_audit_writer(path)(Event(event_type="SECOND"))
    assert len(read_lines(path)) == 2


def test_only_the_owner_can_read_the_log(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    make_audit_writer(path)(Event())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_writes_from_many_threads_do_not_mix(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_audit = make_audit_writer(path)
    long_details = {"text": "x" * 5000}

    def write_many() -> None:
        for _ in range(50):
            write_audit(Event(details=long_details))

    threads = [threading.Thread(target=write_many) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(read_lines(path)) == 400
