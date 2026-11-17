import errno
import json
import os
import stat
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from reconix_ai.harness.audit import audit_line, make_audit_writer, read_timeline

ASSESSMENT_ID = UUID("11111111-1111-1111-1111-111111111111")
SESSION_ID = UUID("22222222-2222-2222-2222-222222222222")
AT = datetime(2026, 10, 26, 14, 0, tzinfo=UTC)
OTHER_ID = UUID("33333333-3333-3333-3333-333333333333")


@dataclass(frozen=True)
class Event:
    """Same fields as the shared AuditEvent."""

    event_type: str = "ACTION_BLOCKED"
    assessment_id: UUID | None = ASSESSMENT_ID
    session_id: UUID = SESSION_ID
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
    assert record["details"]["when"] == "2026-10-26T14:00:00+00:00"
    assert record["details"]["path"] == "/lab/repo"


def test_secret_key_names_in_details_are_masked() -> None:
    line = audit_line(Event(details={"password": "hunter22", "raw": b"token=abcdefgh"}))
    assert "hunter22" not in line
    assert "abcdefgh" not in line


def test_secret_in_actor_is_masked() -> None:
    record = json.loads(audit_line(Event(actor="password=hunter22")))
    assert record["actor"] == "password=[MASKED:password]"


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


def test_writer_refuses_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.txt"
    target.write_text("")
    path = tmp_path / "audit.jsonl"
    path.symlink_to(target)
    with pytest.raises(OSError):
        make_audit_writer(path)(Event())
    assert target.read_text() == ""


def test_writer_tightens_rights_on_an_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    path.write_text("")
    path.chmod(0o644)
    make_audit_writer(path)(Event())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_writer_ignores_unsupported_filesystem_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"

    def fake_fchmod(fd: int, mode: int) -> None:
        raise OSError(errno.ENOTSUP, "Operation not supported")

    monkeypatch.setattr(os, "fchmod", fake_fchmod, raising=False)
    make_audit_writer(path)(Event(event_type="TEST"))
    assert len(read_lines(path)) == 1


def test_writer_raises_and_closes_descriptor_on_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "audit.jsonl"
    closed_fds: list[int] = []
    orig_close = os.close
    monkeypatch.setattr(os, "close", lambda fd: (closed_fds.append(fd), orig_close(fd)))

    def fake_fchmod(fd: int, mode: int) -> None:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "fchmod", fake_fchmod, raising=False)

    with pytest.raises(OSError) as exc_info:
        make_audit_writer(path)(Event(event_type="TEST"))

    assert exc_info.value.errno == errno.EPERM
    assert len(closed_fds) == 1


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


# --- read_timeline ---------------------------------------------------------------------


def write_events(path: Path, *events: Event) -> None:
    write_audit = make_audit_writer(path)
    for event in events:
        write_audit(event)


def test_timeline_keeps_only_one_assessment(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(
        path,
        Event(event_type="ACTION_ALLOWED"),
        Event(event_type="OTHER", assessment_id=OTHER_ID),
        Event(event_type="SESSION_STARTED", assessment_id=None),
        Event(event_type="ACTION_BLOCKED"),
    )
    timeline = read_timeline(path, ASSESSMENT_ID)
    assert [event["event_type"] for event in timeline] == ["ACTION_ALLOWED", "ACTION_BLOCKED"]


def test_timeline_record_has_the_written_fields(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(path, Event(details={"reason": "TARGET_OUT_OF_SCOPE"}))
    assert read_timeline(path, str(ASSESSMENT_ID)) == [
        json.loads(audit_line(Event(details={"reason": "TARGET_OUT_OF_SCOPE"})))
    ]


def test_timeline_is_oldest_first(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    later = datetime(2026, 10, 26, 15, 0, tzinfo=UTC)
    write_events(path, Event(event_type="LATER", at=later), Event(event_type="EARLIER"))
    assert [event["event_type"] for event in read_timeline(path, ASSESSMENT_ID)] == [
        "EARLIER",
        "LATER",
    ]


def test_same_time_keeps_file_order(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(path, *(Event(event_type=f"E{number}") for number in range(5)))
    assert [event["event_type"] for event in read_timeline(path, ASSESSMENT_ID)] == [
        f"E{number}" for number in range(5)
    ]


def test_naive_and_aware_times_sort_together(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(
        path,
        Event(event_type="LATER", at=datetime(2026, 10, 26, 15, 0)),
        Event(event_type="EARLIER"),
    )
    assert [event["event_type"] for event in read_timeline(path, ASSESSMENT_ID)] == [
        "EARLIER",
        "LATER",
    ]


def test_timeline_filters_event_types(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(
        path,
        Event(event_type="ACTION_ALLOWED"),
        Event(event_type="APPROVAL_GRANTED"),
        Event(event_type="ACTION_BLOCKED"),
    )
    timeline = read_timeline(
        path, ASSESSMENT_ID, event_types=["ACTION_BLOCKED", "APPROVAL_GRANTED"]
    )
    assert [event["event_type"] for event in timeline] == ["APPROVAL_GRANTED", "ACTION_BLOCKED"]


def test_limit_keeps_the_newest_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(path, *(Event(event_type=f"E{number}") for number in range(5)))
    assert [event["event_type"] for event in read_timeline(path, ASSESSMENT_ID, limit=2)] == [
        "E3",
        "E4",
    ]


@pytest.mark.parametrize("limit", [0, -1])
def test_limit_must_be_positive(tmp_path: Path, limit: int) -> None:
    with pytest.raises(ValueError):
        read_timeline(tmp_path / "audit.jsonl", ASSESSMENT_ID, limit=limit)


def test_missing_log_is_an_empty_timeline(tmp_path: Path) -> None:
    assert read_timeline(tmp_path / "nothing-yet.jsonl", ASSESSMENT_ID) == []


def test_broken_lines_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(path, Event(event_type="FIRST"))
    record = json.loads(audit_line(Event()))
    bad_lines = [
        "",
        "not json",
        '{"event_type": "HALF',
        "[1, 2]",
        "42",
        json.dumps({**record, "at": "yesterday"}),
        json.dumps({**record, "details": "not a dict"}),
        json.dumps({key: value for key, value in record.items() if key != "actor"}),
        "\xff\xfe",
    ]
    with path.open("a", encoding="utf-8", errors="surrogateescape") as file:
        file.write("\n".join(bad_lines) + "\n")
    with path.open("ab") as file:
        file.write(b"\xff\xfe broken bytes\n")
    write_events(path, Event(event_type="LAST"))
    assert [event["event_type"] for event in read_timeline(path, ASSESSMENT_ID)] == [
        "FIRST",
        "LAST",
    ]


def test_extra_fields_in_a_line_are_dropped(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    record = {**json.loads(audit_line(Event())), "raw_output": "anything"}
    path.write_text(json.dumps(record) + "\n")
    assert "raw_output" not in read_timeline(path, ASSESSMENT_ID)[0]


def test_timeline_masks_a_line_added_by_hand(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    record = json.loads(audit_line(Event()))
    record["actor"] = "password=hunter22"
    record["details"] = {"token": "abcdefgh1234", "note": "password=hunter22"}
    path.write_text(json.dumps(record) + "\n")
    text = json.dumps(read_timeline(path, ASSESSMENT_ID))
    assert "hunter22" not in text
    assert "abcdefgh1234" not in text


def test_timeline_does_not_change_masked_lines(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    write_events(path, Event(details={"arguments": ["--auth", "password=hunter22"]}))
    assert read_timeline(path, ASSESSMENT_ID)[0]["details"]["arguments"] == [
        "--auth",
        "password=[MASKED:password]",
    ]


def test_timeline_refuses_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.jsonl"
    write_events(target, Event())
    path = tmp_path / "audit.jsonl"
    path.symlink_to(target)
    with pytest.raises(OSError):
        read_timeline(path, ASSESSMENT_ID)
