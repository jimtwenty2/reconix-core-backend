"""JSON-lines audit log.

Every decision writes exactly one line. The web timeline reads these lines
back with read_timeline(), so the field names must stay stable.

The API wires the real write_audit like this:

    write_audit = make_audit_writer(settings.audit_log_path)

and GET /assessments/{id}/timeline returns:

    read_timeline(settings.audit_log_path, assessment_id)
"""

import errno
import json
import os
import threading
from collections.abc import Callable, Collection, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from reconix_ai.harness.masking import mask_secrets, mask_value


class AuditRecord(Protocol):
    """The fields of the shared AuditEvent this writer needs."""

    @property
    def event_type(self) -> str: ...
    @property
    def assessment_id(self) -> UUID | None: ...
    @property
    def session_id(self) -> UUID: ...
    @property
    def actor(self) -> str: ...
    @property
    def at(self) -> datetime: ...
    @property
    def details(self) -> Mapping[str, Any]: ...


def make_audit_writer(path: str | Path) -> Callable[[AuditRecord], None]:
    """Return a write_audit function that appends to the given file."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    def write_audit(event: AuditRecord) -> None:
        line = audit_line(event)
        with lock:
            # 0o600: only the user running Reconix can read the audit log.
            # O_NOFOLLOW: never write through a symlink planted at the log path.
            flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags, 0o600)
            try:
                if hasattr(os, "fchmod"):
                    try:
                        os.fchmod(
                            descriptor, 0o600
                        )  # also fixes a file made earlier with other rights
                    except OSError as error:
                        if error.errno not in (
                            errno.ENOTSUP,
                            errno.EOPNOTSUPP,
                            errno.ENOSYS,
                            errno.EINVAL,
                            errno.EPERM,
                        ):
                            raise
            except BaseException:
                os.close(descriptor)
                raise
            with os.fdopen(descriptor, "a", encoding="utf-8") as file:
                file.write(line + "\n")

    return write_audit


def audit_line(event: AuditRecord) -> str:
    """One JSON object on one line. Actor and details are masked again, in case a caller forgot."""
    details, _ = mask_value(dict(event.details))
    actor, _ = mask_secrets(str(event.actor))
    record = {
        "event_type": str(event.event_type),
        "assessment_id": str(event.assessment_id) if event.assessment_id else None,
        "session_id": str(event.session_id),
        "actor": actor,
        "at": event.at.isoformat(),
        "details": details,
    }
    # ensure_ascii keeps Khmer and other text as \u escapes, and json never
    # writes a raw newline, so a record can never break into two lines.
    # mask_value already turned every value into plain JSON, so no default=str
    # is needed; an unknown type fails loudly instead of being written unmasked.
    return json.dumps(record, ensure_ascii=True)


RECORD_FIELDS = ("event_type", "assessment_id", "session_id", "actor", "at", "details")


def read_timeline(
    path: str | Path,
    assessment_id: UUID | str,
    event_types: Collection[str] | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return the audit lines of one assessment, oldest first.

    Broken or foreign lines are skipped, never fatal. A missing log means no
    events yet. With a limit, the newest `limit` lines are kept.
    """
    if limit is not None and limit < 1:
        raise ValueError("limit must be at least 1")
    wanted = str(assessment_id)
    types = {str(event_type) for event_type in event_types} if event_types else None
    try:
        # O_NOFOLLOW: never read a symlink planted at the log path.
        descriptor = os.open(Path(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except FileNotFoundError:
        return []
    with os.fdopen(descriptor, encoding="utf-8", errors="replace") as file:
        records = [record for line in file if (record := parse_line(line)) is not None]
    events = [
        record
        for record in records
        if record["assessment_id"] == wanted and (types is None or record["event_type"] in types)
    ]
    # Lines are appended in time order; sorting by time (stable) only fixes
    # writes that raced across threads.
    events.sort(key=lambda record: record["_at"])
    if limit is not None:
        events = events[-limit:]
    for record in events:
        del record["_at"]
    return events


def parse_line(line: str) -> dict[str, Any] | None:
    """One audit line as a dict, or None when it is broken or not an audit record."""
    try:
        record = json.loads(line)
        at = datetime.fromisoformat(record["at"])
    except (ValueError, TypeError, KeyError):
        return None
    if not all(name in record for name in RECORD_FIELDS) or not isinstance(record["details"], dict):
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=UTC)  # so naive and aware times sort together
    # Mask again on the way out, in case a line was added to the file by hand.
    details, _ = mask_value(record["details"])
    actor, _ = mask_secrets(str(record["actor"]))
    event = {name: record[name] for name in RECORD_FIELDS}
    event.update(details=details, actor=actor, _at=at)
    return event
