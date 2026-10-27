"""JSON-lines audit log.

Every decision writes exactly one line. The web timeline reads these lines
back (week 2), so the field names must stay stable.

The API wires the real write_audit like this:

    write_audit = make_audit_writer(settings.audit_log_path)
"""

import json
import os
import threading
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, Protocol
from uuid import UUID

from reconix_ai.harness.masking import mask_value


class AuditRecord(Protocol):
    """The fields of the shared AuditEvent this writer needs."""

    @property
    def event_type(self) -> str: ...
    @property
    def assessment_id(self) -> UUID | None: ...
    @property
    def session_id(self) -> UUID: ...
    @property
    def role(self) -> str: ...
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
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as file:
                file.write(line + "\n")

    return write_audit


def audit_line(event: AuditRecord) -> str:
    """One JSON object on one line. Details are masked again, in case a caller forgot."""
    details, _ = mask_value(dict(event.details))
    record = {
        "event_type": str(event.event_type),
        "assessment_id": str(event.assessment_id) if event.assessment_id else None,
        "session_id": str(event.session_id),
        "role": str(event.role),
        "actor": str(event.actor),
        "at": event.at.isoformat(),
        "details": details,
    }
    # ensure_ascii keeps Khmer and other text as \u escapes, and json never
    # writes a raw newline, so a record can never break into two lines.
    return json.dumps(record, default=str, ensure_ascii=True)
