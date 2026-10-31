"""An assessment's timeline: the harness's audit log lines for it.

The reader is the harness's read_timeline (owner: the harness). Like core/agent.py for
the agent, this is the one place the API calls it. A log that cannot be read is a 503,
never a crash.
"""

from pathlib import Path
from typing import Any
from uuid import UUID

from reconix_ai import harness
from reconix_api.core.errors import ApiError


def read(
    path: str | Path, assessment_id: UUID, event_types: list[str], limit: int
) -> tuple[list[dict[str, Any]], bool]:
    """(events, has_older): oldest first, the newest `limit` of them; has_older is True
    when older ones were left out. No log yet: no events."""
    try:
        events = harness.read_timeline(path, assessment_id, event_types or None, limit + 1)
    except (OSError, RecursionError):  # a symlink at the log path, a hostile line
        raise ApiError(503, "AUDIT_LOG_UNREADABLE", "The audit log cannot be read.") from None
    return events[-limit:], len(events) > limit
