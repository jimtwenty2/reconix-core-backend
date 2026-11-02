"""Audit trail and operator feedback: record and list what the operator did and said.

The trail spans the whole session (`lists.EVENTS`, `lists.FEEDBACK`), so every row is
tagged with the assessment it happened in. `current_events()`/`current_feedback()` give
the current assessment's rows only — what `/audit` shows, so one run's trail never leaks
into another's. The getters return copies: changing a returned row changes nothing here.
"""

from dataclasses import replace
from typing import List

from ..models import AuditEvent, Feedback
from . import lists
from .errors import StoreValidationError


def current_operator() -> str:
    return lists.current().operator


def _current_label() -> str:
    """The assessment every row logged now belongs to ("" before any exists)."""
    return lists.current().label if lists.ASSESSMENTS else ""


def log_event(kind: str, detail: str = "") -> AuditEvent:
    """Append an audit event such as `scope.approved` or `report.export_requested`."""
    kind = kind.strip()
    if not kind:
        raise StoreValidationError("Event kind is required.")
    event = AuditEvent(kind=kind, operator=current_operator(), detail=detail.strip(),
                       assessment=_current_label())
    lists.EVENTS.append(event)
    return event


def list_events() -> List[AuditEvent]:
    """Every event of the session, oldest first (copies)."""
    return [replace(event) for event in lists.EVENTS]


def current_events() -> List[AuditEvent]:
    """The current assessment's events only (copies). An untagged row never matches."""
    label = _current_label()
    return [replace(event) for event in lists.EVENTS if label and event.assessment == label]


MAX_FEEDBACK_LENGTH = 500


def add_feedback(gate: str, text: str) -> Feedback:
    """Save free text typed at a question (the "Type something." answer)."""
    text = " ".join(text.split())
    if not text:
        raise StoreValidationError("Type some feedback first.")
    if len(text) > MAX_FEEDBACK_LENGTH:
        raise StoreValidationError(f"Keep feedback under {MAX_FEEDBACK_LENGTH} characters.")
    feedback = Feedback(gate=gate, text=text, operator=current_operator(),
                        assessment=_current_label())
    lists.FEEDBACK.append(feedback)
    log_event(f"{gate}.feedback", text)
    return feedback


def list_feedback() -> List[Feedback]:
    """Every answer typed this session, oldest first (copies)."""
    return [replace(entry) for entry in lists.FEEDBACK]


def current_feedback() -> List[Feedback]:
    """The current assessment's answers only (copies)."""
    label = _current_label()
    return [replace(entry) for entry in lists.FEEDBACK if label and entry.assessment == label]
