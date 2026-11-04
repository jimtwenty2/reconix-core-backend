"""The current assessment, the operator's typed requests, and the session's assessments."""

from dataclasses import dataclass
from typing import List

from ..models import Assessment, UserRequest
from . import lists
from .activity import log_event
from .errors import StoreValidationError
from .redact import HIDDEN_LINE, clean, escaped_secret, redact

MAX_REQUEST_LENGTH = 500


def get_assessment() -> Assessment:
    """The current assessment itself, live.

    This is the store's internal mutation seam (with `run.get_run()`): the store changes the
    assessment through it, so it is not a copy. The list getters built on it —
    `list_assessments()`, `list_findings()`, `get_finding()`, `list_activity()`,
    `list_events()` — do return copies, and screens read those.
    """
    return lists.current()


def assessment_label() -> str:
    """The assessment id once the scope is approved, else ""."""
    return get_assessment().assessment_id


# --- the session's assessments (create, list, reopen) -----------------------------------------
@dataclass
class AssessmentCard:
    """One row in the assessments list."""

    index: int
    label: str
    target: str
    template: str
    status: str          # New | Running | Awaiting input | Completed | Stopped
    findings: int
    current: bool


def assessment_status(assessment: Assessment) -> str:
    run = assessment.run
    if run.stopped:
        return "Stopped"
    if run.completed:
        return "Completed"
    if not run.started:
        return "New"
    if run.waiting_gate:
        return "Awaiting input"
    return "Running"


def list_assessments() -> List[AssessmentCard]:
    from .templates import template_name
    current_index = lists.CURRENT[0]
    cards = []
    for index, assessment in enumerate(lists.ASSESSMENTS):
        revealed = set(assessment.run.revealed)
        cards.append(AssessmentCard(
            index=index, label=assessment.label, target=assessment.target or "—",
            template=template_name(assessment.template_id) if assessment.template_id else "—",
            status=assessment_status(assessment),
            findings=sum(1 for f in assessment.findings if f.fid in revealed),
            current=index == current_index,
        ))
    return cards


def is_empty_assessment() -> bool:
    """The current assessment is still as built: no target, template, scope or run, and
    nothing the operator typed, decided or found. A new one would only repeat it."""
    a = lists.current()
    return (not a.target and not a.template_id and not a.selected_template
            and not a.run.started and a.scope is None and a.api_spec is None
            and not (a.requests or a.findings or a.approvals or a.decisions or a.vault)
            and all(entry.speaker != "you" for entry in a.chat)
            and all(entry.source != "USER" for entry in a.activity))


def switch_assessment(index: int) -> None:
    """Make another assessment the current one (reopen a past one)."""
    from .persist import autosave       # (imported here: persist depends on this module)

    autosave()                          # keep the one we leave up to date on disk
    try:
        lists.set_current(index)
    except IndexError:
        raise StoreValidationError("No such assessment.") from None
    log_event("assessment.switched", lists.current().label)


def list_requests() -> List[UserRequest]:
    return list(lists.current().requests)


# A typed line refused because control codes (colour codes, invisible characters…) sit in it
# next to a secret: with a code inside a word, neither the spaced form ("pass word=…") nor the
# glued one ("10.0.0.1token=…") can be masked reliably (`redact.escaped_secret`).
ESCAPED_SECRET = (
    "Remove the colour or control codes from the line and type it again: it holds a "
    "password, token or key."
)


def refuse_escaped_secret(text: str) -> None:
    """Raise for a typed line that holds control codes and a secret: it is never kept."""
    if escaped_secret(text):
        raise StoreValidationError(ESCAPED_SECRET)


def fold_line(text: str) -> str:
    """`text` with every control byte and escape sequence turned into a space (`clean`), its
    whitespace folded. So "10.0.0.1<ESC>[31mred" is "10.0.0.1 red", not one word the target
    parser can't read. Never raises: a line with control codes and a secret comes back as
    `HIDDEN_LINE`. Typed lines are refused before that (`refuse_escaped_secret`).
    """
    if escaped_secret(text):
        return HIDDEN_LINE
    return " ".join(clean(text).split())


def shown_line(text: str) -> str:
    """Typed text as an error message may repeat it: folded and masked. Never raises."""
    return redact(fold_line(text))


def clean_request(text: str) -> str:
    """A typed line without control bytes or escape sequences (BEL, ESC, NUL…), its
    whitespace folded; raises if it is empty or too long.

    The result can still hold a secret (https://user:pass@host): the target parser reads it
    as typed, and `recorded_line()` masks it before it is stored, shown or logged. A line
    with control codes and a secret is refused (`refuse_escaped_secret`).
    """
    refuse_escaped_secret(text)
    text = fold_line(text)
    if not text:
        raise StoreValidationError("Type a request first.")
    if len(text) > MAX_REQUEST_LENGTH:
        raise StoreValidationError(
            f"Keep the request to at most {MAX_REQUEST_LENGTH} characters.")
    return text


def recorded_line(text: str) -> str:
    """A typed line as Reconix records it: cleaned (`clean_request`) and with credentials,
    tokens and keys masked. Chat, the audit trail, the history and the model only ever get
    this form."""
    return redact(clean_request(text))


def add_request(text: str) -> UserRequest:
    """Store a plain-language request typed at the prompt (masked, see `recorded_line`)."""
    request = UserRequest(recorded_line(text))
    lists.current().requests.append(request)
    log_event("request.submitted", request.text)
    return request
