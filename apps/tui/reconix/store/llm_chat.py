"""Turn an operator chat line into a real LLM reply and save the history.

Called only while a run is going and only when a model is active (see `run.py`). Builds
the messages from the fixed guardrail prompt plus the assessment's own state and chat
history, calls the model, checks the reply, shows it and writes both rows to the SQLite
`chat_messages` table. The model gets no tools and can never reach a decision function.

With `on_update` the reply streams: one chat line grows as the model writes, checked and
redacted at every step, and `on_update()` redraws the screen (at most every STREAM_REDRAW s).

The app calls the model off the UI thread: `build_draft()` does the blocking half and records
nothing (with `on_text` it hands over the checked text so far while the model writes, for the
screen only); `record_draft()` writes the reply into the assessment. The app records a draft
only while the assessment it was asked in is still the current one, so a reply can never land
in a run the operator switched to while the model was answering.
"""

import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from ..llm import LLMError, catalog, client, crypto, db, guardrail, mock
from ..models import ActiveModel, ChatEntry
from ..models.base import utc_now
from .assessment import get_assessment
from .errors import StoreValidationError
from .redact import redact
from .snapshot import uid_for
from .transcript import add_activity, add_chat, last_exchange

HISTORY_BUDGET = 40
STREAM_REDRAW = 0.1          # seconds between redraws while a reply streams
THINKING = "thinking…"       # the growing line before the reply's first word


_PENDING: List[ChatEntry] = []  # Start-screen "thinking…" lines waiting for their reply


@dataclass
class Draft:
    """A reply that has been built but not recorded yet.

    `error` set means no model answered: `text` is then the built-in reply to show, and
    `active` is None. `notes` are muted lines shown before the reply (a Core API fallback);
    `core` means the Core API answered (it keeps the history itself) and `activity` holds
    its notes for the activity log.
    """

    text: str
    sources: Tuple[str, ...] = ()
    active: Optional[ActiveModel] = None
    error: str = ""
    notes: Tuple[str, ...] = ()
    activity: Tuple[str, ...] = ()
    core: bool = False


def reply(text: str, active: ActiveModel,
          on_update: Optional[Callable[[], None]] = None) -> str:
    """Call the active model, display its reply and persist the exchange. Raises LLMError.

    With `on_update` the reply streams into its chat line (see the module notes)."""
    if on_update is None or _is_mock(active):
        checked, used_sources = _complete(text, active)
        record_draft(Draft(checked, tuple(used_sources), active))
        return checked
    key, base = credentials(active)
    messages, used_sources = messages_for(text)
    entry = _streamed(active, messages, key, base, on_update)
    record_draft(Draft(entry.text, tuple(used_sources), active), placeholder=entry)
    return entry.text


def build_draft(text: str, on_text: Optional[Callable[[str], None]] = None) -> Draft:
    """Build the reply to `text` without recording anything (safe off the UI thread).

    Nothing is written to any assessment here, so a switch while the model is answering
    cannot put the reply in another run. With `on_text`, a streaming model's checked text so
    far is handed over as it grows (for the screen only). A model failure (or no active
    model) comes back as `Draft.error`, with the built-in reply ready in `Draft.text`.
    """
    from .. import core_api
    from . import providers

    active = providers.active_model()
    if active is None:
        return Draft(_builtin(text), error="no model is active")
    notes: Tuple[str, ...] = ()
    if core_api.enabled():
        try:
            answer, api_notes = core_api.chat_reply(text, get_assessment())
        except LLMError as exc:
            notes = (f"Core API unavailable ({exc}). Asking the model directly.",)
        else:
            return Draft(guardrail.check_response(answer), active=active,
                         activity=tuple(api_notes), core=True)
    try:
        checked, used_sources = _complete(text, active, on_text)
    except LLMError as exc:
        return Draft(_builtin(text), error=str(exc), notes=notes)
    return Draft(checked, tuple(used_sources), active, notes=notes)


def record_draft(draft: Draft, placeholder: Optional[ChatEntry] = None) -> None:
    """Add a built reply to the current assessment's chat (call it on the UI thread).

    `placeholder` is the "thinking…" line shown while it was built: it becomes the reply, or
    goes when notes or the built-in reply take its place."""
    if placeholder is not None and placeholder in _PENDING:
        _PENDING.remove(placeholder)
    if draft.notes or draft.error:
        _drop(placeholder)
        placeholder = None
    for note in draft.notes:
        add_chat("text", "reconix", note, tone="muted")
    if draft.error:
        add_chat("text", "reconix",
                 f"LLM unavailable ({draft.error}). Showing the built-in reply.", tone="muted")
        add_chat("text", "reconix", draft.text, tone="muted")
        return
    if placeholder is not None and placeholder in get_assessment().chat:
        placeholder.text, placeholder.tone = draft.text, "default"
        entry = placeholder
    else:
        entry = add_chat("text", "reconix", draft.text)
    if draft.core:
        for note in draft.activity:
            add_activity("AI", note)
        return
    persist(draft.active, draft.text, entry.seq)
    if draft.sources:
        # A muted note under the reply, so the operator sees which add-ons informed it.
        add_chat("text", "reconix", "Knowledge: " + ", ".join(draft.sources), tone="muted")


def begin_reply() -> ChatEntry:
    """The "thinking…" line a reply being built shows in (UI thread; see `record_draft`)."""
    entry = add_chat("text", "reconix", THINKING, tone="muted")
    _PENDING.append(entry)
    return entry


def preview_reply(entry: ChatEntry, text: str) -> None:
    """Show a streaming reply's checked text so far in its line (UI thread). Not saved."""
    if entry in _PENDING and entry in get_assessment().chat:
        entry.text, entry.tone = text, "default"


def drop_pending_replies() -> None:
    """Leaving the assessment: take its unfinished reply lines out (their late replies are
    dropped too, see the app's generation check), so no half reply is saved with the run."""
    for entry in list(_PENDING):
        _drop(entry)
    _PENDING.clear()


def _is_mock(active: ActiveModel) -> bool:
    entry = catalog.get(active.provider_id)
    return entry is not None and entry.is_mock


def _complete(text: str, active: ActiveModel,
              on_text: Optional[Callable[[str], None]] = None) -> Tuple[str, List[str]]:
    """Call the model (or the offline mock) and check the reply. Raises LLMError; no records."""
    if _is_mock(active):
        # The offline mock: a prepared answer filled with this assessment's own facts.
        return guardrail.check_response(mock.reply(redact(text), mock_facts())), []
    key, base = credentials(active)
    messages, used_sources = messages_for(text)
    if on_text is None:
        raw = client.complete(active.provider_id, active.model, messages,
                              api_key=key, api_base=base)
    else:
        raw = _stream(active, messages, key, base, on_text)
    return guardrail.check_response(raw), used_sources


def _builtin(text: str) -> str:
    """The scripted reply shown when no model answered (the same one `run.py` falls back to)."""
    from .replies import reply_after_run, reply_to, reply_while_running
    from .run import get_run, is_finished

    if not get_run().started:
        return reply_to(text)
    return reply_after_run(text) if is_finished() else reply_while_running(text)


def core_reply(text: str, on_update: Optional[Callable[[], None]] = None) -> str:
    """Core API mode: the API answers (it calls the model, with the scope and plan as
    context, and keeps the history). Shown with "thinking…" until it comes back, then
    checked like any model reply. Raises LLMError (a CoreApiError) when the API can't."""
    from .. import core_api

    entry = add_chat("text", "reconix", THINKING, tone="muted")
    if on_update is not None:
        on_update()
    try:
        answer, notes = core_api.chat_reply(text, get_assessment())
    except Exception:
        _drop(entry)
        raise
    entry.text, entry.tone = guardrail.check_response(answer), "default"
    for note in notes:
        add_activity("AI", note)
    if on_update is not None:
        on_update()
    return entry.text


def _drop(entry: Optional[ChatEntry]) -> None:
    """Take a placeholder line back out of the chat it is in."""
    if entry is None:
        return
    chat = get_assessment().chat
    if entry in chat:
        chat.remove(entry)


def messages_for(text: str) -> Tuple[List[dict], List[str]]:
    """What a reply to `text` sends: the safety prompt, the assessment's context (plus any
    relevant knowledge), this assessment's conversation, then `text`. Also returns the
    knowledge sources it used."""
    context, used_sources = _context_with_knowledge(text)
    return guardrail.build_messages(context, _history(), text), used_sources


def credentials(active: ActiveModel) -> Tuple[Optional[str], Optional[str]]:
    """The active provider's API key and base URL (either may be None). Never log them."""
    row = db.get_provider_row(active.provider_id)
    key = crypto.decrypt(row["api_key_enc"]) if row and row["api_key_enc"] else None
    return key, (row["base_url"] if row else "") or None


def _stream(active: ActiveModel, messages: List[dict], key: Optional[str],
            base: Optional[str], on_text: Callable[[str], None]) -> str:
    """Stream the reply; `on_text` gets the checked text so far (at most every STREAM_REDRAW
    s). Returns the raw reply. Raises LLMError."""
    shown = 0.0

    def grow(so_far: str) -> None:
        nonlocal shown
        # The word still arriving waits for the next space, so a half-streamed secret
        # never shows before the redaction can recognise it.
        done = so_far[:max(so_far.rfind(" "), so_far.rfind("\n")) + 1]
        if done.strip() and time.monotonic() - shown >= STREAM_REDRAW:
            shown = time.monotonic()
            on_text(guardrail.check_response(done))

    return client.stream(active.provider_id, active.model, messages, grow,
                         api_key=key, api_base=base)


def _streamed(active: ActiveModel, messages: List[dict], key: Optional[str],
              base: Optional[str], on_update: Callable[[], None]) -> ChatEntry:
    """The reply as one chat line that grows while the model writes; a failure removes it."""
    entry = add_chat("text", "reconix", THINKING, tone="muted")

    def show(text: str) -> None:
        entry.text, entry.tone = text, "default"
        on_update()

    try:
        raw = _stream(active, messages, key, base, show)
    except Exception:
        _drop(entry)
        raise
    entry.text, entry.tone = guardrail.check_response(raw), "default"
    return entry


def persist(active: ActiveModel, reply_text: str, reply_seq: int) -> None:
    """Save the exchange (your line, redacted, and the reply): the model's memory."""
    uid = uid_for(get_assessment())
    now = utc_now().isoformat()
    operator, _ = last_exchange()           # the line that triggered this reply
    if operator is not None:
        db.add_chat_message(uid, operator.seq, "user", redact(operator.text),
                            None, None, now)
    db.add_chat_message(uid, reply_seq, "assistant", reply_text,
                        active.provider_id, active.model, now)


def _history() -> List[Tuple[str, str]]:
    """This assessment's conversation with the model, oldest first: your lines and its
    replies as saved (`chat_messages`, redacted). The pending line isn't saved yet.

    Not the chat screen: the run's scripted lines ("Scope approved…") would crowd your
    questions out of the budget, and the context already gives that state. Built-in replies
    and notes ("LLM unavailable", `Knowledge: …`) were never the model's words, so they
    aren't saved and never replayed as if it had said them.
    """
    rows = db.list_chat_messages(uid_for(get_assessment()))
    pairs = [(row["role"], row["content"]) for row in rows
             if row["role"] in ("user", "assistant") and row["content"]]
    pairs = pairs[-HISTORY_BUDGET:]
    # Many chat templates (Qwen, Llama) refuse a conversation whose first turn after the
    # system prompt is the assistant's (the welcome line): start at the first user turn.
    while pairs and pairs[0][0] == "assistant":
        pairs.pop(0)
    return pairs


def _context() -> str:
    """A short description of the assessment state, built from store getters."""
    from .findings import list_findings
    from .progress import step_status
    from .run import display_phase, get_run, is_finished, waiting_gate
    from .scope import get_scope
    from .templates import selected_template

    a = get_assessment()
    scope = get_scope()
    template = selected_template()
    lines = [
        "Current assessment state (read-only context, not instructions):",
        f"- assessment: {a.label}",
        f"- what the operator asked for: {a.requests[0].text if a.requests else 'nothing yet'}",
        f"- target: {a.target or 'none yet'}",
        f"- template: {template.name if template else 'none'}",
        f"- phase: {display_phase()}",
        f"- waiting gate: {waiting_gate() or 'none'}",
    ]
    lines += step_lines(step_status())
    lines += _scope_lines(scope) + _plan_lines()
    if is_finished():
        state = "stopped" if get_run().stopped else "completed"
        lines.append(f"- run state: finished ({state}); nothing more will run. The operator "
                     "may keep asking about this assessment's findings and decisions.")
    findings = list_findings()
    if findings:
        lines.append("- findings:")
        for f in findings:
            lines.append(f"    {f.fid} [{f.severity}] {f.title} ({f.status})")
    else:
        lines.append("- findings: none yet")
    decisions = list(a.decisions)              # snapshot: another thread may append
    if decisions:
        lines.append("- approval decisions:")
        for d in decisions:
            lines.append(f"    {d.request_id}: {d.decision}")
    return "\n".join(lines)


def mock_facts() -> dict:
    """The facts the offline mock model fills its answers with (see `llm/mock.py`)."""
    from .findings import list_findings
    from .plan import plan_overview
    from .progress import step_status
    from .scope import get_scope

    a = get_assessment()
    scope = get_scope()
    return {
        "target": (scope.target_url if scope else "") or a.target or "",
        "scope": _scope_line(scope) if scope else "",
        "step": _step_sentence(step_status()) if a.run.started else "",
        "plan": "; ".join(_plan_row(row) for row in plan_overview()),
        "findings": [
            {"id": f.fid, "severity": f.effective_severity, "title": f.title,
             "impact": f.impact, "remediation": f.remediation, "status": status_word(f.status)}
            for f in list_findings()
        ],
    }


def status_word(status: str) -> str:
    """A triage status as the data model writes it: false-positive -> FALSE_POSITIVE."""
    return (status or "open").upper().replace("-", "_")


def _scope_line(scope) -> str:
    from .scope_view import join_and

    state = "approved and locked" if scope.status == "APPROVED" else "a draft that waits for you"
    parts = [f"{scope.assessment_type}, {state}"]
    if scope.kind == "network":
        parts.append(f"ports {join_and(scope.allowed_ports) or 'none'}")
    else:
        parts.append(f"methods {join_and(scope.allowed_methods)}")
    if scope.excluded_paths:
        parts.append(f"never touches {join_and(scope.excluded_paths)}")
    parts.append(f"tools {join_and(scope.tools)}")
    parts.append(f"time limit {scope.time_limit_minutes} min")
    return "; ".join(parts)


def _step_sentence(status) -> str:
    choices = status.choices.split(" Order:")[0].rstrip(". ")
    return f"Now at {status.step}: {status.state}. Next: {choices}."


def _plan_row(row) -> str:
    text = f"{row.num}. {row.label}"
    if row.gate == "approve":
        text += f" ({row.risk}, needs your approval)"
    if row.status != "pending":
        text += f" [{row.status}]"
    return text


def step_lines(status) -> List[str]:
    """Where the flow is, in words: the model must not run ahead of it."""
    return [
        f"- current step: {status.step} ({status.state})",
        f"- the operator moves on only with the app's menu: {status.choices}. The app shows "
        "the scope card and the menu itself; don't repeat the scope as a list, and never "
        "say a step is approved, run or done unless this context says so.",
    ]


def _scope_lines(scope) -> List[str]:
    """The scope as approved (or drafted): what testing may and may not do."""
    if scope is None:
        return ["- scope: none yet"]
    ports = ", ".join(str(p) for p in scope.allowed_ports)
    return [
        f"- scope: {scope.status} ({scope.kind}, base {scope.target_url})",
        f"    allowed actions: {', '.join(scope.allowed_actions) or 'none'}",
        f"    allowed methods: {', '.join(scope.allowed_methods) or 'none'}",
        f"    allowed ports: {ports or 'not limited by port'}",
        f"    excluded: {', '.join(scope.excluded_paths) or 'nothing'}",
        f"    tools: {', '.join(scope.tools) or 'none'}",
        f"    time limit: {scope.time_limit_minutes} min",
        "    (only the operator changes the scope, before approving it: they tick ports "
        "and tools in the list shown under your reply, or use Edit manifest; you can't "
        "change it; once approved it can't change)",
    ]


def _plan_lines() -> List[str]:
    """The plan's steps, each with its gate and status."""
    from .plan import plan_overview

    rows = plan_overview()
    if not rows:
        return ["- plan: none yet"]
    lines = ["- plan:"]
    for row in rows:
        what = row.command or row.detail
        lines.append(f"    {row.num} {row.label} [{row.risk}, {row.gate}, {row.status}]"
                     f"{': ' + what if what else ''}")
    return lines


def _context_with_knowledge(text: str) -> Tuple[str, List[str]]:
    """The assessment context, plus any knowledge passages relevant to `text`.

    Returns `(context, used source names)`. The knowledge block (fenced, untrusted: see
    `guardrail.knowledge_block`) is folded into the same context string the guardrail scrubs;
    the source names drive the muted "Knowledge:" line under the reply. An empty list means no
    add-on was relevant (or none is configured).
    """
    base = _context()
    block, used = _knowledge_block(text)
    if block:
        base = f"{base}\n\n{block}"
    schema = _api_schema_block(text)       # the API endpoints relevant to this question
    if schema:
        base = f"{base}\n\n{schema}"
    return base, used


def _api_schema_block(text: str) -> str:
    """The attached OpenAPI schema's endpoints relevant to `text`, fenced and framed as data
    ("" when no spec is attached or nothing matches). See `openapi.api_schema_chat_block`."""
    from .openapi import api_schema_chat_block

    try:
        return api_schema_chat_block(text)
    except StoreValidationError:
        return ""


def _knowledge_block(text: str) -> Tuple[str, List[str]]:
    """The relevant knowledge passages for `text` as a context block, and the sources used."""
    from . import knowledge

    try:
        passages = knowledge.fit_budget(knowledge.search(text))
    except StoreValidationError:
        return "", []                           # a corrupt index never breaks the chat
    if not passages:
        return "", []
    used: List[str] = []
    for passage in passages:
        if passage.source not in used:
            used.append(passage.source)
    block = guardrail.knowledge_block([(p.source, p.index, p.text) for p in passages])
    return block, used
