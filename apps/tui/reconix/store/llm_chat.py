"""Turn an operator chat line into a real LLM reply and save the history.

Called only while a run is going and only when a model is active (see `run.py`). Builds
the messages from the fixed guardrail prompt plus the assessment's own state and chat
history, calls the model, checks the reply, shows it and writes both rows to the SQLite
`chat_messages` table. The model gets no tools and can never reach a decision function.

With `on_update` the reply streams: one chat line grows as the model writes, checked and
redacted at every step, and `on_update()` redraws the screen (at most every STREAM_REDRAW s).
"""

import time
from typing import Callable, List, Optional, Tuple

from ..llm import client, crypto, db, guardrail
from ..models import ActiveModel, ChatEntry
from ..models.base import utc_now
from .assessment import get_assessment
from .errors import StoreValidationError
from .redact import redact
from .snapshot import uid_for
from .transcript import add_chat, last_exchange

HISTORY_BUDGET = 40
STREAM_REDRAW = 0.1          # seconds between redraws while a reply streams
THINKING = "thinking…"       # the growing line before the reply's first word


def reply(text: str, active: ActiveModel,
          on_update: Optional[Callable[[], None]] = None) -> str:
    """Call the active model, display its reply and persist the exchange. Raises LLMError.

    With `on_update` the reply streams into its chat line (see the module notes)."""
    key, base = credentials(active)
    messages, used_sources = messages_for(text)
    if on_update is None:
        checked = guardrail.check_response(
            client.complete(active.provider_id, active.model, messages,
                            api_key=key, api_base=base))
        entry = add_chat("text", "reconix", checked)
    else:
        entry = _streamed(active, messages, key, base, on_update)
        checked = entry.text
    persist(active, checked, entry.seq)
    if used_sources:
        # A muted note under the reply, so the operator sees which add-ons informed it.
        add_chat("text", "reconix", "Knowledge: " + ", ".join(used_sources), tone="muted")
    return checked


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


def _streamed(active: ActiveModel, messages: List[dict], key: Optional[str],
              base: Optional[str], on_update: Callable[[], None]) -> ChatEntry:
    """The reply as one chat line that grows while the model writes; a failure removes it."""
    entry = add_chat("text", "reconix", THINKING, tone="muted")
    redrawn = 0.0

    def grow(so_far: str) -> None:
        nonlocal redrawn
        # The word still arriving waits for the next space, so a half-streamed secret
        # never shows before the redaction can recognise it.
        done = so_far[:max(so_far.rfind(" "), so_far.rfind("\n")) + 1]
        if done.strip():
            entry.text, entry.tone = guardrail.check_response(done), "default"
        if time.monotonic() - redrawn >= STREAM_REDRAW:
            redrawn = time.monotonic()
            on_update()

    try:
        raw = client.stream(active.provider_id, active.model, messages, grow,
                            api_key=key, api_base=base)
    except Exception:
        get_assessment().chat.remove(entry)
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
