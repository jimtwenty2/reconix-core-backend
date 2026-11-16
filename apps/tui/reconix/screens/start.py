"""Frame 01 — Assessment Start: the welcome, then the conversation (like Claude Code).

What the screen shows follows the assessment's chat (see `view_state()`):

    welcome       nothing typed yet: the logo, the quickstart panel and the prompt
    conversation  your latest line on top, then Reconix's answer, or one spinner line
                  while the run heads for its first gate (Ctrl+O lists the finished steps)
"""

from typing import List

from rich.table import Table
from rich.text import Text
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Center, Vertical, VerticalScroll
from textual.widgets import Static

from .base import ReconixScreen
from .. import store, theme
from ..commands import COMMANDS
from ..models import ChatEntry
from ..widgets import ActivityStatus, PromptBox, UserMessage
from ..widgets.step_chat import speaker_label
from ..widgets.stream_text import StreamLine

# Colored by `#logo` in reconix.tcss.
LOGO = r"""██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██║ ╚███╔╝
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║ ██╔██╗
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝"""

# (number, step, hint) for the "Start an assessment" panel
QUICKSTART = (
    ("1", "Pick a template, type its target", "/template"),
    ("2", "Or just type a target", '"https://staging.example.com"'),
    ("3", "Approve scope, plan and risks", "↵ at each gate"),
)

PLACEHOLDER = "Type a target (URL, IPv4, repo, path), a question, or / commands"
READING = "reconix is reading the target…"
EMPTY_HINT = "Type a target, a question, or / for commands."
# The store refuses dash ranges with the same words (store/targets.py).
DASH_RANGE_UNSUPPORTED = store.DASH_RANGE_UNSUPPORTED


def _quickstart_steps() -> Table:
    """The onboarding steps, with hints right-aligned in their own column."""
    grid = Table.grid(expand=True)
    grid.add_column()
    grid.add_column(justify="right", no_wrap=True)
    for num, step, hint in QUICKSTART:
        grid.add_row(
            Text.assemble((num, f"bold {theme.CYAN}"), f"  {step}"), Text(hint, style=theme.TEAL)
        )
    return grid


def _welcome_hint() -> Text:
    return Text.assemble(
        ("No active scope — type ", theme.MUTED),
        ("/template", f"bold {theme.TEAL}"),
        (" or a target below to begin.", theme.MUTED),
    )


def length_error(text: str) -> str:
    """Why a line is too long to send ("" when it fits); the store enforces the same limit."""
    length = len(" ".join(text.split()))
    if length <= store.MAX_REQUEST_LENGTH:
        return ""
    return (
        f"That line has {length:,} characters — keep it to at most "
        f"{store.MAX_REQUEST_LENGTH} (a target, a question, or / for commands)."
    )


def target_error(text: str) -> str:
    """Why a typed target can't start a run ("" when it can).

    Feedback for the person typing only: the store and the backend's scope check decide.
    """
    try:
        check = store.validate_target(text)
    except ValueError:  # a backstop: unreadable text is not a target
        return "That isn't a valid target — e.g. https://app.example.com"
    if not check.valid:
        return check.error
    if check.kind == "IPV4_RANGE" and "-" in check.value:
        return DASH_RANGE_UNSUPPORTED
    return ""


def _answer(replies: List[ChatEntry]) -> Text:
    """Reconix's latest answer to your line (empty until it has one)."""
    if not replies:
        return Text("")
    last = replies[-1]
    return Text.assemble(
        (speaker_label(last.author), f"bold {theme.CYAN}"), (last.text, theme.MUTED)
    )


def _reconix_line(entry: ChatEntry) -> Text:
    """A past Reconix line in the scrollback (tone-colored, plain text)."""
    return Text.assemble(
        (speaker_label(entry.author), f"bold {theme.CYAN}"),
        (entry.text, theme.TONE.get(entry.tone, theme.MUTED)),
    )


class StartScreen(ReconixScreen):
    flow_name = "start"
    mode_name = "CHAT"
    scroll = False

    BINDINGS = [
        Binding("enter", "begin", "continue"),
        Binding("question_mark", "help", "help", key_display="?"),
    ]

    # --- state -------------------------------------------------------------------------------
    def view_state(self) -> object:
        """'welcome', or the line the conversation starts from (a new line rebuilds it)."""
        request = store.last_exchange()[0]
        return "welcome" if request is None else ("conversation", request.seq)

    @staticmethod
    def _working() -> bool:
        """The run is heading for its first gate: Reconix is busy and Enter must not re-send."""
        run = store.get_run()
        return (
            run.started
            and not store.is_finished()
            and not store.waiting_gate()
            and not store.is_scope_approved()
        )

    # --- layout ------------------------------------------------------------------------------
    def compose_body(self) -> ComposeResult:
        if self.view_state() == "welcome":
            yield from self._compose_welcome()
        else:
            yield from self._compose_conversation()
        yield PromptBox(
            COMMANDS,
            store.list_history,
            placeholder=PLACEHOLDER,
            initial=self.app.pending_prompt,
            id="prompt-box",
        )

    def _compose_welcome(self) -> ComposeResult:
        with Vertical(id="start-center"):
            # `align` centres the children as one group, and the full-width text
            # lines make that group full width, so fixed-width blocks get a Center.
            with Center():
                yield Static(LOGO, id="logo", markup=False)
            yield Static("AI-Powered Security Testing Assistant", id="tagline")
            yield Static(
                "v0.4.0  ·  terminal interface  ·  authorized assessments only",
                id="version-line",
            )
            with Center():
                with Vertical(id="quickstart", classes="panel") as qs:
                    qs.border_title = "◆ Start an assessment"
                    yield Static(_quickstart_steps(), classes="muted")
            yield Static(_welcome_hint(), id="no-scope")

    def _compose_conversation(self) -> ComposeResult:
        request, replies = store.last_exchange()
        with VerticalScroll(id="start-conversation"):
            # Earlier exchanges, scrollable; the current one stays live below.
            yield from self._history_rows(request.seq)
            yield UserMessage(request.text)
            yield ActivityStatus(
                [e.text for e in replies],
                READING,
                expanded=self.app.activity_expanded,
                id="start-activity",
                classes="activity",
            )
            last = replies[-1] if replies else None
            full_text = last.text if last else ""
            author = last.author if last else ""
            yield StreamLine(full_text, tone="muted", author=author, id="start-reply")

    @staticmethod
    def _history_rows(current_seq: int) -> ComposeResult:
        """Every chat line before the current exchange, so you can scroll back through it."""
        for entry in store.list_chat():
            if entry.seq >= current_seq:
                break
            if entry.kind != "text" or not entry.text:
                continue
            if entry.speaker == "you":
                yield UserMessage(entry.text)
            elif entry.speaker == "reconix":
                yield Static(_reconix_line(entry), classes="history-reply")

    def on_mount(self) -> None:
        self.app.pending_prompt = ""
        self.query_one(PromptBox).focus_input()
        conversation = self.query("#start-conversation")
        if conversation:
            conversation.first().scroll_end(animate=False)  # latest shown; scroll up for history
        self.refresh_live()

    # --- live: Reconix's answer, or the spinner while the run heads for its first gate ----
    def refresh_live(self) -> None:
        working = self._working()
        box = self.query_one(PromptBox)
        if working != box.locked:
            box.set_locked(working)
        activity = self.query("#start-activity")
        if not activity:
            return  # welcome: nothing live to show
        replies = store.last_exchange()[1]
        status = activity.first(ActivityStatus)
        reply = self.query_one("#start-reply", Static)
        status.display, reply.display = working, not working
        if working:
            status.show([e.text for e in replies])
        else:
            conversation = self.query_one("#start-conversation", VerticalScroll)
            at_end = conversation.is_vertical_scroll_end
            last = replies[-1] if replies else None
            new_text = last.text if last else ""
            author = last.author if last else ""
            if isinstance(reply, StreamLine):
                if reply.current_text != new_text:
                    reply.update_text(new_text, tone="muted", author=author)
            else:
                reply.update(_answer(replies))
            if at_end:  # a streamed reply grows: keep its end in view
                conversation.call_after_refresh(conversation.scroll_end, animate=False)

    def _flush_stream(self) -> None:
        reply = self.query("#start-reply")
        if reply and isinstance(reply.first(), StreamLine):
            reply.first(StreamLine).flush()

    # --- keys and the prompt -----------------------------------------------------------------
    def action_begin(self) -> None:
        """Enter outside the prompt: during a run, reopen what it waits for (else nothing)."""
        self._flush_stream()
        if not self._working():  # Enter while working must not re-send
            self.app.submit_request("")

    def action_help(self) -> None:
        self.app.action_help()

    def on_prompt_box_submitted(self, event: PromptBox.Submitted) -> None:
        event.stop()
        self._flush_stream()
        self._send(event.box, event.text)

    def on_prompt_box_command_submitted(self, event: PromptBox.CommandSubmitted) -> None:
        event.stop()
        self._flush_stream()
        if self.app.is_path_line(event.text):
            self._send(event.box, event.text)  # /home/me/app: a target, not a command
            return
        check = self.app.check_command(event.text)
        if not check.ok:
            event.box.show_error(check.error)
            return
        if self.app.run_command_line(event.text):
            event.box.clear()
        else:
            event.box.release()  # refused with a pop-up

    def _send(self, box: PromptBox, text: str) -> None:
        """A plain line: say why it can't be sent, or hand it to the app."""
        text = text.strip()
        before_run = not store.get_run().started
        if not text and before_run:
            box.show_notice(EMPTY_HINT)  # nothing starts, nothing changes
            return
        error = length_error(text)
        if not error and before_run and store.looks_like_target(text):
            error = target_error(text)
        if error:
            box.show_error(error)
            box.input.select_all()  # kept to edit; typing replaces it
            return
        if self.app.submit_request(text):
            box.clear()
        else:
            box.release()  # refused with a pop-up
            box.input.select_all()  # so "/new" typed now is a command
