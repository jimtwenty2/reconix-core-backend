"""Base screen: window chrome + body + footer, shared by all flow screens."""

from typing import Optional

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer

from .. import store
from ..widgets import (
    ChatBar, ChoiceMenu, FlowProgress, SessionBar, StepChat, TickList, UserMessage,
)
from ..widgets.step_chat import THINKING


class ReconixScreen(Screen):
    """All flow screens inherit this. Subclasses implement `compose_body`.

    Set `flow_name` to the screen's key in the app flow (it drives the progress
    line), `mode_name` for the help title, and `scroll = False` for a fill body.

    The run plays while any screen is shown: after every step the app calls
    `refresh_view()`. A screen whose layout depends on the run returns that state from
    `view_state()`; when it changes the app rebuilds the screen. Small per-step updates
    (a progress bar, a log) go in `refresh_live()`.
    """

    flow_name: str = ""
    mode_name: str = ""
    scroll: bool = True

    def __init__(self) -> None:
        super().__init__()
        self._view_state: object = None
        self._stale = False          # the layout changed while a dialog covered the screen
        self._hidden: list = []      # what the step chat hid (shown again when it closes)

    def compose(self) -> ComposeResult:
        self._view_state = self.view_state()
        yield SessionBar()
        yield FlowProgress(self.flow_name)
        container = VerticalScroll(id="body") if self.scroll else Vertical(id="body")
        with container:
            yield from self.compose_body()
        yield Footer()

    def compose_body(self) -> ComposeResult:  # pragma: no cover - overridden
        return iter(())

    # --- live updates while the run plays ------------------------------------------------
    def view_state(self) -> object:
        """What this screen's layout depends on; a change rebuilds the screen."""
        return None

    def refresh_view(self) -> None:
        """The run moved (or the store changed): rebuild if the layout changed, else update."""
        if not self.is_mounted:
            # Composed but not mounted yet: if the store moved on since, rebuild on resume
            # (else nothing redraws it: e.g. a model's draft landing as the screen opens).
            if self._view_state is not None and self.view_state() != self._view_state:
                self._stale = True
            return
        if self.view_state() != self._view_state:
            if self.app.screen is self and not self.query(StepChat):
                self.app.reload_screen()
            else:
                self._stale = True   # rebuilt when the dialog on top (or the chat) closes
            return
        self.query_one(SessionBar).refresh_line()
        self.refresh_progress()
        self.refresh_live()

    def refresh_live(self) -> None:
        """Per-step updates of the screen's live parts (override where needed)."""

    def refresh_progress(self) -> None:
        """Redraw the flow progress line after this screen changes a step's state."""
        self.query_one(FlowProgress).refresh_line()

    def on_screen_resume(self) -> None:
        if self._stale:
            self._stale = False
            self.app.reload_screen()
            return
        self.app.flow_screen_resumed()

    # --- navigation helpers (delegate to the app) -----------------------------------------
    def action_next(self) -> None:
        self.app.go_next()

    def action_prev(self) -> None:
        self.app.go_prev()

    def action_choose(self) -> None:
        """Enter fallback when focus is outside the screen's menu: pick its highlight."""
        for menu in self.query(ChoiceMenu):
            if menu.can_focus and menu.display:
                menu.choose_highlighted()
                return

    def focus_menu(self, menu_id: str) -> None:
        menus = self.query(f"#{menu_id}")
        if menus:
            menus.first().focus()

    # --- answers from a Question ("Type something." / "Chat about this") --------------------
    def chat_topic(self) -> str:
        """What \"Chat about this\" is about; screens with a Question override it."""
        return self.mode_name.lower()

    def chat_about(self, draft: Optional[str] = None) -> None:
        """Continue in the chat prompt on Start; `draft` pre-fills it (default: the topic)."""
        store.log_event(f"{self.flow_name}.chat")
        self.app.open_chat(f"About {self.chat_topic()}: " if draft is None else draft)

    def action_chat(self) -> None:
        """`c` on the screens that offer it: chat about this assessment (empty draft)."""
        self.chat_about("")

    def step_content(self) -> str:
        """The step's content as text: the first reply of "Chat about this" ("" = none)."""
        return ""

    def chat_in_step(self) -> None:
        """"Chat about this": talk about the step right here; Esc brings its menu back."""
        store.log_event(f"{self.flow_name}.chat")
        self.run_worker(self.open_step_chat(self.step_content()), exclusive=False)

    async def on_choice_menu_typed(self, event: ChoiceMenu.Typed) -> None:
        """"Type something.": keep it as feedback, then answer it in the step chat."""
        event.stop()
        try:
            store.add_feedback(self.flow_name, event.text)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        self._ask_in_chat(await self.open_step_chat(), event.text)

    # --- the chat inside a step (widgets/step_chat.py) ---------------------------------------
    async def open_step_chat(self, first: str = "") -> StepChat:
        """Hide the step's menu and panels (its headline stays) and show the chat instead."""
        chats = self.query(StepChat)
        if chats:
            chat = chats.first(StepChat)
            chat.focus_input()
            return chat
        body = self.query_one("#body")
        self._hidden = [w for w in body.children
                        if w.display and not isinstance(w, UserMessage)
                        and not w.has_class("ai-label")]
        for widget in self._hidden:
            widget.display = False
        chat = StepChat(first)
        await body.mount_all([chat, ChatBar()])   # the bar is pinned at the bottom (tcss)
        chat.focus_input()
        chat.scroll_to_end()
        return chat

    def on_step_chat_asked(self, event: StepChat.Asked) -> None:
        event.stop()
        self._ask_in_chat(event.chat, event.text)

    def on_step_chat_closed(self, event: StepChat.Closed) -> None:
        """Esc: the chat goes, the step's menu comes back (rebuilt if the step moved on)."""
        event.stop()
        event.chat.remove()
        for bar in self.query(ChatBar):
            bar.remove()
        for widget in self._hidden:
            widget.display = True
        self._hidden = []
        if self._stale:
            self._stale = False
            self.app.reload_screen()
            return
        for menu in self.query(ChoiceMenu):
            if menu.can_focus and menu.display:
                menu.focus()
                return

    def _ask_in_chat(self, chat: StepChat, text: str) -> None:
        """Answer a line typed in the step chat. Advice only: the step still waits for you.

        Every line goes to the active model (or gets the built-in reply at once). A line
        asking to change the scope then opens your tick list: the model only explains, you
        tick the change. At the target login the store refuses the line, so a password
        never goes out.
        """
        try:
            line = store.say_operator_line(f"About {self.chat_topic()}: {text}")
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        chat.add_you(text)
        for old in self.query(TickList):
            old.remove()
        scope_change = store.wants_scope_change(text)
        if store.active_model() is None:
            if scope_change:
                self._scope_reply(chat, text)       # no model: Reconix's reply, then the ticks
            else:
                store.llm_answer(line)              # the built-in reply: no network, at once
                entry = store.last_exchange()[1][-1]
                chat.add_reply(entry.text, entry.tone)
            return
        reply = chat.add_reply(THINKING, tone="muted")

        def show() -> None:
            replies = store.last_exchange()[1]
            if replies:
                chat.show_reply(reply, replies[-1].text, replies[-1].tone)

        def done() -> None:
            show()
            if scope_change and chat.is_mounted:
                self._scope_reply(chat, text)       # whatever the model said, you change it

        def work() -> None:
            store.llm_answer(line, on_update=lambda: self.app.call_from_thread(show))
            self.app.call_from_thread(done)

        self.app.run_worker(work, thread=True, group="llm", exit_on_error=False)

    def _scope_reply(self, chat: StepChat, text: str) -> None:
        """Reconix's own line ("Only you can change the scope…", or locked), then your
        tick list (nothing new ticked). Recorded, so the model's history has it too."""
        choices = store.answer_scope_change(text)
        entry = store.last_exchange()[1][-1]
        chat.add_reply(entry.text, entry.tone)
        if choices is not None:
            chat.add(TickList(choices.ports, choices.tools))

    def on_tick_list_saved(self, event: TickList.Saved) -> None:
        """Your ticks become the scope (the store validates them); the chat stays open."""
        event.stop()
        network = store.get_scope().kind == "network"
        try:
            store.edit_scope(allowed_ports=event.ports if network else None, tools=event.tools)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        event.tick_list.remove()
        chat = self.query_one(StepChat)
        entry = store.last_exchange()[1][-1]
        chat.add_reply(f"{entry.text}\n{store.scope_text()}", entry.tone)
        self.refresh_view()
        chat.focus_input()

    def on_tick_list_cancelled(self, event: TickList.Cancelled) -> None:
        event.stop()
        event.tick_list.remove()
        chat = self.query_one(StepChat)
        chat.add_reply("No change to the scope.", tone="muted")
        chat.focus_input()

    def notify_error(self, message: str, title: Optional[str] = None) -> None:
        """A store error, shown as plain text (never markup)."""
        self.notify(message, title=title or "", severity="warning", markup=False)
