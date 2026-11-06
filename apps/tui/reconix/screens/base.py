"""Base screen: window chrome + body + footer, shared by all flow screens."""

from typing import List, NamedTuple, Optional

from textual.app import ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Footer

from .. import store
from ..models import Choice
from ..widgets import (
    ChatBar,
    ChoiceMenu,
    FlowProgress,
    PlanOrder,
    PlanPanel,
    Question,
    ScopePanel,
    SessionBar,
    StepChat,
    TickList,
    UserMessage,
)
from ..widgets.step_chat import THINKING

CHAT_DECISION = "chat-decision"
HIDDEN_CHOICES = "The choices are below — ↓ moves down to them."
CHAT_MENU_HINT = "Enter to select · ↑/↓ to navigate · type to chat · Esc back to the step"


def scope_card() -> Optional[Widget]:
    """The ⛉ SCOPE card for the current scope (None before there is one)."""
    scope = store.get_scope()
    return ScopePanel(scope) if scope is not None else None


def plan_card() -> Optional[Widget]:
    """The ▤ PLAN card: every step in its current order (None before there is a plan)."""
    rows = store.plan_overview()
    if not rows:
        return None
    return PlanPanel(rows, f"{len(rows)} steps · {store.gated_count()} need your approval")


CARDS = {"scope": scope_card, "plan": plan_card}


class Decision(NamedTuple):
    """The step's decision as its menu asks it; the step chat shows the same choices."""

    chip: str
    question: str
    choices: List[Choice]
    default: int = 0


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
        self._stale = False  # the layout changed while a dialog covered the screen
        self._hidden: list = []  # what the step chat hid (shown again when it closes)
        self._hinted = False  # the "choices are below" hint showed on this screen already

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
                self._stale = True  # rebuilt when the dialog on top (or the chat) closes
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
        # A dialog (the API base-URL form) covered the gate as it opened: hint now.
        self.call_after_refresh(self._hint_hidden_choices)

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

    def focus_menu(self, menu_id: str, *, top: bool = False) -> None:
        """Focus the menu `menu_id`. `top`: keep the screen scrolled to its top instead of
        down to the menu, so a gate opens on what is being decided (the manifest, the exact
        request), not only on its choices; ↑/↓ in the menu bring the choices into view."""
        menus = self.query(f"#{menu_id}")
        if not menus:
            return
        menus.first().focus(scroll_visible=not top)
        if top:
            self.call_after_refresh(self._scroll_body_home)

    def _scroll_body_home(self) -> None:
        for body in self.query("#body"):
            body.scroll_home(animate=False)
        self.call_after_refresh(self._hint_hidden_choices)

    def _hint_hidden_choices(self) -> None:
        """On a short terminal the gate's choices start below the fold: say how to reach
        them, so nobody presses Enter on a choice they can't see."""
        menu = self.focused
        if self._hinted or not isinstance(menu, ChoiceMenu) or self.app.screen is not self:
            return
        bodies = self.query("#body")
        if bodies and menu.region.y >= bodies.first().region.bottom - 1:
            self._hinted = True  # once per screen visit, not on every resume
            self.notify(HIDDEN_CHOICES, title="Your decision", timeout=6)

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
        """ "Chat about this": talk about the step right here; Esc brings its menu back.

        It opens with the step's content (the scope card on the scope step) and its menu."""
        store.log_event(f"{self.flow_name}.chat")
        self.run_worker(self._open_about_step(), exclusive=False)

    async def _open_about_step(self) -> None:
        """The step's content (and its card), then the input: you came to talk."""
        chat = await self.open_step_chat(self.step_content())
        card = self.chat_card()
        if card is not None:
            chat.add(card)

    # --- the step's decision (its menu), also offered inside the step chat ------------------
    def decision(self) -> Optional[Decision]:
        """The decision this step waits for, as its menu asks it (None: nothing to decide)."""
        return None

    def decide(self, choice_id: str) -> None:
        """Do what the step's menu does for `choice_id` (screens with a Question override)."""

    def chat_card(self) -> Optional[Widget]:
        """The step's card in the chat (the scope on Template, the plan on Plan)."""
        return None

    def allows_reorder(self) -> bool:
        """Whether a reorder request here opens the plan's order list (the Plan screen)."""
        return False

    def on_choice_menu_chosen(self, event: ChoiceMenu.Chosen) -> None:
        """The step's menu, or the same menu inside the step chat."""
        event.stop()
        if event.menu.parent is not None and event.menu.parent.has_class(CHAT_DECISION):
            self._chat_decided(event.choice_id)
        else:
            self.decide(event.choice_id)

    async def on_choice_menu_typed(self, event: ChoiceMenu.Typed) -> None:
        """ "Type something.": keep it as feedback, then answer it in the step chat. A
        `/name` line is a command instead: it runs, and is neither feedback nor asked."""
        event.stop()
        if self._refused_at_login(event.text):
            return
        if self._is_command(event.text):
            chats = self.query(StepChat)
            self._chat_command(chats.first(StepChat) if chats else None, event.text)
            return
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
        self._hidden = [
            w
            for w in body.children
            if w.display and not isinstance(w, UserMessage) and not w.has_class("ai-label")
        ]
        for widget in self._hidden:
            widget.display = False
        chat = StepChat(first)
        await body.mount_all([chat, ChatBar()])  # the bar is pinned at the bottom (tcss)
        chat.focus_input()
        chat.scroll_to_end()
        return chat

    def on_step_chat_asked(self, event: StepChat.Asked) -> None:
        event.stop()
        if self._refused_at_login(event.text):
            return
        if self._is_command(event.text):
            self._chat_command(event.chat, event.text)
            return
        self._ask_in_chat(event.chat, event.text)

    def _refused_at_login(self, text: str) -> bool:
        """At (or stopped at) the target login a typed line may be the password: refuse it
        before anything else, so it never runs as a command, is never kept and never echoed.
        Only what the command bar takes there passes (/stop, /new, /help, /quit, no argument:
        `app.login_blocks`)."""
        refusal = self.app.login_blocks(text)
        if refusal:
            self.notify_error(refusal)
        return bool(refusal)

    def _is_command(self, text: str) -> bool:
        """`/name …` runs a command; a path (`/api/v1 …`) stays a chat line."""
        return text.lstrip().startswith("/") and not self.app.is_path_line(text)

    def _chat_command(self, chat: Optional[StepChat], text: str) -> None:
        """A `/name` line typed in the chat or on "Type something.": it runs as from the
        command bar (`run_command_line`), never reaches the model and is not feedback. A
        command that moves to another screen takes the chat with it; otherwise the chat
        stays, with a line saying it ran (or why it can't: an unknown command). The echo is
        the masked line, as the history keeps it."""
        check = self.app.check_command(text)
        if chat is None:
            if check.ok:
                self.app.run_checked(text, check)
            else:
                self.notify_error(check.error)
            return
        try:
            echo = store.recorded_line(text)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        self._drop_decision()
        chat.add_you(echo)
        if not check.ok:
            chat.add_reply(check.error, tone="warn")
            chat.focus_input()
            return
        self.app.run_checked(text, check)
        if self in self.app.screen_stack and chat.is_attached:  # still this screen
            chat.add_reply(f"Ran /{check.command.name}.", tone="muted")
            chat.focus_input()

    def on_step_chat_closed(self, event: StepChat.Closed) -> None:
        """Esc: the chat goes, the step's menu comes back (rebuilt if the step moved on)."""
        event.stop()
        self._close_chat()
        if self._stale:
            self._stale = False
            self.app.reload_screen()
            return
        self._focus_step_menu()

    def _focus_step_menu(self) -> None:
        """Focus the step's own menu (shown again once the chat closed), so a dialog opened
        from the chat gives the focus back to it, as one opened from the menu does."""
        for menu in self.query(ChoiceMenu):
            if menu.can_focus and menu.display:
                self.set_focus(menu)
                return

    def _close_chat(self) -> None:
        """Take the chat and its bar away and show the step's own widgets again."""
        for chat in self.query(StepChat):
            chat.remove()
        for bar in self.query(ChatBar):
            bar.remove()
        for widget in self._hidden:
            widget.display = True
        self._hidden = []

    def _show_decision(self, chat: StepChat, card: Optional[Widget] = None) -> None:
        """A card (the scope or the plan) and the step's menu in the chat, as the step first
        showed them: the same choices plus "Type something." and "Chat about this". You
        decide here exactly as in the menu. The input hides while the menu shows ("Chat
        about this" brings it back). Nothing to decide: just the card, and the input stays."""
        self._drop_decision()
        if card is not None:
            chat.add(card)
        decision = self.decision()
        if decision is None:
            return
        # A class, not an id: the menu shown before may still be leaving the DOM.
        question = Question(
            decision.chip,
            decision.question,
            decision.choices,
            default=decision.default,
            hint=CHAT_MENU_HINT,
            typing=False,  # typing anywhere goes to the chat: no "Type something." row
            type_out=True,  # a typed key brings the input back (on_choice_menu_typed_out)
        )
        question.add_class(CHAT_DECISION)
        chat.add(question)
        for bar in self.query(ChatBar):
            bar.display = False
        # Queued on the question itself, so it runs once the menu is mounted.
        question.call_after_refresh(lambda: question.menu.focus())

    def on_choice_menu_typed_out(self, event: ChoiceMenu.TypedOut) -> None:
        """A key typed on the menu inside the chat: like "Chat about this", the menu goes and
        the input comes back holding that key, so the line is asked as a chat line and a
        typed digit or Enter never picks a choice."""
        event.stop()
        self._drop_decision()
        chats = self.query(StepChat)
        if not chats:
            return
        field = chats.first(StepChat).input
        field.value += event.text  # later keys may still arrive here before the focus moves
        field.cursor_position = len(field.value)
        self.set_focus(field)

    def _drop_decision(self) -> None:
        """Take the menu shown in the chat away and bring the input back."""
        for old in self.query(f".{CHAT_DECISION}"):
            old.remove()
        for bar in self.query(ChatBar):
            bar.display = True

    def _chat_decided(self, choice_id: str) -> None:
        """A choice from the menu inside the chat: "Chat about this" brings the input back;
        anything else closes the chat and does what the step's menu does (the step line moves
        with the store). "Type something." arrives as `ChoiceMenu.Typed` instead."""
        if choice_id == "chat":
            self._drop_decision()
            self.query_one(StepChat).focus_input()
            return
        store.log_event(f"{self.flow_name}.chat.decided", choice_id)
        self._close_chat()
        self._focus_step_menu()  # a dialog the choice opens returns the focus here
        self.decide(choice_id)
        if self._stale and self.app.screen is self:
            self._stale = False
            self.app.reload_screen()

    def _ask_in_chat(self, chat: StepChat, text: str) -> None:
        """Answer a line typed in the step chat. Advice only: the step still waits for you.

        Every line goes to the active model (or gets the built-in reply at once). A line
        asking to change the scope then opens your tick list: the model only explains, you
        tick the change. A line that makes the step's decision ("approve that scope",
        "yes") never reaches the model: Reconix says nothing changed and shows the step's
        menu; a question about it is answered first, then the menu. At the target login the
        store refuses the line, so a password never goes out.
        """
        try:
            echo = store.recorded_line(text)  # masked, as the chat and history keep it
            line = store.say_operator_line(f"About {self.chat_topic()}: {text}")
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        chat.add_you(echo)
        for old in [*self.query(TickList), *self.query(PlanOrder)]:
            old.remove()
        self._drop_decision()
        scope_change = store.wants_scope_change(text)
        view = "" if scope_change else store.wants_view(text)
        card = CARDS[view]() if view else None
        if card is not None:  # its card, never the model's list
            chat.add_reply(store.view_reply(view))  # recorded: the last exchange has it
            self._show_decision(chat, card)
            return
        plan_change = (not scope_change and self.flow_name == "plan"
                       and store.wants_plan_change(text))
        if not scope_change and not plan_change and store.wants_decision(text):
            store.decision_reply()  # only you decide: no model is asked
            entry = store.last_exchange()[1][-1]
            chat.add_reply(entry.text, entry.tone)
            self._show_decision(chat)
            return
        about_decision = not (scope_change or plan_change) and store.asks_about_decision(text)
        reply = chat.add_reply(THINKING, tone="muted")
        gen = self.app.llm_generation()  # the assessment this question was asked in

        def show() -> None:
            replies = store.last_exchange()[1]
            if replies:
                last = replies[-1]
                chat.show_reply(reply, last.text, last.tone, last.author)

        def preview(so_far: str) -> None:
            if gen == self.app.llm_generation() and chat.is_mounted:
                chat.show_reply(reply, so_far, "default")  # the screen only: not recorded

        def done(draft: store.Draft) -> None:
            if gen != self.app.llm_generation():
                return  # another assessment is on screen: record nothing into it
            store.record_draft(draft)
            show()
            if scope_change and chat.is_mounted:
                # The model's ports/tools are offered as rows, never ticked.
                model_reply = "\n".join(e.text for e in store.last_exchange()[1])
                self._scope_reply(chat, text, model_reply)  # whatever it said, you change it
            elif plan_change and chat.is_mounted:
                self._redraft_plan(chat)  # it discussed it; the AI re-drafts, you review
            elif about_decision and chat.is_mounted:
                self._show_decision(chat)  # the model explains; you decide here

        def work() -> None:
            # Built off the UI thread and recorded in `done()`, so a switch while the model
            # is answering can't put this reply in another run; it streams into the screen.
            draft = store.build_draft(
                line, on_text=lambda so_far: self.app.call_from_thread(preview, so_far))
            self.app.call_from_thread(done, draft)

        self.app.run_worker(work, thread=True, group="llm", exit_on_error=False)

    def _scope_reply(self, chat: StepChat, text: str, model_reply: str = "") -> None:
        """Reconix's own line ("Only you can change the scope…"), then your tick list
        (nothing new ticked; the ports/tools the model named are added unticked). Recorded,
        so the model's history has it too. At the Plan step the scope is already approved;
        ticking re-opens it for a fresh approval (store.reopen_scope, in on_tick_list_saved)."""
        choices = store.answer_scope_change(text, model_reply)
        entry = store.last_exchange()[1][-1]
        chat.add_reply(entry.text, entry.tone)
        if choices is not None:
            if store.is_scope_approved():
                chat.add_reply("Tick what to add; the scope re-opens for you to approve again.",
                               tone="muted")
            chat.add(
                TickList(choices.ports, choices.tools, choices.suggested,
                         choices.suggested_tools, focus=choices.focus)
            )

    def _redraft_plan(self, chat: StepChat) -> None:
        """A plan-change request at the Plan step: the AI re-drafts the plan with what you
        said as guidance; the new plan card and menu follow when it is ready."""
        chat.add_reply("Re-drafting the plan with your guidance…", tone="muted")
        self.app.redraft_plan(lambda: self._plan_redrafted(chat))

    def _plan_redrafted(self, chat: StepChat) -> None:
        if not chat.is_mounted:
            return
        self.refresh_view()
        card = plan_card()
        if card is not None:
            chat.add_reply("Here is the re-drafted plan. Run it, or ask for another change.",
                           tone="ok")
        self._show_decision(chat, card)

    def on_tick_list_saved(self, event: TickList.Saved) -> None:
        """Your ticks become the scope (the store validates them); the chat stays open.
        From the Plan step the scope is approved, so it is re-opened first; you then review
        and approve the changed scope on the Scope step, and the AI re-drafts the plan."""
        event.stop()
        approved = store.is_scope_approved()
        try:
            if approved:
                store.reopen_scope()
            network = store.get_scope().kind == "network"
            store.edit_scope(allowed_ports=event.ports if network else None, tools=event.tools)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        event.tick_list.remove()
        chat = self.query_one(StepChat)
        entry = store.last_exchange()[1][-1]
        chat.add_reply(entry.text, entry.tone)
        if approved:
            chat.add_reply("Scope changed. Review and approve it again; then I re-draft the "
                           "plan.", tone="warn")
            self.refresh_view()
            self.app.goto("template")      # the Scope step, to approve the changed scope
            return
        self.refresh_view()
        self._show_decision(chat, scope_card())  # the new scope, as a card, and its menu

    def on_tick_list_cancelled(self, event: TickList.Cancelled) -> None:
        event.stop()
        event.tick_list.remove()
        chat = self.query_one(StepChat)
        chat.add_reply("No change to the scope.", tone="muted")
        chat.focus_input()

    # --- the plan's order (store/plan_order.py) ------------------------------------------------
    def _reorder_reply(self, chat: StepChat) -> None:
        """Reconix's own line (what may move, or why nothing can), then your order list.
        Recorded, so the model's history has it too."""
        ok = store.answer_plan_reorder()
        entry = store.last_exchange()[1][-1]
        chat.add_reply(entry.text, entry.tone)
        if ok:
            chat.add(PlanOrder(store.plan_overview(), store.movable_checks()))
        else:
            self._show_decision(chat, plan_card())

    def on_plan_order_saved(self, event: PlanOrder.Saved) -> None:
        """Your order becomes the plan's (the store checks it and moves the run's steps)."""
        event.stop()
        try:
            store.reorder_gated(event.order)
        except store.StoreValidationError as exc:
            self.notify_error(str(exc))
            return
        event.plan_order.remove()
        chat = self.query_one(StepChat)
        entry = store.last_exchange()[1][-1]
        chat.add_reply(entry.text, entry.tone)
        self.refresh_view()
        self.refresh_live()
        self._show_decision(chat, plan_card())  # the plan in its new order, and the menu

    def on_plan_order_cancelled(self, event: PlanOrder.Cancelled) -> None:
        event.stop()
        event.plan_order.remove()
        chat = self.query_one(StepChat)
        chat.add_reply("No change to the plan.", tone="muted")
        chat.focus_input()

    def notify_error(self, message: str, title: Optional[str] = None) -> None:
        """A store error, shown as plain text (never markup)."""
        self.notify(message, title=title or "", severity="warning", markup=False)
