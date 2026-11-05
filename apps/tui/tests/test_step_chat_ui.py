"""The chat inside a step: "Type something." and "Chat about this" at Scope, Plan, Approval.

The step's menu hides while you chat and comes back on Esc. A line asking to change the
scope opens a tick list (you tick; no model is asked); anything else is answered by the
active model, or by the built-in reply at once.
"""

import pytest
from textual.widgets import SelectionList

from reconix import store
from reconix.llm import client
from reconix.widgets import (
    ChatBar, ChoiceMenu, FlowProgress, PlanOrder, PlanPanel, Question, ScopePanel, StepChat,
    TickList, UserMessage,
)

from .support import (
    NETWORK, SIZE, TEST_PASSWORD, ask_in_chat, chat_about_this, chat_menu, chat_menu_ready,
    chat_text, fake_model, run_to, run_ui_to, screen_text, settle, step_menu, type_in_menu,
    wait_until,
)


def _question_shown(app) -> bool:
    return any(q.display for q in app.screen.query(Question) if not q.has_class("chat-decision"))


def _chat_choices(app) -> list:
    """The labels of the menu inside the chat."""
    menu = chat_menu(app)
    return [choice.label for choice in menu._choices] if menu else []


def _step_line(app) -> str:
    return str(app.screen.query_one(FlowProgress).render())


async def test_type_something_opens_the_chat_and_hides_the_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "looks fine")
        await wait_until(pilot, lambda: "looks fine" in chat_text(app), what="the chat")
        assert store.list_feedback()[-1].text == "looks fine"
        assert "◆ reconix" in chat_text(app)  # the built-in reply, at once
        assert "thinking" not in chat_text(app)
        assert not _question_shown(app)
        assert store.waiting_gate() == "scope"  # still waits for you


async def test_the_model_answers_and_you_stay_in_chat(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "why these ports?")
        await wait_until(pilot, lambda: "model answer 1" in chat_text(app), what="answer 1")
        assert calls[-1][-1]["content"].startswith("About ")
        await ask_in_chat(app, pilot, "and the tools?")
        await wait_until(pilot, lambda: "model answer 2" in chat_text(app), what="answer 2")
        assert app.screen.query_one(StepChat).input.has_focus
        assert not store.is_scope_approved()


async def test_chat_about_this_shows_the_scope_card_and_esc_brings_the_menu_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(ScopePanel)), what="the card")
        await settle(pilot)
        chat = app.screen.query_one(StepChat)
        assert chat.query(ScopePanel)                       # the card, as on the screen
        text = chat_text(app)
        assert NETWORK in text and "nmap" in text
        assert chat_menu(app) is None                      # you came to talk, not decide
        assert chat.input.has_focus
        assert not _question_shown(app)
        await pilot.press("escape")
        await settle(pilot)
        assert not app.screen.query(StepChat)
        assert _question_shown(app)
        assert step_menu(app).has_focus
        assert store.waiting_gate() == "scope"


async def test_chat_about_this_at_the_plan_prints_the_plan(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(PlanPanel)), what="the card")
        text = screen_text(app.screen.query_one(PlanPanel))
        assert "Host discovery" in text and "nmap, testssl.sh" in text
        assert not app.screen.query_one("#plan-list").display


async def test_chat_about_this_at_an_approval_prints_the_action(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "approval:approval-001")
        chat_about_this(app)
        await wait_until(pilot, lambda: "Approval ·" in chat_text(app), what="the approval")
        assert "risk" in chat_text(app)
        assert store.list_approval_decisions() == []


async def test_asking_to_add_a_port_opens_your_tick_list(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        assert "model answer 1" in chat_text(app)  # the model answers it first
        assert len(calls) == 1
        rows = app.screen.query_one(SelectionList)
        ticked = {f"port:{p}" for p in before} | {f"tool:{t}" for t in store.get_scope().tools}
        assert set(rows.selected) == ticked  # only what the scope allows today
        assert "port:3389" not in rows.selected  # nothing new ticked for you
        rows.select("port:3389")  # you tick it
        rows.focus()
        await pilot.press("enter")
        await settle(pilot)
        assert 3389 in store.get_scope().allowed_ports
        assert not app.screen.query(TickList)
        assert "3389" in chat_text(app)
        assert app.screen.query(StepChat)  # you stay in chat


async def test_esc_on_the_tick_list_changes_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        assert "Only you can change the scope" in chat_text(app)   # the built-in reply
        app.screen.query_one(SelectionList).select("port:3389")
        await pilot.press("escape")
        await settle(pilot)
        assert store.get_scope().allowed_ports == before
        assert app.screen.query(StepChat)
        assert "No change to the scope" in chat_text(app)


async def test_the_approved_scope_cannot_change_from_the_chat(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: "locked" in chat_text(app), what="the reply")
        assert not app.screen.query(TickList)
        assert 3389 not in store.get_scope().allowed_ports


async def test_typed_markup_shows_literally(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "is [bold]this[/bold] ok?")
        await wait_until(pilot, lambda: "[bold]this[/bold]" in chat_text(app), what="echo")


def test_a_line_typed_at_the_login_is_refused(model_active, monkeypatch):
    """The chat records the line with `say_operator_line`, which refuses at the login, so
    the model is never called (a password typed there never goes out)."""
    calls = fake_model(monkeypatch)
    run_to("account")
    with pytest.raises(store.StoreValidationError, match="login"):
        store.say_operator_line(f"About execution: password is {TEST_PASSWORD}")
    assert calls == []


async def test_the_question_box_is_pinned_at_the_bottom(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        type_in_menu(app, "hello")
        await wait_until(pilot, lambda: bool(app.screen.query(ChatBar)), what="the bar")
        await settle(pilot)
        bar = app.screen.query_one(ChatBar)
        body = app.screen.query_one("#body")
        assert bar.region.bottom == body.region.bottom       # docked under the chat
        assert bar.query_one("#step-chat-input").has_focus
        await pilot.press("escape")
        await settle(pilot)
        assert not app.screen.query(ChatBar)


async def test_a_model_claiming_it_changed_the_scope_is_corrected(app, model_active, monkeypatch):
    """A model may say "added"; Reconix's own line follows it and the scope is unchanged."""
    from reconix.llm import guardrail
    from reconix.store import scope_ask

    monkeypatch.setattr(client, "complete", lambda *a, **k: "Port 3389 has been added.")
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        text = chat_text(app)
        assert text.index("has been added") < text.index("Only you can change the scope")
        assert store.list_chat()[-1].text == scope_ask.ONLY_YOU   # in the model's history
        assert store.get_scope().allowed_ports == before
    assert "Never say you changed" in guardrail.SYSTEM_PROMPT


# --- a decision typed in the chat: the step's own menu, never the model ---------------------
async def test_a_typed_decision_shows_the_menu_and_no_model_is_asked(app, model_active,
                                                                     monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "apporve that scope")                   # a typo still counts
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert calls == []                                 # the model never saw it
        text = chat_text(app)
        assert "nothing is approved" in text and "Only you decide this" in text
        assert _chat_choices(app) == ["Approve scope", "Edit manifest", "Reject",
                                      "Chat about this"]   # typing anywhere goes to the chat
        assert "1. Approve scope" not in chat_text(app)     # no numbers: a digit types
        assert "type to chat" in chat_text(app)
        assert not app.screen.query_one(ChatBar).display   # the menu, not the input
        assert not store.is_scope_approved()
        # The focus is queued until the menu has drawn: wait for it, don't race it.
        await wait_until(pilot, lambda: chat_menu(app).has_focus, what="the menu focused")
        await pilot.press("enter")                         # 1. Approve scope
        await wait_until(pilot, lambda: store.waiting_gate() == "plan", what="the plan gate")
        await settle(pilot)
        assert store.is_scope_approved()
        assert not app.screen.query(StepChat)              # the chat closed
        line = _step_line(app)
        assert "✓ Template" in line and "! Plan" in line   # the step line moved


async def test_typing_on_the_chat_menu_brings_the_input_back_and_is_answered(
    app, model_active, monkeypatch
):
    """A second line typed while the menu shows goes to the input (like "Chat about this")
    and is asked; its Enter never picks the highlighted "Approve scope"."""
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "yes")  # line 1: the menu shows
        menu = await chat_menu_ready(app, pilot)
        assert menu.highlighted_id == "approve"
        for key in "what is this":  # line 2, typed on the menu
            await pilot.press("space" if key == " " else key)
        chat = app.screen.query_one(StepChat)
        assert chat.input.value == "what is this" and chat.input.has_focus
        assert chat_menu(app) is None  # the menu went
        assert app.screen.query_one(ChatBar).display  # the input is back
        await pilot.press("enter")
        await wait_until(
            pilot, lambda: "model answer 1" in chat_text(app), what="the reply to line 2"
        )
        assert len(calls) == 1 and "what is this" in calls[0][-1]["content"]
        assert not store.is_scope_approved()  # typing decided nothing
        assert store.waiting_gate() == "scope"
        assert app.screen.query(StepChat) and chat_menu(app) is None
        assert app.screen.query_one(ChatBar).display
        assert "what is this" not in [f.text for f in store.list_feedback()]  # a chat line


async def test_a_digit_on_the_chat_menu_types_and_never_approves(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "yes")
        await chat_menu_ready(app, pilot)
        await pilot.press("1")  # outside the chat: 1 = Approve
        await settle(pilot)
        chat = app.screen.query_one(StepChat)
        assert chat.input.value == "1" and chat.input.has_focus
        assert chat_menu(app) is None
        assert not store.is_scope_approved()
        assert store.waiting_gate() == "scope"


async def test_chat_about_this_in_the_chat_menu_brings_the_input_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "yes")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), "chat"))
        await settle(pilot)
        assert chat_menu(app) is None
        assert app.screen.query_one(ChatBar).display
        assert app.screen.query_one(StepChat).input.has_focus
        assert not store.is_scope_approved()
        assert store.waiting_gate() == "scope"


async def test_a_saved_tick_list_shows_the_new_scope_card_and_the_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        rows.select("port:3389")
        rows.focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        chat = app.screen.query_one(StepChat)
        [card] = chat.query(ScopePanel)
        assert "3389" in screen_text(card) and "draft" in str(card.border_subtitle)
        assert "Scope updated" in chat_text(app)
        assert not store.is_scope_approved()


async def test_show_the_scope_prints_the_card(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "show the scope")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert app.screen.query_one(StepChat).query(ScopePanel)


async def test_yes_at_the_plan_shows_the_plan_menu_and_run_plan_runs(app, model_active,
                                                                     monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        await wait_until(pilot, lambda: not store.plan_drafting(), what="the plan draft")
        type_in_menu(app, "yes")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert calls == []
        assert _chat_choices(app)[0] == "Run plan" and "nothing has run" in chat_text(app)
        assert not store.is_plan_started()
        app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), "run"))
        await wait_until(pilot, store.is_plan_started, what="the plan to run")


async def test_a_question_about_the_decision_is_answered_then_the_menu(app, model_active,
                                                                       monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "should I approve it?")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert len(calls) == 1 and "model answer 1" in chat_text(app)
        assert not store.is_scope_approved()


async def test_approve_in_chat_keeps_the_high_double_check(app):
    from reconix.screens.approval import ApprovalScreen
    from reconix.screens.choice import ChoiceScreen

    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "approval:approval-002")
        await wait_until(pilot, lambda: isinstance(app.screen, ApprovalScreen), what="approval")
        type_in_menu(app, "approve")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        app.screen.post_message(ChoiceMenu.Chosen(chat_menu(app), "approve"))
        await wait_until(pilot, lambda: isinstance(app.screen, ChoiceScreen),
                         what="the double check")
        assert store.decision_for("approval-002") is None   # nothing approved yet


async def test_a_new_menu_replaces_the_one_shown_before(app):
    """Saving the ticks shows a menu; typing a decision right after shows a new one (it
    crashed with a duplicate id while the first was still leaving)."""
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "add more scope")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        rows.focus()
        await pilot.press("enter")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the first menu")
        await ask_in_chat(app, pilot, "apporve that scope")
        await ask_in_chat(app, pilot, "yes")
        await settle(pilot)
        assert len(app.screen.query(".chat-decision")) == 1
        await wait_until(pilot, lambda: chat_menu(app).has_focus, what="the menu focused")
        await pilot.press("enter")
        await wait_until(pilot, store.is_scope_approved, what="the approval")


async def test_the_plan_shows_your_request_not_the_chat_line(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        type_in_menu(app, "apporve that scope")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        await pilot.press("enter")
        await wait_until(pilot, lambda: store.waiting_gate() == "plan", what="the plan gate")
        app.goto("plan")
        await settle(pilot)
        [shown] = app.screen.query(UserMessage)
        assert NETWORK in str(shown.content) and "apporve" not in str(shown.content)


# --- the model's ports, the plan card and the plan's order ----------------------------------
async def test_ports_the_model_names_are_offered_unticked(app, model_active, monkeypatch):
    reply = ("To scan 12 ports, add port 4000 along with 21 (FTP), 23 (Telnet) and "
             "3306 (MySQL).")
    monkeypatch.setattr(client, "complete", lambda *a, **k: reply)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "i need to add more port to 4000 also and i need 12 port to scan")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        rows = app.screen.query_one(SelectionList)
        values = [rows.get_option_at_index(i).value for i in range(rows.option_count)]
        for port in (4000, 21, 23, 3306):
            assert f"port:{port}" in values and f"port:{port}" not in rows.selected
        assert "port:12" not in values                      # a count, not a port
        prompt = rows.get_option_at_index(values.index("port:21")).prompt
        assert "suggested by the model" in str(prompt)
        assert store.get_scope().allowed_ports == before    # nothing changed by itself


async def test_give_the_plan_shows_the_plan_card_and_the_menu(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(StepChat)), what="the chat")
        await ask_in_chat(app, pilot, "give the plan")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert calls == []                                  # the card, not the model's list
        assert len(app.screen.query_one(StepChat).query(PlanPanel)) == 2
        assert _chat_choices(app)[0] == "Run plan"


async def test_a_reorder_is_discussed_then_you_order_it(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        first, second = [a.request_id for a in store.get_assessment().approvals]
        type_in_menu(app, "can we change the 3a and 3b to first 1")
        await wait_until(pilot, lambda: bool(app.screen.query(PlanOrder)), what="the order")
        assert len(calls) == 1 and "model answer 1" in chat_text(app)   # discussed first
        assert "Only you can change the order" in chat_text(app)
        assert [a.request_id for a in store.get_assessment().approvals] == [first, second]
        await pilot.press("shift+up")                       # a fixed phase: refused
        assert "fixed" in chat_text(app)
        await pilot.press("shift+down")                     # 3a below 3b
        await pilot.press("enter")
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert [a.request_id for a in store.get_assessment().approvals] == [second, first]
        card = app.screen.query_one(StepChat).query(PlanPanel).last()
        text = screen_text(card)
        assert text.index(store.get_approval(second).action) < \
            text.index(store.get_approval(first).action)
        assert _chat_choices(app)[0] == "Run plan"
        assert not store.is_plan_started()


async def test_esc_on_the_order_list_changes_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        order = [a.request_id for a in store.get_assessment().approvals]
        type_in_menu(app, "move 3b before 3a")
        await wait_until(pilot, lambda: bool(app.screen.query(PlanOrder)), what="the order")
        await pilot.press("shift+down", "escape")
        await settle(pilot)
        assert [a.request_id for a in store.get_assessment().approvals] == order
        assert "No change to the plan" in chat_text(app)


# --- a second change in the same chat: a fresh list, never a duplicate id -------------------
def _mounted(app, kind) -> list:
    return [w for w in app.screen.query(kind) if w.is_mounted]


@pytest.mark.parametrize("mock", [True, False], ids=["mock", "no-model"])
async def test_a_second_scope_change_shows_a_fresh_tick_list(app, mock):
    """RULE-04: Reconix answers alone (mock or no model), so the new list is mounted while
    the old one is still leaving; it must not clash with it."""
    if mock:
        store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        await ask_in_chat(app, pilot, "add 3389, 0, 99999, 8080 and then scan 12 ports")
        await wait_until(pilot, lambda: len(_mounted(app, TickList)) == 1, what="one list")
        await settle(pilot)
        (ticks,) = _mounted(app, TickList)
        rows = ticks.query_one(SelectionList)
        assert rows.has_focus                               # Space/Enter work at once
        values = [rows.get_option_at_index(i).value for i in range(rows.option_count)]
        assert "port:3389" in values and "port:0" not in values and "port:99999" not in values
        assert "port:12" not in values                      # a count, not a port
        assert chat_text(app).count("Only you can change the scope") == 2
        assert store.get_scope().allowed_ports == before    # nothing changed by typing
        await pilot.press("enter")                          # the new list saves
        await wait_until(pilot, lambda: bool(chat_menu(app)), what="the menu in the chat")
        assert not _mounted(app, TickList)


@pytest.mark.parametrize("mock", [True, False], ids=["mock", "no-model"])
async def test_a_second_reorder_shows_a_fresh_order_list(app, mock):
    if mock:
        store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        before = store.plan_overview()
        type_in_menu(app, "move 3b before 3a")
        await wait_until(pilot, lambda: bool(app.screen.query(PlanOrder)), what="the order")
        await ask_in_chat(app, pilot, "move 3b before 3a please")
        await wait_until(pilot, lambda: len(_mounted(app, PlanOrder)) == 1, what="one list")
        await settle(pilot)
        assert chat_text(app).count("Only you can change the order") == 2
        assert store.plan_overview() == before              # nothing moved by typing
