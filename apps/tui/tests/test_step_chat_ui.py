"""The chat inside a step: "Type something." and "Chat about this" at Scope, Plan, Approval.

The step's menu hides while you chat and comes back on Esc. A line asking to change the
scope opens a tick list (you tick; no model is asked); anything else is answered by the
active model, or by the built-in reply at once.
"""

import pytest
from textual.widgets import SelectionList

from reconix import store
from reconix.llm import client
from reconix.widgets import ChatBar, ChoiceMenu, Question, StepChat, TickList

from .support import SIZE, TEST_PASSWORD, run_to, run_ui_to, screen_text, settle, wait_until

NETWORK = "10.0.0.0/24"


def _fake_model(monkeypatch):
    """Chat calls answer "model answer N"."""
    calls = []

    def complete(pid, model, messages, **kw):
        calls.append(messages)
        return f"model answer {len(calls)}"

    monkeypatch.setattr(client, "complete", complete)
    return calls


def _menu(app) -> ChoiceMenu:
    return app.screen.query(ChoiceMenu).first()


def _type(app, text: str) -> None:
    app.screen.post_message(ChoiceMenu.Typed(_menu(app), text))


def _chat_about_this(app) -> None:
    app.screen.post_message(ChoiceMenu.Chosen(_menu(app), "chat"))


def _chat_text(app) -> str:
    chats = app.screen.query(StepChat)
    return screen_text(chats.first()) if chats else ""


async def _ask(app, pilot, text: str) -> None:
    chat = app.screen.query_one(StepChat)
    chat.input.value = text
    chat.input.focus()
    await pilot.press("enter")
    await settle(pilot)


def _question_shown(app) -> bool:
    return any(q.display for q in app.screen.query(Question))


async def test_type_something_opens_the_chat_and_hides_the_menu(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        _type(app, "looks fine")
        await wait_until(pilot, lambda: "looks fine" in _chat_text(app), what="the chat")
        assert store.list_feedback()[-1].text == "looks fine"
        assert "◆ reconix" in _chat_text(app)  # the built-in reply, at once
        assert "thinking" not in _chat_text(app)
        assert not _question_shown(app)
        assert store.waiting_gate() == "scope"  # still waits for you


async def test_the_model_answers_and_you_stay_in_chat(app, model_active, monkeypatch):
    calls = _fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        _type(app, "why these ports?")
        await wait_until(pilot, lambda: "model answer 1" in _chat_text(app), what="answer 1")
        assert calls[-1][-1]["content"].startswith("About ")
        await _ask(app, pilot, "and the tools?")
        await wait_until(pilot, lambda: "model answer 2" in _chat_text(app), what="answer 2")
        assert app.screen.query_one(StepChat).input.has_focus
        assert not store.is_scope_approved()


async def test_chat_about_this_shows_the_scope_and_esc_brings_the_menu_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        _chat_about_this(app)
        await wait_until(pilot, lambda: "Scope ·" in _chat_text(app), what="the scope text")
        text = _chat_text(app)
        assert NETWORK in text and "Ports:" in text and "nmap" in text
        assert not _question_shown(app)
        await pilot.press("escape")
        await settle(pilot)
        assert not app.screen.query(StepChat)
        assert _question_shown(app)
        assert _menu(app).has_focus
        assert store.waiting_gate() == "scope"


async def test_chat_about_this_at_the_plan_prints_the_plan(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        _chat_about_this(app)
        await wait_until(pilot, lambda: "Plan ·" in _chat_text(app), what="the plan text")
        text = _chat_text(app)
        assert "1. Host discovery" in text and "nmap, testssl.sh" in text
        assert not app.screen.query_one("#plan-list").display


async def test_chat_about_this_at_an_approval_prints_the_action(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "approval:approval-001")
        _chat_about_this(app)
        await wait_until(pilot, lambda: "Approval ·" in _chat_text(app), what="the approval")
        assert "risk" in _chat_text(app)
        assert store.list_approval_decisions() == []


async def test_asking_to_add_a_port_opens_your_tick_list(app, model_active, monkeypatch):
    calls = _fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        _type(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        assert "model answer 1" in _chat_text(app)  # the model answers it first
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
        assert "3389" in _chat_text(app)
        assert app.screen.query(StepChat)  # you stay in chat


async def test_esc_on_the_tick_list_changes_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        _type(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        assert "Only you can change the scope" in _chat_text(app)   # the built-in reply
        app.screen.query_one(SelectionList).select("port:3389")
        await pilot.press("escape")
        await settle(pilot)
        assert store.get_scope().allowed_ports == before
        assert app.screen.query(StepChat)
        assert "No change to the scope" in _chat_text(app)


async def test_the_approved_scope_cannot_change_from_the_chat(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        _type(app, "add port 3389")
        await wait_until(pilot, lambda: "locked" in _chat_text(app), what="the reply")
        assert not app.screen.query(TickList)
        assert 3389 not in store.get_scope().allowed_ports


async def test_typed_markup_shows_literally(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        _type(app, "is [bold]this[/bold] ok?")
        await wait_until(pilot, lambda: "[bold]this[/bold]" in _chat_text(app), what="echo")


def test_a_line_typed_at_the_login_is_refused(model_active, monkeypatch):
    """The chat records the line with `say_operator_line`, which refuses at the login, so
    the model is never called (a password typed there never goes out)."""
    calls = _fake_model(monkeypatch)
    run_to("account")
    with pytest.raises(store.StoreValidationError, match="login"):
        store.say_operator_line(f"About execution: password is {TEST_PASSWORD}")
    assert calls == []


async def test_the_question_box_is_pinned_at_the_bottom(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        _type(app, "hello")
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
        _type(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        text = _chat_text(app)
        assert text.index("has been added") < text.index("Only you can change the scope")
        assert store.list_chat()[-1].text == scope_ask.ONLY_YOU   # in the model's history
        assert store.get_scope().allowed_ports == before
    assert "Never say you changed" in guardrail.SYSTEM_PROMPT
