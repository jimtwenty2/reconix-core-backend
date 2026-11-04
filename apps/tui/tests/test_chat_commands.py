"""A line starting with / in a step chat (or on "Type something.") runs that command.

It runs as from the command bar: never sent to the model, never saved as feedback, and it
decides no gate. A command that moves to another screen takes the chat with it; one that
stays (a dialog) leaves the chat open with a "Ran /name." line. A path ("/api/v1 …") is
still a chat line; an unknown "/xyz" gets the bar's error in the chat.
"""

from reconix import store
from reconix.screens import ApprovalScreen, ExecutionScreen, PlanScreen
from reconix.store import replies
from reconix.widgets import ChoiceMenu, StepChat

from .support import (
    NETWORK, SIZE, ask_in_chat, chat_about_this, chat_text, fake_model, run_ui_to, screen_text,
    settle, toasts, type_in_menu, wait_until,
)


async def _open_chat(app, pilot, gate: str = "scope") -> None:
    await run_ui_to(app, pilot, gate, request=NETWORK)
    chat_about_this(app)
    await wait_until(pilot, lambda: bool(app.screen.query(StepChat)), what="the step chat")


def _nothing_asked_or_kept(calls, text: str) -> None:
    assert calls == []  # the model never saw it
    assert all(text not in entry.text for entry in store.list_chat())


async def test_slash_plan_in_the_step_chat_opens_the_plan(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "/plan")
        await wait_until(pilot, lambda: isinstance(app.screen, PlanScreen), what="the plan")
        assert not app.screen.query(StepChat)  # the chat went with the screen
        _nothing_asked_or_kept(calls, "/plan")
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()


async def test_a_command_that_stays_keeps_the_chat_open(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        step = app.screen
        await ask_in_chat(app, pilot, "/audit")  # a dialog over the step
        await settle(pilot)
        assert step in app.screen_stack
        assert "Ran /audit." in screen_text(step.query_one(StepChat))
        _nothing_asked_or_kept(calls, "/audit")
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()


async def test_a_path_line_is_still_a_chat_line(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "/api/v1 in scope?")
        await wait_until(pilot, lambda: "model answer 1" in chat_text(app), what="the reply")
        assert len(calls) == 1 and "/api/v1 in scope?" in calls[0][-1]["content"]
        assert "Ran /" not in chat_text(app)


async def test_an_unknown_command_shows_the_error_and_asks_nothing(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "/xyz")
        text = chat_text(app)
        assert 'Unknown command "/xyz"' in text
        assert app.screen.query_one(StepChat).input.has_focus  # still chatting
        _nothing_asked_or_kept(calls, "/xyz")


async def test_slash_plan_on_type_something_runs_and_is_not_feedback(
    app, model_active, monkeypatch
):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = len(store.list_feedback())
        type_in_menu(app, "/plan")  # "Type something." on the menu
        await wait_until(pilot, lambda: isinstance(app.screen, PlanScreen), what="the plan")
        assert len(store.list_feedback()) == before
        _nothing_asked_or_kept(calls, "/plan")
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()


async def test_a_command_in_the_chat_never_decides_the_gate(app, model_active, monkeypatch):
    calls = fake_model(monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot, "approval:approval-001")
        await ask_in_chat(app, pilot, "/approval")  # the same step, rebuilt
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert store.waiting_gate() == "approval:approval-001"
        assert store.decision_for("approval-001") is None
        assert calls == []


async def test_without_a_model_the_reply_at_scope_review_fits_the_step(app):
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "tell me a joke")
        await wait_until(
            pilot, lambda: store.list_chat()[-1].text == replies.RUNNING, what="the built-in reply"
        )
        assert "take new instructions" not in replies.RUNNING
        assert "changes nothing" in replies.RUNNING and "/new" in replies.RUNNING


async def test_a_command_line_at_the_target_login_runs_nothing(app):
    """At the target login a typed line may be the password: "/new <password>" is refused
    before it could run as a command, so no assessment starts and no history line is kept."""
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "account")
        step = next(s for s in app.screen_stack if isinstance(s, ExecutionScreen))
        assessments, history = len(store.list_assessments()), store.list_history()
        step.post_message(StepChat.Asked(StepChat(), "/new Xyz123"))
        step.post_message(ChoiceMenu.Typed(ChoiceMenu(), "/new Xyz123"))
        await settle(pilot)
        assert len(store.list_assessments()) == assessments   # /new did not run
        assert store.list_history() == history                # nothing kept
        assert store.waiting_gate() == "account"
        assert sum("target login" in t for t in toasts(app)) == 2   # refused, both ways
