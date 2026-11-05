"""A line starting with / in a step chat (or on "Type something.") runs that command.

It runs as from the command bar: never sent to the model, never saved as feedback, and it
decides no gate. A command that moves to another screen takes the chat with it; one that
stays (a dialog) leaves the chat open with a "Ran /name." line. A path ("/api/v1 …") is
still a chat line; an unknown "/xyz" gets the bar's error in the chat.
"""

import pytest

from reconix import store
from reconix.screens import ApprovalScreen, PlanScreen
from reconix.widgets import StepChat

from .support import (
    NETWORK, SIZE, ask_in_chat, chat_about_this, chat_text, pass_gate, run_ui_to, screen_text,
    settle, type_in_menu, wait_for_run, wait_until,
)


@pytest.fixture
def api_ok(model_active):
    """The active model is approved for the Core API (/provider's OK), so chat lines go there."""
    store.core_api_approve()


def _chats(fake_api) -> list:
    """What reached the Core API's chat route."""
    return [body["content"] for m, path, body, _ in fake_api.calls
            if m == "POST" and path.endswith("/chat")]


async def _open_chat(app, pilot, gate: str = "scope") -> None:
    await run_ui_to(app, pilot, gate, request=NETWORK)
    chat_about_this(app)
    await wait_until(pilot, lambda: bool(app.screen.query(StepChat)), what="the step chat")


def _nothing_asked_or_kept(fake_api, text: str) -> None:
    assert _chats(fake_api) == []  # the AI never saw it
    assert all(text not in entry.text for entry in store.list_chat())


async def test_slash_plan_in_the_step_chat_opens_the_plan(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "/plan")
        await wait_until(pilot, lambda: isinstance(app.screen, PlanScreen), what="the plan")
        assert not app.screen.query(StepChat)  # the chat went with the screen
        _nothing_asked_or_kept(fake_api, "/plan")
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()


async def test_a_command_that_stays_keeps_the_chat_open(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        step = app.screen
        await ask_in_chat(app, pilot, "/audit")  # a dialog over the step
        await settle(pilot)
        assert step in app.screen_stack
        assert "Ran /audit." in screen_text(step.query_one(StepChat))
        _nothing_asked_or_kept(fake_api, "/audit")
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()


async def test_a_path_line_is_still_a_chat_line(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "/api/v1 in scope?")
        await wait_until(pilot, lambda: fake_api.reply in chat_text(app), what="the reply")
        [sent] = _chats(fake_api)
        assert "/api/v1 in scope?" in sent and "(Reconix app: step" in sent
        assert "Ran /" not in chat_text(app)


async def test_an_unknown_command_shows_the_error_and_asks_nothing(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await _open_chat(app, pilot)
        await ask_in_chat(app, pilot, "/xyz")
        text = chat_text(app)
        assert 'Unknown command "/xyz"' in text
        assert app.screen.query_one(StepChat).input.has_focus  # still chatting
        _nothing_asked_or_kept(fake_api, "/xyz")


async def test_slash_plan_on_type_something_runs_and_is_not_feedback(
    app, api_ok, fake_api
):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = len(store.list_feedback())
        type_in_menu(app, "/plan")  # "Type something." on the menu
        await wait_until(pilot, lambda: isinstance(app.screen, PlanScreen), what="the plan")
        assert len(store.list_feedback()) == before
        _nothing_asked_or_kept(fake_api, "/plan")
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()


async def test_a_command_in_the_chat_never_decides_the_gate(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        await pass_gate(app, pilot)                     # Run plan: LOW runs, MEDIUM waits
        await wait_for_run(pilot)
        gate = store.waiting_gate()
        assert gate.startswith("approval:")
        chat_about_this(app)
        await wait_until(pilot, lambda: bool(app.screen.query(StepChat)), what="the step chat")
        await ask_in_chat(app, pilot, "/approval")  # the same step, rebuilt
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert store.waiting_gate() == gate
        assert store.decision_for(gate[9:]) is None
        assert _chats(fake_api) == []
