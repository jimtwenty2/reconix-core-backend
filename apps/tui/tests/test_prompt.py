"""The Start prompt: slash suggestions, completion, history, replies, and the command bar."""

import os

import pytest

from reconix import store
from reconix.commands import COMMANDS
from reconix.screens import (
    ChoiceScreen, CommandBarScreen, FindingsListScreen, HelpScreen, PlanScreen, StartScreen,
    TemplateScreen,
)
from reconix.widgets import PromptBox, UserMessage

from .support import SIZE, settle, show, wait_until


def box(app) -> PromptBox:
    return app.screen.query_one(PromptBox)


async def test_slash_opens_every_command(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash")
        await pilot.pause()
        assert box(app).menu_open
        assert box(app).menu.option_count == len(COMMANDS)


async def test_suggestions_open_above_the_input_without_moving_it(app):
    async with app.run_test(size=SIZE) as pilot:
        before = box(app).input.region
        await pilot.press("slash")
        await pilot.pause()
        assert box(app).input.region == before
        assert box(app).menu.region.bottom == before.y


async def test_typing_filters_and_enter_runs_the_highlighted_command(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "f", "i")
        await pilot.pause()
        assert box(app).menu.option_count == 2
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)
        assert store.list_history()[-1] == "/findings"


async def test_tab_completes_and_enter_asks_for_the_argument(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("slash", "e", "x", "p", "tab")
        await pilot.pause()
        assert box(app).input.value == "/export "
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)


async def test_conversation_history_is_scrollable(app):
    # Earlier exchanges stay on screen (above the current one) so you can scroll back.
    async with app.run_test(size=SIZE) as pilot:
        app.submit_request("my first question")
        await settle(pilot)
        app.submit_request("my second question")
        await settle(pilot)
        shown = [str(w.render()) for w in app.screen.query(UserMessage)]
        assert any("my first question" in m for m in shown)    # scrollback kept
        assert any("my second question" in m for m in shown)   # current exchange
        assert app.screen.query("#start-conversation")         # in the scrollable container


async def _ask(app, pilot, text: str) -> str:
    """Type a question at Start; return the reply once the Core API's answer is in."""
    box(app).input.value = text
    await pilot.press("enter")
    await settle(pilot)
    await wait_until(pilot, lambda: "API" in str(app.screen.query_one("#start-reply").render())
                     or "couldn't answer" in str(app.screen.query_one("#start-reply").render()),
                     what="the reply")
    return str(app.screen.query_one("#start-reply").render())


async def test_a_question_gets_the_apis_answer_and_nothing_starts(app, local_model):
    async with app.run_test(size=SIZE) as pilot:
        reply = await _ask(app, pilot, "hello")
        assert isinstance(app.screen, StartScreen)
        assert not store.get_run().started
        assert "› hello" in str(app.screen.query_one(".user-msg").render())
        assert "The API's answer." in reply


async def test_without_a_local_model_the_core_apis_own_model_answers(app):
    async with app.run_test(size=SIZE) as pilot:
        reply = await _ask(app, pilot, "hello")
        assert "The API's answer." in reply


async def test_a_target_starts_the_run_and_shows_the_request(app):
    async with app.run_test(size=SIZE) as pilot:
        box(app).input.value = "scan https://staging.example.com [now]"
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert store.list_requests()[-1].text == "scan https://staging.example.com [now]"
        assert "[now]" in str(app.screen.query_one(".user-msg").render())


def _slash_path(folder, monkeypatch) -> str:
    """`folder` written from the root as "/…" (on Windows: of the drive we chdir onto)."""
    monkeypatch.chdir(folder)
    return "/" + os.path.splitdrive(str(folder))[1].lstrip("\\/").replace("\\", "/")


async def test_a_local_path_is_a_target_not_a_command(app, tmp_path, monkeypatch):
    path = _slash_path(tmp_path, monkeypatch)
    async with app.run_test(size=SIZE) as pilot:
        box(app).input.value = path
        await pilot.press("enter")
        await settle(pilot)
        assert store.get_assessment().template_id == "source"


async def test_a_missing_local_path_is_refused_and_nothing_starts(app):
    async with app.run_test(size=SIZE) as pilot:
        box(app).input.value = "/does/not/exist"
        await pilot.press("enter")
        await settle(pilot)
        assert not store.get_run().started
        assert "doesn't exist" in box(app).message
        assert box(app).input.value == "/does/not/exist"           # kept, so you can fix it


async def test_rejected_request_keeps_the_text(app):
    async with app.run_test(size=SIZE) as pilot:
        box(app).input.value = "x" * 501
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert box(app).input.value == "x" * 501


async def test_unknown_command_keeps_the_text(app):
    async with app.run_test(size=SIZE) as pilot:
        box(app).input.value = "/scope"                       # renamed to /template
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert box(app).input.value == "/scope"


async def test_up_recalls_history(app):
    store.add_history("/plan")
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("up")
        await pilot.pause()
        assert box(app).input.value == "/plan"
        assert not box(app).menu_open
        await pilot.press("up")                           # nothing older: no demo request
        assert box(app).input.value == "/plan"


async def test_question_mark_opens_help_only_on_an_empty_prompt(app):
    async with app.run_test(size=SIZE) as pilot:
        await pilot.press("question_mark")
        await settle(pilot)
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("escape")
        await settle(pilot)
        await pilot.press("a", "question_mark")
        await pilot.pause()
        assert box(app).input.value == "a?"


# --- the command bar on screens without a prompt ---------------------------------------------
async def open_bar(app, pilot) -> PromptBox:
    await pilot.press("slash")
    await settle(pilot)
    assert isinstance(app.screen, CommandBarScreen)
    return app.screen.query_one(PromptBox)


async def test_the_bar_runs_a_command_and_closes(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        depth = len(app.screen_stack)
        await open_bar(app, pilot)
        await pilot.press("p", "l", "a", "enter")
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)
        assert len(app.screen_stack) == depth


async def test_the_bar_refuses_plain_text(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        bar = await open_bar(app, pilot)
        bar.input.value = "scan everything"
        await pilot.press("enter")
        await settle(pilot)
        assert isinstance(app.screen, CommandBarScreen)
        assert store.list_requests() == []


@pytest.fixture
def local_model(reachable):
    """A model on this computer, active here: the Core API uses it at once (no approval)."""
    store.set_provider("ollama", base_url="http://127.0.0.1:11434", models=["llama3.2"])
    store.test_provider("ollama")
    store.activate("ollama", "llama3.2")
