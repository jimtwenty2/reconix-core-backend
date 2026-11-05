"""QA-013: Ctrl+C (and /stop) stops a run on every flow screen, always asking first."""

import pytest

from reconix import store
from reconix.screens import ChoiceScreen, HelpScreen
from reconix.widgets import PromptBox

from .support import SIZE, decide, play_until_gate, run_to, screen_text, settle, show


def _run_to(gate: str) -> None:
    """Run to `gate`; "approval" is the run's first approval gate (the API's MEDIUM step)."""
    if gate != "approval":
        run_to(gate)
        return
    run_to("plan")
    decide("plan")
    assert play_until_gate().startswith("approval:")


async def _stop_through_the_dialog(app, pilot) -> None:
    await pilot.press("ctrl+c")
    await settle(pilot)
    assert isinstance(app.screen, ChoiceScreen)
    assert "Stop this assessment?" in screen_text(app.screen)
    await pilot.press("down", "enter")  # Stop now
    await settle(pilot)


@pytest.mark.parametrize(
    "gate, screen",
    [
        ("scope", "template"),  # scope review
        ("plan", "plan"),  # plan review
        ("approval", "approval"),  # MEDIUM approval
        ("approval", "start"),  # back on the Start prompt (focused)
        ("approval", "findings"),  # a parked run seen from Findings
    ],
)
async def test_ctrl_c_asks_then_stops_on_every_flow_screen(app, gate, screen):
    _run_to(gate)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, screen)
        await _stop_through_the_dialog(app, pilot)
        assert store.get_run().stopped == "you stopped it"
        assert not isinstance(app.screen, ChoiceScreen)


async def test_ctrl_c_keep_running_is_the_default(app):
    run_to("scope")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "template")
        await pilot.press("ctrl+c")
        await settle(pilot)
        await pilot.press("enter")  # "Keep running" is first
        await settle(pilot)
        assert not store.is_finished()
        assert store.waiting_gate() == "scope"


async def test_ctrl_c_without_a_run_only_says_so(app):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)
        assert app.is_running  # it never quits the app
        assert any("No assessment is running" in str(n.message) for n in app._notifications)


async def test_ctrl_c_after_the_run_ended_asks_nothing(app):
    run_to(None)  # played to the end
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)
        assert not store.get_run().stopped


async def test_ctrl_c_copies_selected_prompt_text_instead(app):
    run_to("scope")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "start")
        prompt = app.screen.query_one(PromptBox).input
        prompt.value = "some text"
        prompt.focus()
        prompt.select_all()
        await settle(pilot)
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)
        assert not store.is_finished()


async def test_ctrl_c_inside_a_dialog_opens_no_second_dialog(app):
    run_to("scope")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "template")
        await pilot.press("question_mark")
        await settle(pilot)
        assert isinstance(app.screen, HelpScreen)
        await pilot.press("ctrl+c")
        await settle(pilot)
        assert isinstance(app.screen, HelpScreen)
        assert not store.is_finished()


async def test_stop_command_takes_the_same_confirm_path(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "plan")
        assert app.run_command_line("/stop")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("down", "enter")
        await settle(pilot)
        assert store.get_run().stopped == "you stopped it"
