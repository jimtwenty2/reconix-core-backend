"""The `/` command bar: a local path is a target, Esc steps back one thing at a time, and a
double Enter runs the command once."""

from reconix import store
from reconix.screens import CommandBarScreen, FindingsListScreen, ReportScreen
from reconix.widgets import PromptBox

from .support import SIZE, settle, show, wait_until


async def open_bar(app, pilot) -> PromptBox:
    await pilot.press("slash")
    await settle(pilot)
    assert isinstance(app.screen, CommandBarScreen)
    return app.screen.query_one(PromptBox)


async def test_the_bar_takes_a_local_path_as_a_target(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        bar = await open_bar(app, pilot)
        bar.input.value = "/home/me/app"
        await pilot.press("enter")
        await settle(pilot)
        assert not isinstance(app.screen, CommandBarScreen)
        assert store.list_requests()[-1].text == "/home/me/app"
        assert store.get_assessment().template_id == "source"
        # The run stops at its first gate: nothing is approved and nothing is tested.
        await wait_until(pilot, lambda: bool(store.waiting_gate()), what="the first gate")
        assert not store.is_scope_approved()
        assert store.list_findings() == []


async def test_esc_in_the_bar_closes_the_menu_then_clears_then_closes(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        bar = await open_bar(app, pilot)
        await pilot.press("p")
        await pilot.pause()
        assert bar.menu_open
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, CommandBarScreen)
        assert not bar.menu_open and bar.input.value == "/p"
        await pilot.press("escape")
        await pilot.pause()
        assert isinstance(app.screen, CommandBarScreen)
        assert bar.input.value == ""
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)


async def test_two_submits_before_the_bar_closes_run_the_command_once(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        depth = len(app.screen_stack)
        bar = await open_bar(app, pilot)
        bar.input.value = "/report"
        await pilot.pause()
        await bar.input.action_submit()          # Enter twice, both queued in the bar
        await bar.input.action_submit()
        await settle(pilot)
        assert isinstance(app.screen, ReportScreen)
        assert len(app.screen_stack) == depth
        assert store.list_history().count("/report") == 1
