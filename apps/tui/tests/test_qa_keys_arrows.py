"""←/→ change step unless you are typing or editing (the arrow rule, 2026-11-04).

A typed "Type something." draft keeps them; an empty step chat input says how to leave; the
ends of the flow say so; → never leaves a gate that still waits (← still goes back); a dialog
keeps them. On the menu inside the step chat "/" and "?" still open the command bar and help.
"""

from reconix import store
from reconix.models import Choice
from reconix.screens import (
    ChoiceScreen,
    CommandBarScreen,
    PlanScreen,
    ReportScreen,
    StartScreen,
    TemplateScreen,
)
from reconix.screens.help import HelpScreen
from reconix.shell.navigation import FIRST_STEP, LAST_STEP, PANEL_OPEN, gate_blocks, gate_hint
from reconix.widgets import ChoiceMenu, StepChat

from .support import (
    NETWORK, SIZE, chat_menu_ready, run_ui_to, settle, show, start_demo, step_menu, toasts,
    wait_until,
)


async def _open_chat(app, pilot) -> StepChat:
    app.screen.post_message(ChoiceMenu.Chosen(step_menu(app), "chat"))
    await settle(pilot)
    return app.screen.query_one(StepChat)


async def _in_chat_menu(app, pilot) -> ChoiceMenu:
    """The scope's menu inside the step chat, focused and armed."""
    await run_ui_to(app, pilot, "scope", request=NETWORK)
    app.screen.post_message(ChoiceMenu.Typed(step_menu(app), "yes"))
    return await chat_menu_ready(app, pilot)


# --- typing keeps the arrows ---------------------------------------------------------------------
async def test_a_typed_draft_keeps_the_arrows_and_the_screen(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)  # the scope waits on Template
        await settle(pilot)
        menu = step_menu(app)
        ids = [c.id for c in menu._choices]
        menu.highlighted = next(i for i, c in enumerate(menu._choices) if c.kind == "input")
        menu.focus()
        await pilot.pause(menu.ARM_DELAY + 0.1)
        await pilot.press("a", "b", "c", "left", "right")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert menu._draft == "abc"  # nothing lost
        assert gate_hint("scope") not in toasts(app)
        assert ids == [c.id for c in step_menu(app)._choices]


async def test_an_empty_chat_input_says_how_to_leave(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        chat = await _open_chat(app, pilot)
        assert chat.input.has_focus and not chat.input.value
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert app.screen.query(StepChat)  # still open
        assert PANEL_OPEN in toasts(app)


async def test_text_in_the_chat_input_keeps_the_arrows_for_the_cursor(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        chat = await _open_chat(app, pilot)
        chat.input.value = "abc"
        chat.input.cursor_position = 3
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert chat.input.cursor_position == 2
        assert PANEL_OPEN not in toasts(app)


# --- the ends of the flow ------------------------------------------------------------------------
async def test_left_on_start_says_it_is_the_first_step(app):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert FIRST_STEP in toasts(app)


async def test_right_on_the_report_says_it_is_the_last_step(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "report")
        app.screen.focus_next()
        await pilot.press("right")
        await settle(pilot)
        assert isinstance(app.screen, ReportScreen)
        assert LAST_STEP in toasts(app)


# --- a gate that still waits ---------------------------------------------------------------------
async def test_right_stays_at_a_waiting_scope_and_left_still_goes_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        await pilot.press("right")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert gate_blocks("scope") in toasts(app)
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert gate_hint("scope") in toasts(app)
        assert not store.is_scope_approved()


async def test_right_moves_on_once_the_gate_is_decided(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)  # the scope is approved
        await show(app, pilot, "template")
        await pilot.press("right")
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)


# --- "/" and "?" on the menu inside the chat -----------------------------------------------------
async def test_slash_on_the_chat_menu_opens_the_command_bar(app):
    async with app.run_test(size=SIZE) as pilot:
        await _in_chat_menu(app, pilot)
        await pilot.press("slash")
        await wait_until(
            pilot, lambda: isinstance(app.screen, CommandBarScreen), what="the command bar"
        )
        assert app.screen_stack[-2].query_one(StepChat).input.value == ""


async def test_question_mark_on_the_chat_menu_opens_the_help(app):
    async with app.run_test(size=SIZE) as pilot:
        await _in_chat_menu(app, pilot)
        await pilot.press("question_mark")
        await wait_until(pilot, lambda: isinstance(app.screen, HelpScreen), what="the help")


# --- dialogs keep the arrows ---------------------------------------------------------------------
async def test_a_dialog_keeps_the_arrows(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        app.open_dialog(ChoiceScreen("Check", "Sure?", [Choice("no", "No"), Choice("yes", "Yes")]))
        await wait_until(pilot, lambda: isinstance(app.screen, ChoiceScreen), what="the dialog")
        await pilot.press("left", "right")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert isinstance(app.screen_stack[-2], TemplateScreen)
