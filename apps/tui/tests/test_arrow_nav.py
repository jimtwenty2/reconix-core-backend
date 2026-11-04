"""←/→ between the flow screens (arrow-key plan A).

They move to the previous / next screen, but never away from an open step chat, tick list or
order list (that would throw it away unsaved), they step over Finding detail while no finding
is chosen, an empty Start prompt passes them on (with text they move the cursor), and leaving
a gate that still waits says how to come back. No arrow ever decides anything.
"""

from textual.widgets import SelectionList

from reconix import store
from reconix.screens import (
    ApprovalScreen,
    FindingsListScreen,
    PlanScreen,
    ReportScreen,
    StartScreen,
    TemplateScreen,
)
from reconix.screens.help import HelpScreen
from reconix.shell.navigation import PANEL_OPEN, gate_blocks, gate_hint
from reconix.widgets import ChoiceMenu, PlanOrder, PromptBox, TickList

from .support import (
    NETWORK, SIZE, run_to, run_ui_to, settle, start_demo, toasts, type_in_menu, wait_until,
)


# --- open panels are kept ----------------------------------------------------------------------
async def test_arrows_keep_an_open_tick_list(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        before = list(store.get_scope().allowed_ports)
        type_in_menu(app, "add port 3389")
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        app.screen.query_one(SelectionList).focus()
        await pilot.press("right", "left")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert app.screen.query(TickList)  # still open, nothing lost
        assert PANEL_OPEN in toasts(app)
        assert store.get_scope().allowed_ports == before  # and nothing changed


async def test_arrows_keep_an_open_order_list(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", request=NETWORK)
        type_in_menu(app, "move 3b before 3a")
        await wait_until(pilot, lambda: bool(app.screen.query(PlanOrder)), what="the order")
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)
        assert app.screen.query(PlanOrder)


async def test_arrows_still_move_the_cursor_in_the_chat_input(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        app.screen.post_message(ChoiceMenu.Chosen(app.screen.query(ChoiceMenu).first(), "chat"))
        await settle(pilot)
        field = app.screen.query_one("#step-chat-input")
        field.value = "abc"
        field.cursor_position = 3
        field.focus()
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert field.cursor_position == 2


# --- Finding detail is skipped without a finding -----------------------------------------------
async def test_left_from_the_report_goes_to_findings_when_no_finding_is_chosen(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        app.goto("report")
        await settle(pilot)
        assert isinstance(app.screen, ReportScreen)
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)


async def test_left_from_the_report_opens_the_chosen_finding(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        app.open_finding("001")
        await settle(pilot)
        app.goto("report")
        await settle(pilot)
        await pilot.press("left")
        await settle(pilot)
        assert type(app.screen).__name__ == "FindingDetailScreen"


# --- the Start prompt --------------------------------------------------------------------------
async def test_an_empty_start_prompt_passes_the_arrows_on(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)  # the scope waits on Template
        app.goto("start")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert app.screen.query_one(PromptBox).input.has_focus
        await pilot.press("right")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)


async def test_typed_text_keeps_the_arrows_for_the_cursor(app):
    async with app.run_test(size=SIZE) as pilot:
        box = app.screen.query_one(PromptBox)
        box.input.value = "hello"
        box.input.cursor_position = 5
        box.input.focus()
        await pilot.press("left", "left", "right")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert box.input.cursor_position == 4


# --- gates ----------------------------------------------------------------------------------------
async def test_leaving_the_scope_with_an_arrow_decides_nothing_and_says_how_back(app):
    async with app.run_test(size=SIZE) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert store.waiting_gate() == "scope" and not store.is_scope_approved()
        assert gate_hint("scope") in toasts(app)
        assert "Alt+2" in gate_hint("scope")


async def test_arrows_at_an_approval_decide_nothing(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "approval:approval-001")
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        await pilot.press("right")                   # → stays: the approval is decided first
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert store.decision_for("approval-001") is None
        assert gate_blocks("approval:approval-001") in toasts(app)
        await pilot.press("left")
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)
        assert gate_hint("approval:approval-001") in toasts(app)
        assert store.decision_for("approval-001") is None
        assert store.waiting_gate() == "approval:approval-001"


def test_each_gate_names_its_way_back():
    assert "Alt+3" in gate_hint("plan")
    assert "Alt+4" in gate_hint("approval:approval-001")
    assert "Alt+5" in gate_hint("account")
    assert "Alt+2" in gate_hint("template")


# --- the help overlay ----------------------------------------------------------------------------
async def test_the_help_on_start_is_named_after_the_screen_and_says_it_scrolls(app):
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.press("question_mark")
        await settle(pilot, 6)
        assert isinstance(app.screen, HelpScreen)
        box = app.screen.query_one("#help-box")
        assert box.border_title == "⌨ Shortcuts · Start"
        if box.max_scroll_y > 0:
            assert "scroll" in str(box.border_subtitle)
            await pilot.press("pagedown")
            await settle(pilot)
            assert box.scroll_y > 0
