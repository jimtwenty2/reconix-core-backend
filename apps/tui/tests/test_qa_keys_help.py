"""QA-018: the "Everywhere" keys do what the help says, and never break typing."""

from textual.widgets import Input

from reconix import store
from reconix.screens import ApprovalScreen, TemplateScreen
from reconix.screens.forms import ScopeEditForm
from reconix.screens.help import GLOBAL_ROWS
from reconix.widgets import ChoiceMenu, PromptBox

from .support import SIZE, run_to, settle, show


def test_help_says_where_slash_and_question_mark_work():
    rows = dict(GLOBAL_ROWS)
    assert "not inside a dialog" in rows["/"]
    assert "not inside a dialog" in rows["?"]
    assert "^C" in rows


async def test_alt_jump_works_with_the_start_prompt_focused(app):
    run_to("scope")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "start")
        prompt = app.screen.query_one(PromptBox).input
        prompt.focus()
        await settle(pilot)
        await pilot.press("alt+2")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert prompt.value == ""  # nothing was typed
        assert store.waiting_gate() == "scope"  # nothing was decided


async def test_slash_and_question_mark_stay_text_in_a_form_field(app):
    run_to("scope")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "template")
        app.edit_scope()
        await settle(pilot)
        assert isinstance(app.screen, ScopeEditForm)
        field = app.screen.focused
        assert isinstance(field, Input)
        field.value = ""
        await pilot.press("slash", "a", "question_mark")
        await settle(pilot)
        assert isinstance(app.screen, ScopeEditForm)  # no command bar, no help
        assert field.value == "/a?"


async def test_slash_and_question_mark_stay_text_on_type_something(app):
    run_to("approval:approval-001")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "approval")
        await settle(pilot, 8)  # let the menu arm
        menu = app.screen.query_one("#approval-menu", ChoiceMenu)
        row = next(i for i, c in enumerate(menu._choices) if c.kind == "input")
        menu.focus()
        menu.highlighted = row
        await settle(pilot)
        await pilot.press("slash", "question_mark")
        await settle(pilot)
        assert isinstance(app.screen, ApprovalScreen)
        assert menu._draft == "/?"
        assert store.waiting_gate() == "approval:approval-001"
