"""Evaluator pass at 80×24: dialogs, forms, bars and hints that must fit an 80-column screen.

PROV-02 (the focused key field in view), CMD-05 (a long dialog keeps its choices and hint on
screen), one-line form footers, the Start card, the Findings hint, the plan rows, the session
bar and the flow line after a completed run.
"""

from textual.widgets import Button, Input, Static

from reconix import store
from reconix.app import ReconixApp
from reconix.llm.catalog import MOCK_ID
from reconix.screens import ChoiceScreen
from reconix.screens.forms.add_on import AddOnForm
from reconix.screens.forms.provider import ProviderForm

from .support import pass_gate, run_to, settle, start_demo

SMALL = (80, 24)


def _on_screen(widget) -> bool:
    region = widget.region
    return region.height > 0 and region.y >= 0 and region.bottom <= widget.screen.size.height


def _inside(widget, box) -> bool:
    """`widget` is drawn inside `box`'s content area (not cut off by its border)."""
    inner = box.content_region
    region = widget.region
    return region.height > 0 and region.y >= inner.y and region.bottom <= inner.bottom


def _lines(widget) -> int:
    return widget.size.height


# --- 1. PROV-02: the focused field is in view ---------------------------------------------------
async def test_the_mock_provider_key_field_is_in_view_at_80x24():
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        app.push_screen(ProviderForm(MOCK_ID))
        await settle(pilot, 8)
        form = app.screen
        key = form.query_one("#api_key", Input)
        assert form.focused is key
        assert _inside(key, form.query_one(".form-body"))
        assert _on_screen(form.query_one("#submit", Button))


# --- 2. CMD-05: a long dialog keeps Close and its hint on screen ---------------------------------
async def test_the_audit_dialog_keeps_close_and_the_hint_on_screen():
    app = ReconixApp()
    run_to(None)  # a full run: a long audit trail
    async with app.run_test(size=SMALL) as pilot:
        app.show_audit()
        await settle(pilot, 8)
        dialog = app.screen
        assert isinstance(dialog, ChoiceScreen)
        box = dialog.query_one(".dialog")
        assert _inside(dialog.query_one("#dialog-menu"), box)
        hint = dialog.query_one(".menu-hint", Static)
        assert _inside(hint, box)
        assert "PgUp/PgDn" in str(hint.render())
        assert dialog.query_one(".dialog-body").max_scroll_y > 0


async def test_the_approval_details_keep_their_choice_on_screen():
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await start_demo(pilot)
        while not (store.waiting_gate() or "").startswith("approval:"):
            await pass_gate(app, pilot)
        await settle(pilot, 6)
        app.screen.action_details()
        await settle(pilot, 8)
        dialog = app.screen
        assert isinstance(dialog, ChoiceScreen)
        box = dialog.query_one(".dialog")
        assert _inside(dialog.query_one("#dialog-menu"), box)
        assert _inside(dialog.query_one(".menu-hint", Static), box)


async def test_a_short_dialog_keeps_its_natural_height():
    app = ReconixApp()
    async with app.run_test(size=(140, 45)) as pilot:
        app.show_audit()  # nothing recorded yet: short
        await settle(pilot, 8)
        assert app.screen.query_one(".dialog").region.height < 20


# --- 3. form footers fit on one line; no empty gap -------------------------------------------
async def test_every_form_footer_fits_on_one_line_at_80x24():
    for make in (lambda: ProviderForm(MOCK_ID), AddOnForm):
        app = ReconixApp()
        async with app.run_test(size=SMALL) as pilot:
            app.push_screen(make())
            await settle(pilot, 6)
            assert _lines(app.screen.query_one(".menu-hint", Static)) == 1


async def test_the_provider_form_has_no_empty_gap_above_its_buttons():
    app = ReconixApp()
    async with app.run_test(size=(120, 36)) as pilot:
        app.push_screen(ProviderForm(MOCK_ID))
        await settle(pilot, 8)
        form = app.screen
        key = form.query_one("#api_key", Input)
        submit = form.query_one("#submit", Button)
        assert submit.region.y - key.region.bottom <= 2  # margin + one error row at most


# --- (b) a form with fields below the fold says so ---------------------------------------------
async def test_the_login_form_says_more_fields_wait_below_the_fold():
    from reconix.screens.forms import LoginForm

    from .support import run_ui_to

    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await run_ui_to(app, pilot, "account")
        await settle(pilot, 8)
        form = app.screen
        assert isinstance(form, LoginForm)
        body = form.query_one(".form-body")
        more = form.query_one("#form-more", Static)
        if body.max_scroll_y > 0:                        # the password is below the fold
            assert more.display and _on_screen(more)
            assert "more fields" in str(more.render())
            form.query_one("#secret", Input).focus()     # Tab / Enter moves there
            await settle(pilot, 8)
            assert _inside(form.query_one("#secret", Input), body)
            assert not more.display                      # nothing left below
        else:
            assert not more.display


async def test_no_more_fields_hint_when_everything_fits():
    app = ReconixApp()
    async with app.run_test(size=(140, 45)) as pilot:
        app.push_screen(AddOnForm())
        await settle(pilot, 8)
        assert not app.screen.query_one("#form-more", Static).display
        assert not app.screen.query_one("#form-error", Static).display   # no empty row


# --- 4 + placeholder: the Start screen fits 80 columns ----------------------------------------
async def test_the_start_card_and_prompt_fit_80_columns():
    from reconix.screens.start import PLACEHOLDER, QUICKSTART
    from reconix.widgets import PromptBox

    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await settle(pilot, 6)
        card = app.screen.query_one("#quickstart")
        # One row per step: the card is its border plus one line per step, nothing wrapped
        assert card.content_region.height == len(QUICKSTART)
        prompt = app.screen.query_one(PromptBox).input
        assert prompt.placeholder == PLACEHOLDER
        assert len(PLACEHOLDER) <= prompt.content_region.width


# --- 5 + (a): the Findings hint and table fit 80 columns -------------------------------------
async def test_the_findings_hint_is_one_line_and_no_column_is_drawn_half():
    from textual.widgets import DataTable

    run_to(None)
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        app.goto("findings")
        await settle(pilot, 8)
        assert _lines(app.screen.query_one("#findings-hint", Static)) == 1
        table = app.screen.query_one("#findings-table", DataTable)
        visible = table.scrollable_content_region.width
        edge = 0
        for column in table.columns.values():
            right = edge + column.get_render_width(table)
            assert right <= visible or edge >= visible, f"{column.label} is cut at the edge"
            edge = right
        labels = [str(c.label) for c in table.columns.values()]
        assert "VALIDATION" in labels                    # the last column on screen at 80


# --- 6: the highlighted plan row never wraps back to the first column -----------------------
def test_a_long_plan_row_continues_under_its_own_column():
    from reconix.models import PlanRow
    from reconix.widgets.plan_rows import LABEL_WIDTH, NUM_WIDTH, plan_line

    row = PlanRow(num="1", label="Crawl & map endpoints",
                  detail="map the permitted surface · OWASP ZAP and more words here",
                  risk="LOW", gate="auto", status="pending")
    width = 70
    lines = plan_line(row, width, full=True).plain.split("\n")
    room = width - NUM_WIDTH - LABEL_WIDTH
    assert len(lines) >= 3                               # wrapped, then the risk line
    for line in lines[1:-1]:                             # the continuation lines
        assert line.startswith(" " * (NUM_WIDTH + LABEL_WIDTH))
        assert len(line.strip()) <= room
    assert all(len(line) <= width for line in lines)


# --- 7: the session bar keeps the id whole and uses its width --------------------------------
async def test_the_session_bar_keeps_the_id_and_the_target_at_80_columns():
    from reconix.store.providers import use_mock
    from reconix.widgets import SessionBar

    use_mock()
    run_to("scope")
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await settle(pilot, 6)
        line = str(app.screen.query_one(SessionBar).render())
        label = store.get_assessment().label
        assert f"{label} · stagin" in line                 # the id whole, then the target
        assert "Scope pending" in line and "reconix-mock-1" in line
        bar = app.screen.query_one(SessionBar)
        assert len(line.rstrip()) == bar.content_region.width   # the whole width is used


async def test_the_session_bar_shows_everything_on_a_wide_terminal():
    from reconix.store.providers import use_mock
    from reconix.widgets import SessionBar

    use_mock()
    run_to("scope")
    app = ReconixApp()
    async with app.run_test(size=(160, 40)) as pilot:
        await settle(pilot, 6)
        line = str(app.screen.query_one(SessionBar).render())
        assert "staging.example.com" in line
        assert "Scope pending approval" in line
        assert "Reconix mock (offline) · reconix-mock-1" in line


# --- 8: the flow line marks Findings done once the run completed ------------------------------
def test_findings_are_settled_once_the_run_completed():
    run_to(None)
    assert store.step_states()["findings"] == "done"


def test_findings_are_not_settled_while_the_run_plays():
    run_to("approval:approval-001")
    assert "findings" not in store.step_states()
