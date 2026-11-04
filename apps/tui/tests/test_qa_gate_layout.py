"""QA-008, QA-009, QA-010: gates and forms at 80×24.

A digit on a gate may only pick a numbered, non-destructive choice; screen jumps live on
Alt. Forms taller than the terminal scroll with Save / Cancel always on screen. A gate opens
on what is being decided, scrolled to its top.
"""

import pytest
from textual.widgets import Button

from reconix import store
from reconix.app import ReconixApp
from reconix.screens import ApprovalScreen, TemplateScreen
from reconix.screens.forms import ScopeEditForm
from reconix.screens.forms.add_on import AddOnForm
from reconix.widgets import ChoiceMenu

from .support import pass_gate, settle, start_demo

SMALL = (80, 24)


async def _to_gate(app, pilot, prefix: str) -> None:
    await start_demo(pilot)
    while not (store.waiting_gate() or "").startswith(prefix):
        await pass_gate(app, pilot)
    await settle(pilot, 6)


def _on_screen(widget) -> bool:
    region = widget.region
    return region.height > 0 and region.y >= 0 and region.bottom <= widget.screen.size.height


# --- QA-009: forms ---------------------------------------------------------------------------
@pytest.mark.parametrize("size", [SMALL, (120, 36), (140, 45)])
@pytest.mark.parametrize("make", [ScopeEditForm, AddOnForm])
async def test_save_and_cancel_stay_on_screen(size, make):
    app = ReconixApp()
    async with app.run_test(size=size) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        app.push_screen(make())
        await settle(pilot, 6)
        form = app.screen
        assert _on_screen(form.query_one("#submit", Button))
        assert _on_screen(form.query_one("#cancel", Button))


async def test_a_tall_form_scrolls_to_the_field_in_focus():
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        app.edit_scope()
        await settle(pilot, 6)
        form = app.screen
        assert isinstance(form, ScopeEditForm)
        body = form.query_one(".form-body")
        assert body.max_scroll_y > 0  # taller than the terminal
        form.query_one("#time-limit").focus()
        await settle(pilot, 6)
        assert _on_screen(form.query_one("#time-limit"))
        await pilot.press("pageup")
        await settle(pilot)
        assert body.scroll_y < body.max_scroll_y


async def test_a_short_form_keeps_its_natural_height():
    app = ReconixApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await start_demo(pilot)
        await settle(pilot)
        app.push_screen(AddOnForm())
        await settle(pilot, 6)
        dialog = app.screen.query_one(".dialog")
        assert dialog.region.height < 45 * 0.9 - 4


# --- QA-010: gates open on what is decided ---------------------------------------------------
@pytest.mark.parametrize(
    "prefix,screen", [("scope", TemplateScreen), ("approval:", ApprovalScreen)]
)
async def test_a_gate_opens_at_its_top_and_down_shows_the_choices(prefix, screen):
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await _to_gate(app, pilot, prefix)
        assert isinstance(app.screen, screen)
        body = app.screen.query_one("#body")
        assert body.max_scroll_y > 0 and body.scroll_y == 0
        menu = app.screen.focused
        assert isinstance(menu, ChoiceMenu)
        await pilot.press("down")
        await settle(pilot)
        assert body.scroll_y > 0  # the menu came into view


# --- QA-008: a digit on a gate ---------------------------------------------------------------
async def test_a_bare_digit_on_a_gate_jumps_nowhere_and_alt_jumps():
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await _to_gate(app, pilot, "scope")
        await pilot.press("8")  # no choice 8, no screen jump
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert store.waiting_gate() == "scope"
        await pilot.press("alt+1")
        await settle(pilot)
        assert type(app.screen).__name__ == "StartScreen"
        assert store.waiting_gate() == "scope"  # a jump decides nothing


async def test_a_digit_cannot_pick_a_destructive_choice():
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await _to_gate(app, pilot, "scope")
        menu = app.screen.focused
        assert isinstance(menu, ChoiceMenu)
        reject = [c.id for c in menu._choices].index("reject")
        await pilot.press(str(reject + 1))
        await settle(pilot)
        assert not store.get_run().stopped
        assert menu.highlighted != reject  # not even highlighted
        line = str(menu.get_option_at_index(reject).prompt)
        assert f"{reject + 1}." not in line  # drawn without its number


async def test_a_gate_with_hidden_choices_says_how_to_reach_them():
    app = ReconixApp()
    async with app.run_test(size=SMALL) as pilot:
        await _to_gate(app, pilot, "scope")
        app.clear_notifications()
        app.screen._hinted = False              # it may have shown once already: show it again
        app.screen._hint_hidden_choices()       # the check the gate runs once it is laid out
        await settle(pilot)
        assert any("↓ moves down to them" in str(n.message) for n in app._notifications)


async def test_a_tall_terminal_needs_no_hint():
    app = ReconixApp()
    async with app.run_test(size=(140, 45)) as pilot:
        await _to_gate(app, pilot, "approval:")
        notes = [str(n.message) for n in app._notifications]
        assert not any("↓ moves down to them" in note for note in notes)


def test_a_rejected_action_is_never_shown_with_a_green_tick():
    from reconix.screens.approval import _context_line
    from tests.support import run_to

    run_to("approval:approval-001")
    store.reject("approval-001")
    from tests.support import play_until_gate
    assert play_until_gate() == "approval:approval-002"
    line = _context_line()
    assert line.plain.startswith("✕ Skipped: Baseline request")


def test_the_candidate_is_confirmed_only_after_its_validation_runs():
    from tests.support import decide, play_until_gate, run_to

    run_to("approval:approval-001")
    assert store.get_finding("001").validation == "UNCONFIRMED"   # revealed as a candidate
    decide("approval:approval-001")
    assert play_until_gate() == "approval:approval-002"
    assert store.get_finding("001").validation == "UNCONFIRMED"
    decide("approval:approval-002")
    assert play_until_gate() is None
    assert store.get_finding("001").validation == "CONFIRMED"


@pytest.mark.parametrize("rejected", ["approval-001", "approval-002"])
def test_rejecting_either_check_leaves_the_candidate_unconfirmed(rejected):
    from tests.support import decide, play_until_gate, run_to

    run_to("approval:approval-001")
    for gate in ("approval:approval-001", "approval:approval-002"):
        if gate.endswith(rejected):
            store.reject(rejected)
        else:
            decide(gate)
        play_until_gate()
    assert store.is_completed()
    assert store.get_finding("001").validation == "UNCONFIRMED"
