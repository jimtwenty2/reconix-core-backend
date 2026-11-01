"""The approval gate stays readable at 80x24: the risk, Action, Target, the full command, the
hash and every menu label are on screen at once, even with a 3-line command or a masked secret.
At 120x36 the full layout is kept, and the screen switches layouts on resize."""

import pytest
from textual.widgets import Static

from reconix import store
from reconix.screens import ApprovalScreen
from reconix.store.approvals import command_digest
from reconix.widgets import ChoiceMenu

from .support import run_ui_to, settle, wait_until

SMALL, BIG = (80, 24), (120, 36)
FIRST, SECOND = "approval-001", "approval-002"
LONG = "GET https://staging.example.com/api/orders/10482/" + "abcdefgh/" * 14 + "end"
SECRET = "abc123SECRET"
SECRET_CMD = f"GET https://staging.example.com/api/orders?token={SECRET} as test account A"


def _note(screen) -> str:
    notes = screen.query(".panel-note")
    return str(notes.first().render().plain) if notes else ""


def _all_text(screen) -> str:
    menu = screen.query_one("#approval-menu", ChoiceMenu)
    parts = [str(menu.get_option_at_index(i).prompt) for i in range(menu.option_count)]
    for widget in screen.query(Static):
        rendered = widget.render()
        if hasattr(rendered, "plain"):
            parts.append(rendered.plain)
    return " ".join(parts)


def _settled(app) -> bool:
    screen = app.screen
    if not isinstance(screen, ApprovalScreen):
        return False
    try:
        body = screen.query_one("#body")
    except Exception:
        return False                                   # mid-transition: not composed yet
    return body.max_scroll_y == 0 or screen._fit_level >= ApprovalScreen.MAX_FIT_LEVEL


async def _settle_fit(pilot, app) -> None:
    await wait_until(pilot, lambda: _settled(app), what="approval fit to settle")
    await settle(pilot)


def _inject(request_id: str, command: str) -> None:
    request = store.get_approval(request_id)           # display-only; the hash stays real
    request.command = command
    request.command_hash = command_digest(request.command)


def _assert_fits(screen, *, secret: str = "") -> None:
    body = screen.query_one("#body")
    assert body.max_scroll_y == 0                      # nothing is pushed below the fold
    note, text = _note(screen), _all_text(screen)
    request = store.get_approval(screen._request.request_id)
    assert request.command_hash[:23] in note           # the hash is visible
    assert request.risk in str(screen.query_one(".panel").border_subtitle)   # risk shown
    menu = screen.query_one("#approval-menu", ChoiceMenu)
    for choice in menu._choices:                        # every menu label is visible
        if choice.kind != "input":
            assert choice.label in text, choice.label
    if secret:
        assert secret not in note and secret not in text
        assert "secrets masked on screen" in text
    else:
        assert request.command in note                  # the full command, unwrapped, is shown


# --- MEDIUM and HIGH at 80x24 ---------------------------------------------------------------
@pytest.mark.parametrize("gate", [FIRST, SECOND])
async def test_gate_fits_at_80x24(app, gate):
    async with app.run_test(size=SMALL) as pilot:
        await run_ui_to(app, pilot, f"approval:{gate}")
        await _settle_fit(pilot, app)
        assert isinstance(app.screen, ApprovalScreen)
        _assert_fits(app.screen)


# --- the worst cases at 80x24 ---------------------------------------------------------------
async def test_long_command_wraps_and_fits_at_80x24(app):
    async with app.run_test(size=SMALL) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        _inject(FIRST, LONG)
        app.reload_screen()
        await settle(pilot)
        await _settle_fit(pilot, app)
        assert app.screen.query(".panel-note").first().size.height >= 3   # wraps to 3+ lines
        _assert_fits(app.screen)


async def test_masked_secret_fits_and_shows_the_note_at_80x24(app):
    async with app.run_test(size=SMALL) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        _inject(FIRST, SECRET_CMD)
        app.reload_screen()
        await settle(pilot)
        await _settle_fit(pilot, app)
        _assert_fits(app.screen, secret=SECRET)


async def test_long_and_secret_fit_at_80x24(app):
    async with app.run_test(size=SMALL) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        _inject(FIRST, LONG + f"?token={SECRET}")
        app.reload_screen()
        await settle(pilot)
        await _settle_fit(pilot, app)
        _assert_fits(app.screen, secret=SECRET)


# --- 120x36 keeps the full layout; resize switches ------------------------------------------
async def test_full_layout_at_120x36(app):
    async with app.run_test(size=BIG) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        await _settle_fit(pilot, app)
        assert app.screen._fit_level == 0                         # the full layout
        assert app.screen.query_one("#body").max_scroll_y == 0
        text = _all_text(app.screen)
        assert "EXACT REQUEST" in text                            # full-only elements present
        assert "The assessment stops" in text                     # full (not trimmed) hint
        assert "logged to audit" in text


async def test_switches_to_compact_on_resize_and_back(app):
    async with app.run_test(size=BIG) as pilot:
        await run_ui_to(app, pilot, f"approval:{FIRST}")
        await _settle_fit(pilot, app)
        assert app.screen._fit_level == 0

        await pilot.resize_terminal(*SMALL)
        await _settle_fit(pilot, app)
        assert app.screen._fit_level >= 1                         # compacted to fit
        _assert_fits(app.screen)

        await pilot.resize_terminal(*BIG)
        await _settle_fit(pilot, app)
        assert app.screen._fit_level == 0                         # back to the full layout
