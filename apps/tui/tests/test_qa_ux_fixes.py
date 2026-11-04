"""QA findings (2 Nov 2026 TUI QA pass), the polish batch: QA-004, QA-017, QA-001, QA-002,
QA-019. Each test failed before its fix."""

from textual.widgets import DataTable

from reconix import store, theme
from reconix.screens import ChoiceScreen, FindingsListScreen
from reconix.screens.report import ReportScreen
from reconix.widgets.chrome import SessionBar

from .support import run_to, settle, show

LONG_TARGET = (
    "Assess https://a-very-long-subdomain-name.staging.shop.example.com/api/v2/orders for issues"
)


def _messages(app) -> str:
    return " | ".join(str(n.message) for n in app._notifications)


# --- QA-004: an export key that can't run says why; a running export says it is busy ----------
async def test_an_export_key_before_the_end_says_why(app):
    run_to("approval:approval-001")
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "report")
        await pilot.press("j")
        await settle(pilot)
        assert "available once the assessment is complete" in _messages(app)
        assert store.get_run().report_path == ""


async def test_an_export_shows_a_busy_note_then_saves(app):
    run_to(None)
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "report")
        await pilot.press("j")
        await settle(pilot)
        assert "Writing the JSON report" in _messages(app)
        assert isinstance(app.screen, ChoiceScreen)  # ✓ REPORT SAVED
        assert store.get_run().report_path.endswith(".json")


# --- QA-017: ←/→ on the Findings list do what its hint says ------------------------------------
async def test_right_and_left_move_through_the_flow_from_the_findings_table(app):
    run_to(None)
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "findings")
        assert isinstance(app.focused, DataTable)  # the table has focus
        await pilot.press("right")
        await settle(pilot)
        assert isinstance(app.screen, ReportScreen)
        await show(app, pilot, "findings")
        await pilot.press("left")
        await settle(pilot)
        assert not isinstance(app.screen, FindingsListScreen)


async def test_shift_arrows_still_scroll_the_findings_table_sideways(app):
    run_to(None)
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "findings")
        table = app.screen.query_one("#findings-table", DataTable)
        assert table.max_scroll_x > 0
        await pilot.press("shift+right")
        await settle(pilot)
        assert table.scroll_offset.x > 0
        assert isinstance(app.screen, FindingsListScreen)


# --- QA-001: the active model stays in the top bar at 80 columns -------------------------------
def _bar(app) -> str:
    bar = app.screen.query_one(SessionBar)
    bar.refresh_line()
    return str(bar.render())


async def test_the_top_bar_keeps_the_model_and_phase_at_80_columns(app):
    store.use_mock()
    run_to("approval:approval-001", request=LONG_TARGET)
    async with app.run_test(size=(80, 24)) as pilot:
        await settle(pilot)
        text = _bar(app)
        assert "reconix-mock-1" in text and "●" in text
        assert "Awaiting" in text  # the run's phase
        assert len(text) <= 80
        assert "…" in text  # the long target gave way


async def test_the_top_bar_shows_the_full_model_line_when_wide(app):
    store.use_mock()
    async with app.run_test(size=(160, 30)) as pilot:
        await settle(pilot)
        active = store.active_model()
        assert f"{active.label} · {active.model}" in _bar(app)


# --- QA-002: /provider opens on the ACTIVE provider -------------------------------------------
async def test_provider_menu_opens_on_the_active_provider_in_view(app):
    store.use_mock()
    async with app.run_test(size=(80, 24)) as pilot:
        app.run_command_line("/provider")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        menu = app.screen.query_one("#dialog-menu")
        assert menu.highlighted_id == "mock"
        row = menu.highlighted
        assert menu.scroll_offset.y <= row  # the row is not above
        assert (
            row - menu.scroll_offset.y < menu.scrollable_content_region.height
            or menu.max_scroll_y == 0
        )


# --- QA-019: one wording per triage status -----------------------------------------------------
def test_the_list_uses_the_same_triage_words_as_the_dialog():
    assert {status: label for status, (_, label) in theme.TRIAGE.items()} == store.TRIAGE_LABELS
