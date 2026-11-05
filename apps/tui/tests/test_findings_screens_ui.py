"""Findings list + detail screens: empty states, filter/sort, triage, prev/next, the live
refill keeping the cursor, and display-only masking of secrets that rode into a finding.

Masking is display only: `store.redact` masks every finding text the list, the detail, the
triage dialog subtitle and the chat draft render; the store data, the filter/sort and the
export are unchanged (the report masks on its own)."""

import pytest
from textual.containers import Vertical
from textual.widgets import DataTable, Static

from reconix import store
from reconix.screens import ChoiceScreen, FindingDetailScreen, FindingsListScreen
from reconix.store.findings_view import FINDING_FILTERS, FINDING_SORTS

from .support import SIZE, TEST_PASSWORD, add_finding, run_to, screen_text, settle, show

def _api_finding(code: str, title: str, path: str, severity: str, cwe: str, owasp: str) -> dict:
    from .fakes.fake_api import finding_row

    row = finding_row(code, title, path, severity, "NMAP", evidence=f"{path}: seen in the scan")
    row.update(
        cwe_ids=[cwe], owasp_id=[owasp],
        description=f"{title}: the scan saw it on {path}, answering without any sign-in.",
        impact="An attacker could learn about the service and plan a targeted attack on it.",
        remediation="Restrict it to the admin network or turn it off where it isn't needed.",
    )
    return row


@pytest.fixture(autouse=True)
def three_findings(fake_api):
    """The API's run gives three findings, in this order: two MEDIUM, then one LOW (so the
    list, sorted by severity, reads 001, 002, 003)."""
    fake_api.findings_for = {"NMAP": [
        _api_finding("NMAP-ADMIN", "Exposed admin panel", "/admin", "MEDIUM", "CWE-284",
                     "OWASP A01:2021"),
        _api_finding("NMAP-OLD-TLS", "Deprecated TLS offered", "/login", "MEDIUM", "CWE-327",
                     "OWASP A02:2021"),
        _api_finding("NMAP-BANNER", "Server banner shows its version", "/", "LOW", "CWE-200",
                     "OWASP A05:2021"),
    ]}


# A secret shaped so `redact` recognizes it in every field: a bare word would (correctly) not be
# masked, so each field carries the test password inside a key/scheme/URL the masker knows.
SECRET = TEST_PASSWORD


def _plant_secret_finding(severity: str = "CRITICAL") -> str:
    """Add one revealed finding whose every shown field hides the test password. Returns its id."""
    add_finding(
        f"Leak token={SECRET}", path=f"/p?password={SECRET}", severity=severity,
        description=f"Authorization: Bearer {SECRET}",
        evidence=[f"Set-Cookie: session={SECRET}", f"https://admin:{SECRET}@evil.example.com/x"],
    )
    return next(f.fid for f in store.list_findings() if f.fid.startswith("AI-"))


def _table(app) -> DataTable:
    return app.screen.query_one("#findings-table", DataTable)


def _row_ids(app) -> list:
    table = _table(app)
    return [table.coordinate_to_cell_key((i, 0)).row_key.value for i in range(table.row_count)]


def _cursor_id(app):
    table = _table(app)
    return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value


def _table_text(app) -> str:
    """Every cell of the findings table as plain text."""
    table = _table(app)
    cells = []
    for ri in range(table.row_count):
        for ci in range(len(table.columns)):
            value = table.get_cell_at((ri, ci))
            cells.append(value.plain if hasattr(value, "plain") else str(value))
    return " ".join(cells)


def _fully_visible_columns(table: DataTable) -> list:
    """The column labels whose render width fits before the table must scroll right."""
    width = table.scrollable_content_region.width
    out, run = [], 0
    for col in table.ordered_columns:
        run += col.get_render_width(table)
        if run <= width:
            out.append(str(col.label))
    return out


def _region_visible(widget, container) -> bool:
    """Whether `widget` sits fully inside `container`'s visible region (no scrolling needed)."""
    r, c = widget.region, container.region
    return r.height > 0 and r.y >= c.y and r.bottom <= c.bottom


async def _pick_filter(app, pilot, filter_id: str) -> None:
    """Apply a filter the way the screen does: open the `f` dialog and pick it (1-based number)."""
    index = [fid for fid, _ in FINDING_FILTERS].index(filter_id) + 1
    await pilot.press("f")
    await settle(pilot)
    assert isinstance(app.screen, ChoiceScreen)
    await pilot.press(str(index))
    await settle(pilot)
    assert app.findings_filter == filter_id


# --- a. both empty states -------------------------------------------------------------------
async def test_the_two_empty_states_show_the_right_message(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        empty = app.screen.query_one("#findings-empty", Static)
        assert not _table(app).display
        assert "No findings yet" in str(empty.render())
        # Now reveal findings, then filter to one that matches nothing (no CRITICAL/HIGH here).
        run_to(None)
        app.refresh_view()
        await settle(pilot)
        await _pick_filter(app, pilot, "high_up")                # nothing is CRITICAL/HIGH here
        empty = app.screen.query_one("#findings-empty", Static)
        assert not _table(app).display
        assert "No findings match this filter" in str(empty.render())


# --- b. filter counts and sort cycling ------------------------------------------------------
async def test_filter_counts_equal_the_rows_each_filter_shows(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        counts = store.filter_counts()
        for fid, _label in FINDING_FILTERS:
            await _pick_filter(app, pilot, fid)
            assert _table(app).row_count == counts[fid], f"{fid}: table vs count"
            assert len(store.find_findings(fid)) == counts[fid], f"{fid}: count vs store"


async def test_sort_cycles_through_every_option_and_wraps(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        labels = [label for _sid, label in FINDING_SORTS]
        seen = []
        for _ in range(len(FINDING_SORTS)):
            line = str(app.screen.query_one("#view-line", Static).render())
            assert store.sort_label(app.findings_sort) in line
            seen.append(app.findings_sort)
            await pilot.press("s")
            await settle(pilot)
        assert [store.sort_label(s) for s in seen] == labels     # every option, in order
        assert app.findings_sort == FINDING_SORTS[0][0]          # wrapped back to the first


# --- c. triage updates the row, the detail badge and the note -------------------------------
async def test_triage_updates_row_and_detail_and_note(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("down", "t")                           # 002
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("2")                                   # Fixed
        await settle(pilot)
        assert store.get_finding("002").status == "fixed"
        assert "Fixed" in _table_text(app)                       # row STATUS cell
        # A note set on the finding shows in the detail (masked).
        store.triage_finding("002", note=f"accepted — see token={SECRET}")
        app.open_finding("002")
        await settle(pilot)
        assert isinstance(app.screen, FindingDetailScreen)
        text = screen_text(app.screen)
        assert "Fixed" in text and "Triage note" in text        # badge + the note heading
        assert SECRET not in text                                # the note is masked


async def test_escape_on_the_triage_dialog_changes_nothing(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("t")                                   # 001
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)
        assert store.get_finding("001").status == "open"


# --- d. prev / next stop at the ends (bell, no wrap), step in filter order -------------------
async def test_prev_next_ring_the_bell_at_both_ends(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        bells = []
        app.bell = lambda: bells.append(1)
        app.open_finding("001")
        await settle(pilot)
        await pilot.press("left_square_bracket")                 # at the first: bell, no move
        await settle(pilot)
        assert app.selected_finding == "001" and len(bells) == 1
        await pilot.press("right_square_bracket", "right_square_bracket")   # 002, 003
        await settle(pilot)
        assert app.selected_finding == "003"
        await pilot.press("right_square_bracket")                # at the last: bell, no move
        await settle(pilot)
        assert app.selected_finding == "003" and len(bells) == 2


async def test_prev_next_step_in_the_filter_order(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        app.findings_filter = "medium"                           # 001, 002 only
        app.open_finding("001")
        await settle(pilot)
        await pilot.press("right_square_bracket")
        await settle(pilot)
        assert app.selected_finding == "002"
        await pilot.press("right_square_bracket")                # 003 is out of the filter: bell
        await settle(pilot)
        assert app.selected_finding == "002"


# --- e. masked text never reveals secrets ---------------------------------------------------
async def test_the_list_and_detail_never_show_a_secret(app):
    run_to(None)
    fid = _plant_secret_finding()
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        assert SECRET not in _table_text(app)                    # list rows
        app.open_finding(fid)
        await settle(pilot)
        assert SECRET not in screen_text(app.screen)             # detail header + panels


async def test_the_triage_dialog_and_chat_draft_never_show_a_secret(app):
    from reconix.widgets import PromptBox

    run_to(None)
    fid = _plant_secret_finding()                                # CRITICAL -> top row
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("t")                                   # triage the top (secret) row
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert SECRET not in screen_text(app.screen)             # dialog subtitle
        await pilot.press("escape")
        await settle(pilot)
        app.open_finding(fid)
        await settle(pilot)
        await pilot.press("c")                                   # chat about the finding
        await settle(pilot)
        draft = app.screen.query_one(PromptBox).input.value
        assert fid in draft and SECRET not in draft             # draft names it, masked


# --- live refill: the cursor stays on the same finding by id --------------------------------
async def test_the_cursor_stays_on_the_same_finding_when_rows_arrive_above(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("down")                                # cursor on 002
        assert _cursor_id(app) == "002"
        add_finding("New critical", "/c", severity="CRITICAL")   # sorts to the top, above 002
        app.refresh_view()
        await settle(pilot)
        assert _row_ids(app)[0].startswith("AI-")                # the new row is above
        assert _cursor_id(app) == "002"                          # cursor kept its finding


async def test_the_cursor_falls_back_when_the_filter_hides_it(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        assert _cursor_id(app) == "001"                          # a MEDIUM finding
        await _pick_filter(app, pilot, "low")                    # hides 001 and 002, leaves 003
        assert _row_ids(app) == ["003"]
        assert _cursor_id(app) == "003"                          # fell back sensibly, no crash


KEY_COLUMNS = {"ID", "SEVERITY", "TITLE", "STATUS", "VALIDATION"}

# A 50-char title fits at 120x36 (stays full) but not at 80x24 (gets cut), so it exercises the cap.
MED_TITLE = "Insecure direct object reference on account data ok"   # 50 chars
LONG_TITLE = "X" * 70


def _title_cell(app, row_id: str) -> str:
    table = _table(app)
    key = table.coordinate_to_cell_key((_row_ids(app).index(row_id), 2)).column_key
    return table.get_cell(row_id, key).plain


# --- the list (8 columns, STATUS/VALIDATION kept visible) measured at 80x24 and 120x36 -------
# Measured regions, not screen_text (which reads content regardless of what is on screen): the
# triage-critical STATUS and VALIDATION are in the no-scroll region at both sizes; PATH/TOOL/CVE
# scroll off the right at 80x24. At 120x36 all 8 columns fit.
@pytest.mark.parametrize("size,scrolls_right", [((80, 24), True), ((120, 36), False)])
async def test_the_findings_list_keeps_status_visible(app, size, scrolls_right):
    run_to(None)
    async with app.run_test(size=size) as pilot:
        await show(app, pilot, "findings")
        table = _table(app)
        assert _row_ids(app) == ["001", "002", "003"]
        # strip + view line + rows are visible together: the body never scrolls vertically here
        assert app.screen.query_one("#body").max_scroll_y == 0
        columns = _fully_visible_columns(table)
        assert KEY_COLUMNS <= set(columns)                       # STATUS/VALIDATION never hidden
        assert table.scroll_offset.x == 0
        if scrolls_right:                                        # 80x24: PATH/TOOL/CVE scroll off
            assert table.max_scroll_x > 0
            assert "CVE / CWE" not in columns
        else:                                                    # 120x36: every column fits
            assert table.max_scroll_x == 0
            assert len(columns) == len(table.ordered_columns)


async def test_a_long_title_is_cut_but_status_stays_visible_at_80x24(app):
    run_to(None)
    add_finding(LONG_TITLE, "/x", severity="CRITICAL")
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "findings")
        table = _table(app)
        fid = _row_ids(app)[0]                                   # the CRITICAL finding, on top
        assert "…" in _title_cell(app, fid)                     # the title cell is cut
        columns = _fully_visible_columns(table)
        assert KEY_COLUMNS <= set(columns) and table.scroll_offset.x == 0


async def test_triage_status_is_visible_in_the_row_without_scrolling(app):
    run_to(None)
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("down", "t")                           # triage 002
        await settle(pilot)
        await pilot.press("4")                                   # False positive
        await settle(pilot)
        assert store.get_finding("002").status == "false-positive"
        table = _table(app)
        assert "STATUS" in _fully_visible_columns(table) and table.scroll_offset.x == 0
        key = table.coordinate_to_cell_key((_row_ids(app).index("002"), 3)).column_key
        assert table.get_cell("002", key).plain == "False positive"    # the new status, in the row


async def test_the_full_title_shows_at_120x36(app):
    run_to(None)
    add_finding(MED_TITLE, "/x", severity="CRITICAL")
    async with app.run_test(size=(120, 36)) as pilot:
        await show(app, pilot, "findings")
        fid = _row_ids(app)[0]
        assert _title_cell(app, fid) == MED_TITLE               # shown in full, not cut


async def test_the_title_refits_on_resize(app):
    run_to(None)
    add_finding(MED_TITLE, "/x", severity="CRITICAL")
    async with app.run_test(size=(80, 24)) as pilot:
        await show(app, pilot, "findings")
        fid = _row_ids(app)[0]
        assert "…" in _title_cell(app, fid)                     # cut at 80 wide
        await pilot.resize_terminal(120, 36)
        await settle(pilot)
        assert _title_cell(app, fid) == MED_TITLE               # full again once there is room


@pytest.mark.parametrize("size,body_scrolls", [((80, 24), True), ((120, 36), False)])
async def test_the_finding_detail_header_is_visible(app, size, body_scrolls):
    run_to(None)
    async with app.run_test(size=size) as pilot:
        app.open_finding("001")
        await settle(pilot)
        assert isinstance(app.screen, FindingDetailScreen)
        body = app.screen.query_one("#body")
        header = app.screen.query_one("#detail-header", Vertical)
        panels = list(app.screen.query("#detail-cols .panel"))
        assert len(panels) == 2 and all(p.size.width > 0 for p in panels)
        # the header line (severity · title · status) sits in the visible region, no scroll
        assert _region_visible(header.query(Static).first(), body)
        # 80x24: the taller AI panel pushes the body past one screen (scroll to read its foot);
        # 120x36: the whole detail fits with no scrolling.
        assert (body.max_scroll_y > 0) == body_scrolls


# --- a live refill while a dialog is open leaves it alone, then restores the table -----------
@pytest.mark.parametrize("dialog_key", ["t", "f"])     # triage, filter
async def test_a_live_refill_under_a_dialog_keeps_it_and_restores_focus(app, dialog_key):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        await pilot.press("down")                                # cursor on 002
        assert _cursor_id(app) == "002"
        await pilot.press(dialog_key)
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        menu = app.screen.query_one("#dialog-menu")
        assert app.focused is menu
        add_finding("New critical live", "/c", severity="CRITICAL")   # a refill arrives above 002
        app.refresh_view()
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)             # the dialog did not close
        assert app.focused is menu                              # and did not lose focus
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)
        assert app.focused is _table(app)                       # the table has focus again
        assert _cursor_id(app) == "002"                         # still on the same finding
