"""Small QA fixes (2026-11-04): the step bar, action names, the plan card, skipped steps, the
help, 80-column cosmetics, UTC times, /provider, /add-on duplicates, report file names and
labels, length messages and the stopped run's findings."""

from datetime import datetime, timezone

import pytest

from reconix import store
from reconix.models import PlanRow
from reconix.screens import ChoiceScreen, ExecutionScreen, FindingsListScreen, HelpScreen
from reconix.screens.execution import task_line
from reconix.store import report, report_view
from reconix.widgets import ChoiceMenu, FlowProgress
from reconix.widgets.plan_rows import LABEL_WIDTH, NUM_WIDTH, plan_line
from reconix.wording import clock, counted

from .support import (
    NETWORK,
    SIZE,
    TEST_PASSWORD,
    decide,
    play_until_gate,
    run_to,
    run_to_end,
    screen_text,
    settle,
    show,
    wait_until,
)
from .support import DEMO_REQUEST

SMALL = (80, 24)
FAKE_KEY = "sk-1234"  # noqa: S105 - a fake


def _to_gate(risk: str, request: str = DEMO_REQUEST) -> str:
    """Run until the API's step of `risk` (MEDIUM or HIGH) waits for you; its request id.
    The fake API plans a LOW, a MEDIUM and a HIGH step, in that order; MEDIUM is approved
    on the way to HIGH."""
    run_to("plan", request=request)
    decide("plan")
    while True:
        gate = play_until_gate()
        assert gate and gate.startswith("approval:")
        request_id = gate.split(":", 1)[1]
        if store.get_approval(request_id).risk == risk:
            return request_id
        decide(gate)


def _bar(app) -> str:
    return app.screen.query_one(FlowProgress)._render_line(120).plain


# --- 1: a step is ✓ only when it is done ------------------------------------------------------
async def test_report_with_no_assessment_marks_nothing_done(app):
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "report")
        bar = _bar(app)
        assert "✓" not in bar  # was "✓ Findings" before the report


async def test_findings_are_not_done_while_the_run_waits(app):
    _to_gate("HIGH")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "report")
        assert "✓ Findings" not in _bar(app) and "○ Findings" in _bar(app)


# --- 2: HIGH actions have a human name everywhere ----------------------------------------------
@pytest.mark.parametrize("request_text", [DEMO_REQUEST, f"Scan {NETWORK} for services"])
def test_gated_actions_have_human_names(request_text):
    high = _to_gate("HIGH", request_text)
    for request in store.get_assessment().approvals:
        assert "_" not in request.action and " " in request.action
    store.reject(high)
    run_to_end()
    activity = " ".join(entry.message for entry in store.list_activity())
    assert "_validation" not in activity and "_probe" not in activity


# --- 3: the plan card always keeps a gap after the label ----------------------------------------
@pytest.mark.parametrize("width", [0, 70, 110])
def test_a_long_label_gets_its_own_line_in_the_card(width):
    label = "Banner and TLS check (read-only)"  # 32 characters: longer than its column
    row = PlanRow(
        "3a",
        label,
        "",
        "MEDIUM",
        "approve",
        "pending",
        command="connect 10.0.0.1:8443 · read banner + TLS",
    )
    lines = plan_line(row, width, full=True).plain.split("\n")
    assert lines[0].rstrip() == f" 3a {label}"
    assert lines[1].startswith(" " * (NUM_WIDTH + LABEL_WIDTH) + "$ connect")


# --- 4: a step whose every gated check was rejected is skipped, not done ------------------------
def _reject_both() -> None:
    store.reject(_to_gate("MEDIUM"))
    gate = play_until_gate()
    assert gate and store.get_approval(gate.split(":", 1)[1]).risk == "HIGH"
    store.reject(gate.split(":", 1)[1])
    run_to_end()


def test_rejecting_every_check_marks_the_validation_skipped():
    _reject_both()
    assert store.validation_skipped()
    row = next(r for r in store.plan_overview() if r.num == "3")
    assert row.status == "skipped"
    task = next(t for t in store.plan_tasks() if t.key == "validation")
    line = task_line(task, "complete").plain
    assert line.startswith("✕") and "skipped" in line


def test_one_rejected_check_of_two_says_so():
    store.reject(_to_gate("HIGH"))
    run_to_end()
    task = next(t for t in store.plan_tasks() if t.key == "validation")
    line = task_line(task, "complete").plain
    assert line.startswith("✓") and "1 check skipped" in line
    assert not store.validation_skipped()


# --- 5: the help's scroll hint follows the scroll; it uses a wide terminal ---------------------
async def test_help_scroll_hint_clears_at_the_end(app):
    async with app.run_test(size=SMALL) as pilot:
        await pilot.press("question_mark")
        await settle(pilot, 6)
        assert isinstance(app.screen, HelpScreen)
        box = app.screen.query_one("#help-box")
        assert box.max_scroll_y > 0 and "↓ more" in str(box.border_subtitle)
        box.scroll_end(animate=False)
        await settle(pilot)
        assert "↓ more" not in str(box.border_subtitle)


async def test_help_uses_the_width_and_indents_wrapped_rows(app):
    async with app.run_test(size=(120, 36)) as pilot:
        await pilot.press("question_mark")
        await settle(pilot, 6)
        box = app.screen.query_one("#help-box")
        assert box.size.width > 90
        descs = app.screen.query(".help-desc")
        assert descs and all(d.region.x == descs.first().region.x for d in descs)


# --- 6: 80-column cosmetics --------------------------------------------------------------------
async def test_long_choice_hints_wrap_under_themselves(app, monkeypatch):
    monkeypatch.setattr(type(app), "ASK_PROVIDER_ON_START", True)
    async with app.run_test(size=SMALL) as pilot:
        await settle(pilot, 6)
        menu = app.screen.query_one("#dialog-menu", ChoiceMenu)
        lines = str(menu.get_option_at_index(0).prompt).split("\n")
        assert len(lines) >= 3  # the hint wrapped …
        assert all(line.startswith("     ") for line in lines[1:])  # … under itself


async def test_execution_counters_fit_at_80_columns(app):
    run_to(None)  # the demo, to its end
    async with app.run_test(size=SMALL) as pilot:
        await show(app, pilot, "execution")
        await settle(pilot)
        panel = app.screen.query_one("#exec-panel")
        subtitle = str(panel.border_subtitle)
        assert "…" not in subtitle and len(subtitle) + 4 <= panel.size.width
        assert "total" in subtitle and "findings" in subtitle


@pytest.mark.parametrize("size,whole", [(SMALL, False), (SIZE, True)])
async def test_the_high_confirmation_hash_fits_one_line(app, size, whole):
    digest = store.get_approval(_to_gate("HIGH")).command_hash
    async with app.run_test(size=size) as pilot:
        await show(app, pilot, "approval")
        app.screen.action_approve()
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        text = screen_text(app.screen)
        assert (digest in text) is whole  # whole when it fits on one line
        if not whole:
            assert "View details" in text and digest[-8:] in text


# --- 7: times say UTC ---------------------------------------------------------------------------
def test_clock_labels_utc():
    moment = datetime(2026, 11, 4, 15, 49, 1, tzinfo=timezone.utc)
    assert clock(moment) == "15:49:01 UTC"
    assert clock(moment.replace(tzinfo=None)) == "15:49:01 UTC"
    assert counted(1, "finding") == "1 finding" and counted(2, "passage") == "2 passages"


async def test_the_audit_dialog_labels_its_times(app):
    _to_gate("HIGH")
    async with app.run_test(size=SIZE) as pilot:
        app.show_audit()
        await settle(pilot)
        assert " UTC" in screen_text(app.screen)


# --- 8: /provider -------------------------------------------------------------------------------
async def test_disabled_provider_choices_say_why(app):
    async with app.run_test(size=SIZE) as pilot:
        app.open_provider_submenu("openai")
        await settle(pilot)
        menu = app.screen.query_one("#dialog-menu", ChoiceMenu)
        prompts = [str(menu.get_option_at_index(i).prompt) for i in range(menu.option_count)]
        assert not any("not in demo" in p for p in prompts)
        assert "set up first" in prompts[1] and "set up first" in prompts[2]


async def test_a_tested_provider_becomes_active_when_none_is(app, reachable):
    # A model on this computer (Ollama) is active at once; a cloud model would ask for your OK.
    store.set_provider("ollama", base_url="http://127.0.0.1:11434", models=["llama3.2"])
    assert store.active_model() is None
    async with app.run_test(size=SIZE) as pilot:
        app.test_provider_async("ollama")
        await wait_until(pilot, lambda: store.active_model() is not None, what="active")
        assert store.active_model().provider_id == "ollama"


async def test_the_provider_list_shows_its_first_row_when_it_fits(app, reachable):
    store.set_provider("openai", api_key=FAKE_KEY, models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")  # a row below the first is the active one
    async with app.run_test(size=(120, 36)) as pilot:
        app.open_provider_menu()
        await settle(pilot, 6)
        menu = app.screen.query_one("#dialog-menu", ChoiceMenu)
        assert menu.max_scroll_y == 0 and menu.scroll_y == 0


# --- 9: /add-on refuses the same file twice ---------------------------------------------------
def test_the_same_add_on_twice_is_refused(tmp_path):
    path = tmp_path / "runbook.md"
    path.write_text("SQL injection reference material for the staging engagement.")
    store.add_source(str(path))
    with pytest.raises(store.StoreValidationError, match="already added"):
        store.add_source(str(path))
    path.write_text("Different reference material, same name.")
    store.add_source(str(path))  # changed content: a new source
    assert len(store.list_sources()) == 2


# --- 10/11: report files and labels ------------------------------------------------------------
def test_a_report_never_replaces_another_sessions_file():
    run_to(None)
    folder = report.REPORTS_DIR
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "RCX-001.json").write_text("an earlier session's report")
    first = store.generate_report("json")
    assert first.endswith("RCX-001-2.json")
    assert (folder / "RCX-001.json").read_text() == "an earlier session's report"
    assert store.generate_report("json") == first  # a re-export overwrites its own file
    assert TEST_PASSWORD not in (folder / "RCX-001-2.json").read_text()


def test_report_status_reads_false_positive():
    assert report_view.status_label({"status": "false-positive"}) == "False positive"


# --- 12: the length limit is "at most" ----------------------------------------------------------
def test_the_length_message_says_at_most():
    with pytest.raises(store.StoreValidationError, match="at most 500"):
        store.start_run("a" * 501)


# --- 13: a stopped run's findings ---------------------------------------------------------------
async def test_a_stopped_run_with_no_findings_says_testing_stopped(app):
    store.start_run(DEMO_REQUEST)
    store.stop_run()
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "findings")
        assert isinstance(app.screen, FindingsListScreen)
        text = screen_text(app.screen)
        assert "Testing stopped" in text and "as testing finds them" not in text


async def test_the_execution_screen_still_opens(app):
    _to_gate("HIGH")
    async with app.run_test(size=SMALL) as pilot:
        await show(app, pilot, "execution")
        assert isinstance(app.screen, ExecutionScreen)
        assert "paused" in str(app.screen.query_one("#exec-panel").border_subtitle)
