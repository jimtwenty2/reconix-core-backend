"""The Plan screen through the real app: every state, the menu, the keys, live rows, layout.

Safety first: nothing on this screen may approve a step, skip a gate or start the plan twice.
The store decides; the screen asks. Demo data only, steps play at once (RunController.SPEED 0).
"""

import pytest
from textual import events
from textual.widgets import OptionList

from reconix import store
from reconix.screens import ChoiceScreen, ExecutionScreen, PlanScreen, TemplateScreen
from reconix.screens.plan import EDIT_UNAVAILABLE
from reconix.widgets import ChoiceMenu

from .support import (
    ASK_REQUEST,
    SIZE,
    decide,
    event_kinds,
    play_until_gate,
    run_to,
    screen_text,
    settle,
    show,
)

SMALL = (80, 24)
WIDE = (160, 50)


def plan_list(app) -> OptionList:
    return app.screen.query_one("#plan-list", OptionList)


def menu(app) -> ChoiceMenu:
    return app.screen.query_one("#plan-menu", ChoiceMenu)


def menu_ids(app) -> list:
    return [c.id for c in menu(app)._choices]


def row_texts(app) -> list:
    rows = plan_list(app)
    return [str(rows.get_option_at_index(i).prompt) for i in range(rows.option_count)]


def approvals_decided() -> int:
    return len(store.list_approval_decisions())


def burst_of_enters(app, count: int) -> None:
    """Enter pressed `count` times faster than the app reacts, as a terminal delivers them."""
    for _ in range(count):
        key = events.Key("enter", "\r")
        key.set_sender(app)
        app._driver.send_message(key)


async def open_plan(app, pilot) -> None:
    await show(app, pilot, "plan")
    await settle(pilot)
    assert isinstance(app.screen, PlanScreen)


# --- the states the store can be in (set up through the store, as the run would) ----------
def to_busy() -> None:
    run_to("scope")
    decide("scope")  # approved; the plan gate hasn't been reached yet


def to_running() -> None:
    run_to("plan")
    decide("plan")
    play_until_gate()  # the next gate after the plan (login or approval)


def to_stopped_mid_plan() -> None:
    to_running()
    store.stop_run()


def to_stopped_before_plan() -> None:
    run_to("scope")
    store.reject_scope()


STATES = [
    # (set-up, state, question, menu choice ids)
    (lambda: store.start_run(ASK_REQUEST), "none", "Go to the template?", ["template"]),
    (lambda: run_to("scope"), "draft", "Approve the scope first", ["template", "chat"]),
    (lambda: run_to("plan"), "ready", "Run this plan?", ["run", "edit", "cancel", "type", "chat"]),
    (to_running, "running", "The plan is running.", ["execution", "chat"]),
    (lambda: run_to(None), "finished", "The plan has run.", ["findings", "execution", "chat"]),
    (to_stopped_before_plan, "stopped", "This assessment stopped", ["new"]),
    (to_stopped_mid_plan, "stopped", "What ran is kept.", ["findings", "execution", "new"]),
]


# --- 1-7: every state shows the right panel, rows, actions and hint ------------------------
@pytest.mark.parametrize("setup, state, question, choices", STATES)
async def test_each_state_shows_its_panel_rows_and_actions(app, setup, state, question, choices):
    setup()
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        assert PlanScreen.state() == state
        text = screen_text(app.screen)
        assert question in text
        assert menu_ids(app) == choices
        if state != "none":
            assert plan_list(app).option_count == len(store.plan_overview())
        else:
            assert not app.screen.query("#plan-list")


async def test_busy_shows_the_rows_and_a_spinner_and_offers_no_action(app):
    to_busy()
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        assert PlanScreen.state() == "busy"
        assert plan_list(app).option_count == len(store.plan_overview())
        assert not app.screen.query("#plan-menu")  # nothing can start or change
        assert app.screen.query(".spinner")


async def test_finished_and_stopped_panels_keep_the_results(app):
    run_to(None)
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        note = str(app.screen.query_one("#plan-results").render())
        assert note.startswith("■ Finished:") and "done" in note
        assert any("✓ done" in row for row in row_texts(app))


async def test_a_run_stopped_mid_plan_is_not_called_finished(app):
    to_stopped_mid_plan()
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        text = screen_text(app.screen)
        assert "The plan has run." not in text and "stopped" in text
        note = str(app.screen.query_one("#plan-results").render())
        assert note.startswith("■ Stopped:") and "not run" in note
        assert any("✓ done" in row for row in row_texts(app))  # 27: what ran is kept


# --- 12, 31: live transitions follow the store, one row per step -----------------------------
async def test_rows_follow_the_run_live(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        assert all("· pending" in row for row in row_texts(app))
        store.run_plan()
        play_until_gate()
        app.screen.refresh_live()  # what the app calls after each step
        rows = store.plan_overview()
        assert [r.status for r in rows] != ["pending"] * len(rows)
        for row, shown in zip(rows, row_texts(app)):
            label = {
                "done": "✓ done",
                "active": "◌ now",
                "pending": "· pending",
                "rejected": "✕ rejected",
            }[row.status]
            assert label in shown, (row.num, row.status, shown)


async def test_repeated_refreshes_never_duplicate_or_mix_up_rows(app):
    to_running()
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        before = row_texts(app)
        for _ in range(5):  # 26: repeated / late progress events
            app.screen.refresh_live()
            app.refresh_view()
        await settle(pilot)
        assert row_texts(app) == before
        ids = [plan_list(app).get_option_at_index(i).id for i in range(plan_list(app).option_count)]
        assert len(ids) == len(set(ids)) == len(store.plan_overview())


# --- 14, 19: Run plan starts the plan exactly once ---------------------------------------------
async def test_run_plan_starts_once_and_opens_execution(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("1")
        await settle(pilot)
        # Execution is shown; the demo's next gate (the target login) opens over it.
        assert store.is_plan_started() and isinstance(app.flow_screen(), ExecutionScreen)
        assert event_kinds().count("plan.run") == 1


async def test_choosing_run_plan_twice_still_starts_once(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        menu(app).choose_highlighted()  # both picks land before either runs
        menu(app).choose_highlighted()
        await settle(pilot)
        assert event_kinds().count("plan.run") == 1
        app.run_plan()  # and once more, after it started
        await settle(pilot)
        assert event_kinds().count("plan.run") == 1


@pytest.mark.xfail(
    strict=True,
    reason="BLOCKED until terminal/input-validation merges: the "
    "gate menus' arm delay lives in its widgets/choice_menu.py",
)
async def test_holding_enter_on_the_scope_never_runs_the_plan(app):
    # Enter held while approving the scope repeats every ~40 ms; today the third repeat
    # picks "Run plan" the moment its gate appears, before anyone could read the plan.
    run_to("scope")
    async with app.run_test(size=SIZE) as pilot:
        await show(app, pilot, "template")
        for _ in range(8):
            burst_of_enters(app, 1)
            await pilot.pause(0.04)
        await settle(pilot, rounds=10)
        assert store.is_scope_approved()
        assert not store.is_plan_started()


# --- 20: every MEDIUM / HIGH step still waits at its own approval gate -------------------------
def test_every_gated_step_waits_for_its_approval():
    run_to("plan")
    store.run_plan()
    waited = []
    while True:
        gate = play_until_gate()
        if gate is None:
            break
        if gate.startswith("approval:"):
            waited.append(gate.split(":", 1)[1])
            assert store.decision_for(waited[-1]) is None  # nothing decided it for us
        decide(gate)
    assert sorted(waited) == sorted(a.request_id for a in store.get_assessment().approvals)


async def test_nothing_on_the_running_plan_screen_approves_a_step(app):
    run_to("plan")
    store.run_plan()
    gate = play_until_gate()
    while not gate.startswith("approval:"):
        decide(gate)
        gate = play_until_gate()
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("tab", "down", "enter", "tab", "escape")
        await settle(pilot)
        assert store.waiting_gate() == gate and approvals_decided() == 0


# --- 15-17: Edit steps -----------------------------------------------------------------------
async def test_edit_steps_opens_the_step_picker_when_allowed(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        assert not app.screen.query("#plan-edit-note")
        await pilot.press("2")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert "Which gated step" in screen_text(app.screen)


@pytest.fixture
def nothing_editable(monkeypatch):
    """No gated step can be edited (the store says so); every demo template has editable steps."""
    monkeypatch.setattr(store, "can_edit", lambda request_id: False)


async def test_edit_steps_is_disabled_and_says_why(app, nothing_editable):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        edit = next(c for c in menu(app)._choices if c.id == "edit")
        assert edit.disabled
        assert EDIT_UNAVAILABLE in str(app.screen.query_one("#plan-edit-note").render())
        # Follow-up: ChoiceMenu still tags it "(not in demo)" (choice_menu.py, other PR).
        assert "(not in demo)" in str(menu(app).get_option_at_index(1).prompt)


async def test_disabled_edit_cannot_be_chosen_any_way(app, nothing_editable):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("2")  # number key
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)
        menu(app).highlighted = 1  # Enter on it
        menu(app).choose_highlighted()
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)
        option = menu(app).get_option_at_index(1)  # a mouse click
        menu(app).post_message(OptionList.OptionSelected(menu(app), option, 1))
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)
        app.edit_plan_steps()  # the handler itself
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen)


# --- 18, 24: Cancel and Esc (today's behaviour: back to the Template screen) ------------------
async def test_cancel_goes_back_to_the_scope_and_the_plan_still_waits(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        before = [(r.num, r.status) for r in store.plan_overview()]
        await pilot.press("3")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert store.waiting_gate() == "plan" and not store.is_plan_started()
        await open_plan(app, pilot)  # and back again
        assert PlanScreen.state() == "ready"
        assert [(r.num, r.status) for r in store.plan_overview()] == before
        assert plan_list(app).option_count == len(before)


async def test_esc_steps_from_the_list_to_the_menu_then_back(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("tab")
        assert app.focused is plan_list(app)
        await pilot.press("escape")
        assert app.focused is menu(app)
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen) and not store.is_plan_started()


async def test_esc_in_busy_goes_back_even_from_the_list(app):
    to_busy()
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("tab")
        assert app.focused is plan_list(app)
        await pilot.press("escape")
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)


# --- 21-23: Tab, arrows, Enter -----------------------------------------------------------------
async def test_tab_toggles_between_menu_and_steps_both_ways(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        assert app.focused is menu(app)
        await pilot.press("tab")
        assert app.focused is plan_list(app) and plan_list(app).has_pseudo_class("focus")
        await pilot.press("tab")
        assert app.focused is menu(app) and menu(app).has_pseudo_class("focus")


async def test_arrows_move_in_the_focused_region_only(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("down")
        assert menu(app).highlighted == 1 and plan_list(app).highlighted == 0
        await pilot.press("tab", "down", "down")
        assert plan_list(app).highlighted == 2 and menu(app).highlighted == 1


async def test_enter_runs_the_highlighted_action_and_enter_on_a_step_returns_to_it(app):
    run_to("plan")
    async with app.run_test(size=SIZE) as pilot:
        await open_plan(app, pilot)
        await pilot.press("tab", "down", "enter")
        assert app.focused is menu(app) and not store.is_plan_started()
        await pilot.press("enter")
        await settle(pilot)
        assert store.is_plan_started()


async def test_the_highlighted_row_shows_its_full_command(app):
    run_to("plan")
    async with app.run_test(size=SMALL) as pilot:
        await open_plan(app, pilot)
        rows = store.plan_overview()
        index = next(i for i, r in enumerate(rows) if r.command)
        await pilot.press("tab", *["down"] * index)
        await settle(pilot)
        assert f"$ {rows[index].command}" in row_texts(app)[index]


# --- 25: live updates keep focus, the highlighted row and the scroll ---------------------------
async def test_live_updates_keep_focus_selection_and_scroll(app):
    to_running()
    async with app.run_test(size=SMALL) as pilot:
        await open_plan(app, pilot)
        await pilot.press("tab", "down", "down", "down")
        await settle(pilot)
        rows = plan_list(app)
        highlighted, scroll_y = rows.highlighted, rows.scroll_y
        decide(store.waiting_gate())
        play_until_gate()
        app.refresh_view()  # the run moved on (same state: running)
        await settle(pilot)
        assert isinstance(app.screen, PlanScreen) and app.focused is plan_list(app)
        assert plan_list(app).highlighted == highlighted
        assert plan_list(app).scroll_y == scroll_y


# --- 28-30: layout -------------------------------------------------------------------------------
@pytest.mark.parametrize("size", [SMALL, WIDE])
async def test_no_overflow_and_no_missing_parts(app, size):
    run_to("plan")
    async with app.run_test(size=size) as pilot:
        await open_plan(app, pilot)
        width, _ = app.size
        rows = plan_list(app)
        assert rows.region.right <= width and rows.max_scroll_x == 0
        assert app.screen.query_one("#body").max_scroll_x == 0
        inner = rows.scrollable_content_region.width
        for i, text in enumerate(row_texts(app)):
            if i != rows.highlighted:
                assert all(len(line) <= inner for line in text.split("\n")), text
        for part in (".ai-label", "#plan-list", "#plan-menu", ".menu-hint", ".chip"):
            assert app.screen.query(part), part
        assert app.screen.query_one(".chip").region.width > 0


async def test_focus_is_always_on_a_visible_region(app):
    run_to("plan")
    async with app.run_test(size=SMALL) as pilot:
        await open_plan(app, pilot)
        for _ in range(3):
            assert app.focused in (menu(app), plan_list(app))
            assert app.focused.has_pseudo_class("focus")
            await pilot.press("tab")
