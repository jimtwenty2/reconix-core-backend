"""Multiple assessments in one session: create, list, reopen, and isolation."""

from reconix import store
from reconix.screens import (
    ApprovalScreen, ChoiceScreen, FindingsListScreen, StartScreen, TemplateScreen,
)

from .support import SIZE, decide, play_until_gate, run_to, settle, wait_until
from .support import DEMO_REQUEST


def test_a_new_assessment_keeps_the_earlier_ones():
    run_to(None)                                   # a completed web assessment
    first = store.get_assessment().label
    store.new_assessment()
    assert store.get_assessment().label != first
    cards = store.list_assessments()
    assert len(cards) == 2
    assert cards[0].status == "Completed" and cards[0].target == "staging.example.com"
    assert cards[1].status == "New" and cards[1].current


def test_assessments_are_isolated_and_reopenable():
    run_to("account")                              # web, mid-run
    web_findings = len(store.list_findings())
    store.new_assessment()
    store.start_run("scan 10.0.0.0/24 for open ports")
    assert store.get_assessment().template_id == "network"
    assert store.list_findings() == []             # the new one has its own (empty) state
    store.switch_assessment(0)                     # reopen the web assessment
    assert store.get_assessment().template_id == "web_url"
    assert len(store.list_findings()) == web_findings
    assert store.get_scope().kind == "web_url"


def test_switch_rejects_a_bad_index():
    import pytest
    with pytest.raises(store.StoreValidationError):
        store.switch_assessment(5)


async def test_assessments_lists_and_reopens(app):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        run_to(None)                               # complete the first (web) assessment
        app.new_assessment()                       # a second, fresh one is now current
        await settle(pilot)
        app.run_command_line("/assessments")
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        await pilot.press("1")                     # reopen the completed web assessment
        await settle(pilot)
        assert store.is_completed()
        assert store.get_assessment().target == "staging.example.com"
        app.goto("findings")
        await settle(pilot)
        assert isinstance(app.screen, FindingsListScreen)


async def test_assessments_new_starts_fresh(app):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        run_to("scope")
        app.run_command_line("/list")
        await settle(pilot)
        await pilot.press("2")                     # New assessment (after the one listed)
        await settle(pilot)
        assert isinstance(app.screen, StartScreen)
        assert not store.get_run().started
        assert len(store.list_assessments()) == 2


async def test_reopening_shows_where_it_stands(app):
    run_to("scope")                                # the first waits for its scope
    store.new_assessment()
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.switch_assessment(0)
        await settle(pilot)
        assert isinstance(app.screen, TemplateScreen)
        assert app.screen.state() == "review"


async def test_reopening_a_running_assessment_resumes_it(app):
    # Drive the first assessment to a between-gates running state (no waiting gate): the
    # plan is sent, its first step not asked for yet.
    store.start_run(DEMO_REQUEST)            # the URL picks Web URL itself
    for _ in range(2):                             # scope (and its plan draft), plan
        decide(play_until_gate())
    store.advance()                                # play past the plan gate
    assert store.waiting_gate() == "" and not store.is_finished()
    store.new_assessment()

    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        app.switch_assessment(0)
        await settle(pilot)
        # The run played on: the Core API ran the LOW step and holds the MEDIUM one.
        await wait_until(pilot, lambda: isinstance(app.screen, ApprovalScreen),
                         what="the MEDIUM approval")
        assert store.waiting_gate().startswith("approval:")
        assert store.get_approval(store.waiting_gate().split(":", 1)[1]).risk == "MEDIUM"


# --- /new on an assessment that is still empty -------------------------------------------------
def test_a_fresh_assessment_is_empty_until_something_is_recorded():
    assert store.is_empty_assessment()
    store.add_request("check the login page")      # something the operator typed
    assert not store.is_empty_assessment()


def test_new_on_an_empty_assessment_keeps_it(monkeypatch):
    from reconix.store import persist

    saves = []
    monkeypatch.setattr(persist, "autosave", lambda: saves.append(1) or True)
    first = store.get_assessment().label
    events = len(store.list_events())
    for _ in range(3):
        assert store.new_assessment() is False
    assert store.get_assessment().label == first
    assert len(store.list_assessments()) == 1
    assert len(store.list_events()) == events and saves == []


def test_new_after_a_target_creates_the_next_id():
    run_to("scope")
    first = store.get_assessment().label
    assert not store.is_empty_assessment()
    assert store.new_assessment() is True
    cards = store.list_assessments()
    assert [card.label for card in cards] == [first, store.get_assessment().label]
    assert cards[1].label == first[:-3] + f"{int(first[-3:]) + 1:03d}"   # numbering never skips
