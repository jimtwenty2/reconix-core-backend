"""The test plan, drafted by the AI on the Core API after the scope is approved.

The fake API (tests/fakes/fake_api.py) plans like services/api: three steps, kept as a
draft until Run plan sends it. Reconix names the plan's phases after the draft's steps and
never runs anything while drafting.
"""

import threading

import pytest
from textual.widgets import OptionList

from reconix import store
from reconix.core_api import run_api
from reconix.screens import PlanScreen

from .support import SIZE, DEMO_REQUEST, draft_plan, play_until_gate, run_ui_to, wait_until


@pytest.fixture
def at_scope_approved(fake_api):
    """The run waits at the plan with the scope approved on the API, no draft asked yet."""
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    store.approve_scope()
    assert play_until_gate() == "plan"
    return fake_api


def _labels():
    return [task.label for task in store.get_assessment().plan]


def test_the_phases_are_named_after_the_apis_draft(at_scope_approved):
    draft_plan()
    labels = _labels()
    assert labels[:3] == ["Find open ports", "Check for known issues", "Confirm the login weakness"]
    assert store.plan_author() == "fake-model"
    assert len(store.get_assessment().live.plan_steps) == 3


def test_a_phase_names_only_the_scopes_own_tools(at_scope_approved):
    draft_plan()
    tasks = {task.key: task for task in store.get_assessment().plan}
    assert tasks["scanning"].tools == ("Nuclei",)  # NUCLEI, as the scope names it
    assert tasks["discovery"].tools == ()  # NMAP is not in a web scope
    assert tasks["scanning"].detail == "Then look for weaknesses."


def test_drafting_runs_nothing(at_scope_approved):
    draft_plan()
    assert at_scope_approved.tool_runs() == []
    assert not any(path.endswith("/send") for path in at_scope_approved.paths())
    assert not store.is_plan_started()


def test_run_plan_waits_for_the_draft(at_scope_approved):
    request = store.plan_draft_request()
    with pytest.raises(store.StoreValidationError, match="drafting"):
        store.run_plan()
    store.apply_plan_draft(request, store.fetch_plan_draft(request))
    store.run_plan()
    assert store.is_plan_started()


def test_a_failed_draft_keeps_run_plan_closed(at_scope_approved):
    at_scope_approved.fail_on["POST /assessments/"] = (503, "MODEL_UNAVAILABLE", "no model")
    draft_plan()
    assert not store.plan_drafting()
    assert "couldn't draft the plan" in store.get_assessment().chat[-1].text
    with pytest.raises(store.StoreValidationError, match="no plan from the AI"):
        store.run_plan()


def test_a_plan_with_nothing_to_send_leaves_run_plan_closed(at_scope_approved, monkeypatch):
    real = run_api.draft_plan

    def nothing(assessment_id):
        out = real(assessment_id)
        return {**out, "draft": False, "plan": [], "action": None}   # what services/api says

    monkeypatch.setattr(run_api, "draft_plan", nothing)
    draft_plan()
    assert store.plan_author() == ""
    with pytest.raises(store.StoreValidationError, match="no plan from the AI"):
        store.run_plan()


def test_blocked_plan_steps_are_shown_as_policy_lines(at_scope_approved, monkeypatch):
    real = run_api.draft_plan

    def with_blocked(assessment_id):
        out = real(assessment_id)
        out["blocked"] = [{"order": 4, "blocked_by": "SCOPE", "reason": "TARGET_OUT_OF_SCOPE"}]
        return out

    monkeypatch.setattr(run_api, "draft_plan", with_blocked)
    draft_plan()
    lines = [e.message for e in store.get_assessment().activity if e.source == "POLICY"]
    assert any("TARGET_OUT_OF_SCOPE" in line and "step 4" in line for line in lines)


def test_a_draft_for_a_plan_that_already_runs_is_dropped(at_scope_approved):
    draft_plan()
    store.run_plan()
    late = store.plan_draft_request()
    assert late is None  # no second draft once it runs


def test_no_draft_before_the_scope_is_approved(fake_api):
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    assert store.plan_draft_request() is None


async def test_the_plan_screen_shows_only_a_loading_line_while_drafting(app, monkeypatch):
    release = threading.Event()
    real = run_api.draft_plan

    def slow(assessment_id):
        release.wait(5)
        return real(assessment_id)

    monkeypatch.setattr(run_api, "draft_plan", slow)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", DEMO_REQUEST)
        app.approve_scope()
        await wait_until(
            pilot,
            lambda: isinstance(app.screen, PlanScreen) and bool(app.screen.query("#plan-drafting")),
            what="the loading line",
        )
        assert not app.screen.query("#plan-menu")  # nothing to run yet
        labels = " ".join(str(w.render()) for w in app.screen.query(".ai-label"))
        assert "drafting the plan" in labels
        release.set()
        await wait_until(
            pilot, lambda: bool(app.screen.query("#plan-menu")), what="the drafted plan"
        )
        rows = app.screen.query_one("#plan-list", OptionList)
        assert "Find open ports" in str(rows.get_option_at_index(0).prompt)
        assert not app.screen.query("#plan-drafting")


async def test_the_plan_screen_names_the_model_that_drafted_it(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan", DEMO_REQUEST)
        await wait_until(
            pilot,
            lambda: isinstance(app.screen, PlanScreen) and bool(app.screen.query("#plan-menu")),
            what="the plan menu",
        )
        labels = " ".join(str(w.render()) for w in app.screen.query(".ai-label"))
        assert "phases drafted by fake-model" in labels
