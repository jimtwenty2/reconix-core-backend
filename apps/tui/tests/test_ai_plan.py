"""An AI-drafted plan: the model suggests the phases, the store decides what is used."""

import json

import pytest
from textual.widgets import OptionList

from reconix import store
from reconix.screens import PlanScreen
from reconix.store import ai_plan

from .support import SIZE, TEST_PASSWORD, play_until_gate, run_to, run_ui_to, wait_until


def _reply(phases) -> str:
    """A thinking model's reply: some prose around the JSON."""
    return "Here is the plan:\n```json\n" + json.dumps({"phases": phases}) + "\n```"


def _good_phases():
    tools = store.get_scope().tools
    return [
        {"key": "discovery", "label": "Map the shop's pages and forms",
         "detail": "crawl inside the scope", "tools": [tools[0].upper(), "sqlmap"]},
        {"key": "scanning", "label": "Check the login and cart",
         "detail": f"passive checks, password={TEST_PASSWORD}", "tools": []},
        {"key": "validation", "label": "[bold]Confirm[/] the candidates" + "!" * 60,
         "detail": "read-only", "tools": []},
    ]


@pytest.fixture
def at_scope(model_active):
    """A model active; the run waits at the scope, which is then approved."""
    run_to("scope")
    store.approve_scope()


def _labels():
    return {task.key: task.label for task in store.plan_tasks()}


def test_the_model_drafts_the_phases_and_reconix_checks_them(at_scope):
    template = _labels()
    request = store.plan_draft_request()
    assert request is not None and store.plan_drafting()
    assert ai_plan.apply_plan_draft(request, _reply(_good_phases()))
    tasks = {task.key: task for task in store.plan_tasks()}
    scope_tools = store.get_scope().tools
    assert tasks["discovery"].label == "Map the shop's pages and forms"
    assert tasks["discovery"].tools == (scope_tools[0],)           # canonical name, in scope
    assert "sqlmap" not in tasks["discovery"].tools                # not allowed: dropped
    assert any(a.source == "POLICY" and "sqlmap" in a.message and a.tone == "block"
               for a in store.list_activity())
    assert TEST_PASSWORD not in tasks["scanning"].detail           # masked
    assert len(tasks["validation"].label) == ai_plan.LABEL_MAX     # capped
    assert tasks["analysis"].label == template["analysis"]         # left out: the template's
    assert not store.plan_drafting()
    assert store.plan_author() == "OpenAI · gpt-4o-mini"


def test_the_plan_rows_show_the_ai_detail_and_tools(at_scope):
    request = store.plan_draft_request()
    ai_plan.apply_plan_draft(request, _reply(_good_phases()))
    first = store.plan_overview()[0]
    assert first.label == "Map the shop's pages and forms"
    assert first.detail == f"crawl inside the scope · {store.get_scope().tools[0]}"


def test_run_plan_waits_for_the_draft(at_scope):
    request = store.plan_draft_request()
    assert play_until_gate() == "plan"
    with pytest.raises(store.StoreValidationError, match="drafting"):
        store.run_plan()
    ai_plan.apply_plan_draft(request, _reply(_good_phases()))
    store.run_plan()
    assert store.is_plan_started()


@pytest.mark.parametrize("raw", ["I can't help with that.", "{not json}",
                                 '{"phases": "none"}', '{"phases": [{"key": "hack"}]}'])
def test_a_reply_without_a_usable_plan_keeps_the_template(at_scope, raw):
    template = _labels()
    request = store.plan_draft_request()
    assert not ai_plan.apply_plan_draft(request, raw)
    assert _labels() == template and store.plan_author() == ""
    assert not store.plan_drafting()
    assert "Kept the template's plan" in store.list_activity()[-1].message


def test_the_real_plan_is_found_after_an_echoed_example(at_scope):
    echo = 'I must reply {"phases": [{"key": "...", "label": "..."}]} so: {draft} '
    raw = echo + _reply(_good_phases())
    request = store.plan_draft_request()
    assert ai_plan.apply_plan_draft(request, raw)
    assert _labels()["discovery"] == "Map the shop's pages and forms"


def test_an_unusable_reply_is_asked_for_once_more(at_scope, monkeypatch):
    from reconix.llm import client

    replies, sent = ["{broken", _reply(_good_phases())], []
    monkeypatch.setattr(client, "complete",
                        lambda pid, model, messages, **kw: sent.append(messages) or
                        replies[len(sent) - 1])
    request = store.plan_draft_request()
    assert ai_plan.apply_plan_draft(request, store.fetch_plan_draft(request))
    assert len(sent) == 2 and "no usable plan" in sent[1][-1]["content"]


def test_a_failed_call_keeps_the_template(at_scope):
    template = _labels()
    request = store.plan_draft_request()
    store.plan_draft_failed(request, "timed out")
    assert _labels() == template and not store.plan_drafting()
    assert "timed out" in store.list_activity()[-1].message


def test_a_draft_for_a_plan_that_already_runs_is_dropped(at_scope):
    template = _labels()
    request = store.plan_draft_request()
    store.plan_draft_failed(request, "x")            # (lets Run plan through)
    play_until_gate()
    store.run_plan()
    assert not ai_plan.apply_plan_draft(request, _reply(_good_phases()))
    assert _labels() == template


def test_without_a_model_there_is_no_draft():
    run_to("scope")
    store.approve_scope()
    assert store.plan_draft_request() is None


def test_the_model_sees_the_approved_scope_masked(at_scope, monkeypatch):
    from reconix.llm import client

    sent = []
    monkeypatch.setattr(client, "complete",
                        lambda pid, model, messages, **kw: sent.append(messages) or "{}")
    request = store.plan_draft_request()
    assert store.fetch_plan_draft(request) == "{}"
    system, question = sent[0]
    assert system["content"] == ai_plan.PLAN_PROMPT
    assert f"allowed tools: {', '.join(store.get_scope().tools)}" in question["content"]


async def test_the_plan_screen_shows_only_a_loading_line_while_drafting(
        app, model_active, monkeypatch):
    import threading

    from reconix.llm import client

    release = threading.Event()

    def slow(pid, model, messages, **kw):
        release.wait(5)
        return _reply(_good_phases())

    monkeypatch.setattr(client, "complete", slow)
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan")
        await wait_until(pilot, lambda: isinstance(app.screen, PlanScreen)
                         and bool(app.screen.query("#plan-drafting")), what="the loading line")
        assert not app.screen.query("#plan-list")                 # no template steps
        assert not app.screen.query("#plan-menu")                 # nothing to run yet
        labels = " ".join(str(w.render()) for w in app.screen.query(".ai-label"))
        assert "drafting the plan" in labels and "steps planned" not in labels
        release.set()
        await wait_until(pilot, lambda: bool(app.screen.query("#plan-list")),
                         what="the drafted steps")
        rows = app.screen.query_one("#plan-list", OptionList)
        assert "Map the shop's pages and forms" in str(rows.get_option_at_index(0).prompt)
        assert not app.screen.query("#plan-drafting")


async def test_the_plan_screen_shows_the_drafted_phases(app, model_active, monkeypatch):
    from reconix.llm import client

    monkeypatch.setattr(client, "complete",
                        lambda pid, model, messages, **kw: _reply(_good_phases()))
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "plan")
        await wait_until(pilot, lambda: store.plan_author() != "", what="the AI draft")
        await wait_until(pilot, lambda: isinstance(app.screen, PlanScreen)
                         and bool(app.screen.query("#plan-menu")), what="the plan menu")
        rows = app.screen.query_one("#plan-list", OptionList)
        first = str(rows.get_option_at_index(0).prompt)
        assert "Map the shop's pages and forms" in first
        labels = " ".join(str(w.render()) for w in app.screen.query(".ai-label"))
        assert "phases drafted by OpenAI · gpt-4o-mini" in labels
