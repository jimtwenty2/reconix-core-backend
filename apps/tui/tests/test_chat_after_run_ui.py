"""Chatting on after the run: a finished (or stopped) assessment keeps its conversation.

Every typed line after the run is a chat turn about that same assessment, answered by the
Core API's AI (the fake API in tests). A new assessment starts only with /new or /template.
"""

import pytest

from reconix import store
from reconix.store.snapshot import uid_for
from reconix.widgets import PromptBox

from .support import SIZE, run_ui_to, settle, type_request, wait_until


@pytest.fixture
def api_ok(model_active):
    """The active model is approved for the Core API, so chat lines go there."""
    store.core_api_approve()


def _uid() -> str:
    return uid_for(store.get_assessment())


def _chat(speaker: str):
    return [c.text for c in store.list_chat() if c.speaker == speaker and c.kind == "text"]


def _chats(fake_api) -> list:
    return [body["content"] for m, path, body, _ in fake_api.calls
            if m == "POST" and path.endswith("/chat")]


# --- after the run ---------------------------------------------------------------------------
async def test_line_after_finished_run_stays_on_the_same_assessment(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        assert store.is_completed()
        uid, cards = _uid(), len(store.list_assessments())
        findings = [f.fid for f in store.list_findings()]

        app.goto("start")
        await settle(pilot)
        await type_request(pilot, "thanks, what did you find?")
        await wait_until(pilot, lambda: fake_api.reply in _chat("reconix"), what="the reply")

        assert _uid() == uid
        assert len(store.list_assessments()) == cards
        assert [f.fid for f in store.list_findings()] == findings
        assert store.is_completed()
        assert "thanks, what did you find?" in _chat("you")
        assert _chats(fake_api)[-1].startswith("thanks, what did you find?")


async def test_a_target_after_the_run_is_chat_not_a_new_assessment(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        uid = _uid()
        app.goto("start")
        await settle(pilot)
        await type_request(pilot, "http://another.example")
        assert _uid() == uid
        assert "http://another.example" in _chat("you")


async def test_stopped_run_keeps_chatting(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope")
        store.stop_run()
        assert store.get_run().stopped
        uid, cards = _uid(), len(store.list_assessments())
        app.goto("start")
        await settle(pilot)
        await type_request(pilot, "hello")
        await wait_until(pilot, lambda: fake_api.reply in _chat("reconix"), what="the reply")
        assert _uid() == uid
        assert len(store.list_assessments()) == cards
        assert store.get_run().stopped


async def test_empty_line_after_the_run_opens_findings(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        assert store.list_findings()
        app.goto("start")
        await settle(pilot)
        await type_request(pilot, "")
        assert app.screen.flow_name == "findings"


async def test_empty_line_after_a_run_without_findings_opens_report(app, monkeypatch):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        monkeypatch.setattr(store, "list_findings", lambda *a, **k: [])
        app.goto("start")
        await settle(pilot)
        await type_request(pilot, "")
        assert app.screen.flow_name == "report"


async def test_new_still_starts_a_fresh_assessment(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        uid, cards = _uid(), len(store.list_assessments())
        app.run_command_line("/new")
        await settle(pilot)
        assert not store.get_run().started
        assert _uid() != uid
        assert len(store.list_assessments()) == cards + 1     # the finished one stays listed


# --- with the Core API's AI ---------------------------------------------------------------
async def test_each_line_after_the_run_goes_to_the_api(app, api_ok, fake_api):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        uid = _uid()
        app.goto("start")
        await settle(pilot)
        await type_request(pilot, "first question about the results")
        await wait_until(pilot, lambda: len(_chats(fake_api)) == 1, what="question 1 sent")
        await type_request(pilot, "and a second one")
        await wait_until(pilot, lambda: len(_chats(fake_api)) == 2, what="question 2 sent")
        await wait_until(pilot, lambda: _chat("reconix").count(fake_api.reply) == 2,
                         what="both replies")
        assert _uid() == uid
        first, second = _chats(fake_api)
        assert first.startswith("first question about the results")
        assert second.startswith("and a second one")
        assert "(Reconix app: step" in second                  # where the flow is


# --- the c key ------------------------------------------------------------------------------
async def test_c_on_findings_opens_chat(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        app.goto("findings")
        await settle(pilot)
        await pilot.press("c")
        await settle(pilot)
        assert app.screen.flow_name == "start"
        assert app.screen.query_one(PromptBox).input.value == ""


async def test_c_on_report_opens_chat(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        app.goto("report")
        await settle(pilot)
        await pilot.press("c")
        await settle(pilot)
        assert app.screen.flow_name == "start"


async def test_c_on_finding_detail_drafts_about_the_finding(app):
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, None)
        finding = store.list_findings()[0]
        app.open_finding(finding.fid)
        await settle(pilot)
        assert app.screen.flow_name == "detail"
        await pilot.press("c")
        await settle(pilot)
        assert app.screen.flow_name == "start"
        assert app.screen.query_one(PromptBox).input.value == (
            f"About {finding.fid} {finding.title}: ")
