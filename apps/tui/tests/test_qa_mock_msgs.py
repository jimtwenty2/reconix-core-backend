"""Evaluator-run fixes: the mock's answers, scope-port lines, and plain messages.

RULE-02: a question about the decision is answered (not refused). RULE-04: "add 3389, 0,
99999, 8080" opens the tick list on a network scope. With the mock, a scope change or a
reorder gets only Reconix's own line. "what does step 2 do?" answers step 2. CMD-09: an
address nothing listens on is "connection refused". CMD-11: /assess explains agent mode
isn't in the static build. WEB-05: without Node.js, no "npm run dev" hint.
"""

import importlib.util

import pytest

from reconix import store, web_server
from reconix.llm import client, mock
from reconix.shell.agent import AGENT_NOT_HERE
from reconix.store.scope_ask import ONLY_YOU
from reconix.widgets import ChoiceMenu, StepChat, TickList

from .support import SIZE, run_to, run_ui_to, screen_text, settle, wait_until

NETWORK = "10.0.0.0/24"
STEP = "Now at Template: scope review. Next: Approve scope, Edit manifest, Reject."
PLAN = "1. Discover hosts; 2. Scan open ports (Nmap); 3a. Check TLS (MEDIUM, needs your approval)"


# --- RULE-02: a question about the decision ---------------------------------------------------
@pytest.mark.parametrize(
    "text",
    [
        "should I approve?",
        "About Template: should I approve?",
        "can I reject it?",
        "is it safe to run the plan?",
        "what should I do?",
        "should we go ahead?",
    ],
)
def test_a_question_about_the_decision_is_answered(text):
    assert mock.intent_of(text)[0] == "decision"
    answer = mock.reply(text, {"step": STEP})
    assert answer.startswith("That's your call") and STEP in answer
    assert "I can't do that" not in answer


@pytest.mark.parametrize(
    "text",
    ["approve that scope", "can you run it now?", "run step 1", "reject it", "add port 3389"],
)
def test_an_order_is_still_refused(text):
    assert mock.intent_of(text)[0] == "action"


# --- "what does step 2 do?" -------------------------------------------------------------------
def test_a_question_about_one_step_answers_that_step_only():
    answer = mock.reply("About Plan: what does step 2 do?", {"plan": PLAN, "step": STEP})
    assert answer.startswith("Step 2: Scan open ports (Nmap).")
    assert "Discover hosts" not in answer


def test_a_gated_step_and_a_missing_one():
    assert mock.reply("what is step 3A?", {"plan": PLAN}).startswith("Step 3a: Check TLS")
    assert "There is no step 9" in mock.reply("what does step 9 do?", {"plan": PLAN})
    assert "no plan yet" in mock.reply("what does step 2 do?", {})


# --- RULE-04: bare numbers after a change verb ------------------------------------------------
def test_bare_numbers_ask_for_a_port_change_on_a_network_scope():
    run_to("scope", f"Scan {NETWORK} for open ports")
    assert store.wants_scope_change("add 3389, 0, 99999, 8080")
    assert not store.wants_scope_change("change step 2 to first")
    assert not store.wants_scope_change("add 2 minutes")
    choices = store.answer_scope_change("add 3389, 0, 99999, 8080")
    ports = dict(choices.ports)
    assert ports[3389] is False and ports[8080] is True  # new unticked, allowed ticked
    assert 0 not in ports and 99999 not in ports
    assert 12 not in dict(store.answer_scope_change("add 12 ports").ports)  # a count
    assert store.get_scope().allowed_ports == [22, 80, 443, 8080, 8443]  # nothing applied


def test_bare_numbers_are_no_scope_change_on_a_web_scope():
    run_to("scope")
    assert not store.wants_scope_change("add 3389, 8080")


# --- the mock says nothing before Reconix's own line on a scope change ------------------------
def _menu(app) -> ChoiceMenu:
    return app.screen.query(ChoiceMenu).first()


def _chat_text(app) -> str:
    chats = app.screen.query(StepChat)
    return screen_text(chats.first()) if chats else ""


async def test_with_the_mock_a_scope_change_gets_only_reconix_line(app):
    store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        app.screen.post_message(ChoiceMenu.Typed(_menu(app), "add 3389, 0, 99999, 8080"))
        await wait_until(pilot, lambda: bool(app.screen.query(TickList)), what="the tick list")
        text = _chat_text(app)
        assert ONLY_YOU in text
        assert "I can't do that" not in text and "mock model" not in text
        assert not store.is_scope_approved()


async def test_with_the_mock_should_i_approve_is_answered_then_the_menu(app):
    store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await run_ui_to(app, pilot, "scope", request=NETWORK)
        app.screen.post_message(ChoiceMenu.Typed(_menu(app), "should I approve?"))
        await wait_until(pilot, lambda: "That's your call" in _chat_text(app), what="the answer")
        await wait_until(pilot, lambda: len(app.screen.query(ChoiceMenu)) > 0, what="menu")
        assert not store.is_scope_approved()


# --- CMD-09: nothing listens there ------------------------------------------------------------
def test_a_connection_error_is_connection_refused_not_http_500():
    class Refused(Exception):
        status_code = 500

    assert client._map_error(Refused("OpenAIException - Connection error.")) == "connection refused"

    class Failed(Exception):
        status_code = 503

    assert client._map_error(Failed("Service Unavailable")) == "the model server failed (HTTP 503)"


def test_a_provider_on_a_closed_port_is_unreachable_with_connection_refused():
    reachable, reason = client.ping(
        "openai_compatible", "m", api_key="sk-1234", api_base="http://127.0.0.1:9/v1"
    )
    assert not reachable and reason == "connection refused"


# --- CMD-11 and WEB-05 ------------------------------------------------------------------------
def _notes(app) -> str:
    return " ".join(str(n.message) for n in app._notifications)


@pytest.mark.skipif(
    importlib.util.find_spec("harness") is not None, reason="the harness is installed here"
)
@pytest.mark.parametrize("mock_on", [False, True])
async def test_assess_explains_agent_mode_is_not_in_the_static_build(app, mock_on):
    if mock_on:
        store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/assess https://shop.example.com")
        await settle(pilot)
        assert AGENT_NOT_HERE in _notes(app)
        assert "pip install" not in _notes(app)
        assert not store.get_run().started


async def test_without_node_web_says_what_to_install(app, web_launches, monkeypatch):
    monkeypatch.setattr(
        web_server, "problem", lambda: "The web dashboard needs Node.js (node and npm)."
    )
    async with app.run_test(size=SIZE) as pilot:
        app.run_command_line("/web")
        await settle(pilot)
        assert web_launches == []
        notes = _notes(app)
        assert "needs Node.js (node and npm)." in notes and "Install Node.js" in notes
        assert "npm run dev" not in notes
