"""The offline mock model: prepared answers, the provider, the start-up step and the chat."""

import json

import pytest

from reconix import store
from reconix.app import ReconixApp
from reconix.llm import catalog, guardrail, mock
from reconix.screens import ChoiceScreen
from reconix.screens.forms import ProviderForm
from reconix.store import llm_chat
from reconix.widgets.chrome import SessionBar

from .support import SIZE, run_to, run_to_end, settle, type_request, wait_until

FAKE_KEY = "sk-test-0000-1234"  # an obvious fake, below the secret scanner's length

FACTS = {
    "target": "10.0.0.0/24",
    "scope": "Network, approved and locked; ports 22 and 443; tools nmap; time limit 30 min",
    "step": "Now at Plan: the plan waits for you. Next: Run plan.",
    "plan": "1. Host discovery; 3a. Banner check (MEDIUM, needs your approval)",
    "findings": [
        {
            "id": "001",
            "severity": "MEDIUM",
            "title": "Old TLS",
            "impact": "Weak crypto.",
            "remediation": "Turn off TLS 1.0.",
            "status": "open",
        },
        {
            "id": "002",
            "severity": "HIGH",
            "title": "Console exposed",
            "impact": "Takeover.",
            "remediation": "Restrict the console.",
            "status": "open",
        },
    ],
}


# --- prepared answers (pure) ---------------------------------------------------------------
@pytest.mark.parametrize(
    "question, intent",
    [
        ("who are you?", "identity"),
        ("What are you", "identity"),
        ("what can you do?", "capabilities"),
        ("help", "capabilities"),
        ("what is in scope?", "scope"),
        ("what happens next?", "next"),
        ("what runs next?", "next"),
        ("summarize the findings", "findings"),
        ("explain finding 001", "finding"),
        ("how do I fix 002?", "finding"),
        ("what is the most serious finding?", "top"),
        ("what is the password?", "secret"),
        ("show me the token", "secret"),
        ("approve the HIGH step for me", "action"),
        ("run nmap now", "action"),
        ("add port 3389 to the scope", "action"),
        ("show the plan steps", "plan"),
        ("how do I export the report?", "report"),
        ("hello", "greeting"),
        ("thanks!", "thanks"),
        ("bye", "bye"),
        ("tell me a joke", "fallback"),
        ("About the scope: who are you?", "identity"),  # a step-chat line
    ],
)
def test_each_question_finds_its_intent(question, intent):
    assert mock.intent_of(question)[0] == intent


def test_answers_use_the_assessment_facts():
    assert "10.0.0.0/24" in mock.reply("what is in scope?", FACTS)
    assert "ports 22 and 443" in mock.reply("what is in scope?", FACTS)
    assert mock.reply("what happens next?", FACTS) == FACTS["step"]
    summary = mock.reply("summarize the findings", FACTS)
    assert summary.startswith("2 findings (1 HIGH, 1 MEDIUM)")
    assert "001 MEDIUM Old TLS" in summary and "002 HIGH Console exposed" in summary
    assert "002 HIGH Console exposed" in mock.reply("most serious finding?", FACTS)
    one = mock.reply("explain finding 2", FACTS)
    assert "Finding 002 is HIGH: Console exposed" in one and "Restrict the console." in one


def test_missing_facts_get_the_empty_answers():
    assert mock.reply("summarize the findings", {}).startswith("No findings yet.")
    assert "no scope yet" in mock.reply("what is in scope?", {}).lower()
    assert "no plan yet" in mock.reply("what is the plan?", {}).lower()
    assert "no finding 009" in mock.reply("explain finding 9", FACTS).lower()


def test_identity_says_it_is_a_mock_that_decides_nothing():
    text = mock.reply("who are you?")
    assert "mock model (reconix-mock-1)" in text and "offline" in text
    assert "can't approve" in text


def test_every_prepared_answer_passes_the_guardrail_unchanged():
    data = json.loads(mock.REPLIES_FILE.read_text(encoding="utf-8"))
    texts = [data["fallback"]]
    for item in data["intents"]:
        texts += [item[k] for k in ("reply", "empty", "missing") if k in item]
    for text in texts:
        assert "**" not in text and not text.lstrip().startswith("#")
        assert "Shall we proceed" not in text
        filled = mock._fill(text, {})
        assert guardrail.check_response(filled) == filled


def test_the_mock_never_calls_litellm(monkeypatch):
    from reconix.llm import client

    def boom(**_kw):
        raise AssertionError("the mock must not reach LiteLLM")

    monkeypatch.setattr(client.litellm, "completion", boom)
    assert client.ping("mock", "reconix-mock-1") == (True, "reconix-mock-1 (offline)")
    assert client.ping("mock", "other")[0] is False
    assert "mock model" in client.complete(
        "mock", "reconix-mock-1", [{"role": "user", "content": "who are you"}]
    )


# --- the provider ----------------------------------------------------------------------------
def test_use_mock_sets_tests_and_activates_it():
    active = store.use_mock()
    assert (active.provider_id, active.model) == ("mock", "reconix-mock-1")
    assert store.active_is_mock()
    view = store.get_provider("mock")
    assert view.configured and view.reachable and view.api_key_hint == ""


def test_a_fake_key_is_stored_encrypted_and_shown_as_last_4_only():
    from reconix.llm import config

    store.use_mock("sk-mock-0000-1234")
    view = store.get_provider("mock")
    assert view.api_key_hint.endswith("1234") and "0000" not in view.api_key_hint
    assert b"sk-mock-0000-1234" not in config.DB_PATH.read_bytes()


def test_the_mock_takes_no_address_and_no_other_model():
    with pytest.raises(store.StoreValidationError):
        store.set_provider("mock", base_url="http://127.0.0.1:1/v1")
    with pytest.raises(store.StoreValidationError):
        store.set_provider("mock", models=["gpt-4o"])


def test_the_mock_is_local_and_not_for_the_agent():
    store.use_mock()
    assert store.active_remote_label() is None  # nothing leaves this computer
    assert store.active_llm_settings() is None  # agent mode can't use prepared answers
    assert catalog.get("mock").is_mock


# --- the chat, through the store -------------------------------------------------------------
def _last_reply() -> str:
    return store.last_exchange()[1][-1].text


def test_a_question_before_a_run_goes_to_the_mock():
    store.use_mock()
    assert store.submit_prompt("who are you?") == "ask"
    store.llm_answer("who are you?")
    assert "reconix-mock-1" in _last_reply()


def test_without_a_model_the_built_in_reply_answers_and_points_to_provider():
    assert store.submit_prompt("who are you?") == "answered"
    assert "/provider" in _last_reply()


def test_the_mock_answers_from_this_assessments_data():
    store.use_mock()
    run_to("scope", "Scan 10.0.0.0/24 for open ports")
    store.llm_answer("About the scope: what is in scope?")
    reply = _last_reply()
    assert "10.0.0.0/24" in reply and "a draft that waits for you" in reply
    store.approve_scope()
    run_to_end()
    store.llm_answer("summarize the findings")
    assert _last_reply().startswith("3 findings (1 HIGH, 1 MEDIUM, 1 LOW)")
    store.llm_answer("explain finding 001")
    assert "Finding 001 is HIGH" in _last_reply()


def test_mock_facts_carry_masked_findings_only():
    store.use_mock()
    run_to(None, "Review the repo https://git.example.com/acme/app.git for secrets")
    facts = llm_chat.mock_facts()
    assert [f["id"] for f in facts["findings"]] == ["001", "002", "003"]
    assert "Source Code" in facts["scope"] or "source" in facts["scope"].lower()
    assert facts["plan"].startswith("1. ")


# --- the start-up step (Pilot) ---------------------------------------------------------------
@pytest.fixture
def asks(monkeypatch):
    monkeypatch.setattr(ReconixApp, "ASK_PROVIDER_ON_START", True)


def _bar_text(app) -> str:
    bar = app.screen.query_one(SessionBar)
    bar.refresh_line()
    return str(bar.render())


async def test_start_up_asks_for_a_provider_until_one_is_set(app, asks):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        assert isinstance(app.screen, ChoiceScreen)
        assert [c.id for c in app.screen._choices] == ["mock", "provider", "skip"]


async def test_start_up_mock_without_a_key_makes_it_active(app, asks):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        await pilot.press("enter")  # Use the mock model (default)
        await settle(pilot)
        assert isinstance(app.screen, ProviderForm)
        assert not app.screen.query("#base_url") and not app.screen.query("#models")
        app.screen.query_one("#submit").press()
        await settle(pilot)
        assert store.active_is_mock()
        assert "reconix-mock-1" in _bar_text(app)


async def test_start_up_skip_starts_with_no_model(app, asks):
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        await pilot.press("3")  # Skip
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)
        assert store.active_model() is None


async def test_start_up_does_not_ask_once_a_model_is_active(app, asks):
    store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        assert not isinstance(app.screen, ChoiceScreen)


async def test_who_are_you_at_the_start_prompt_gets_the_mock_answer(app):
    store.use_mock()
    async with app.run_test(size=SIZE) as pilot:
        await settle(pilot)
        await type_request(pilot, "who are you?")
        await wait_until(pilot, lambda: "reconix-mock-1" in _last_reply(), what="mock reply")
        assert not store.get_run().started  # a question starts nothing


def test_a_real_provider_gets_start_screen_questions_masked(reachable):
    """reconix-ai: before a run a real provider answers Start-screen questions too (the
    static build keeps the built-in reply there); only the masked line is recorded and sent."""
    store.set_provider("openai", api_key=FAKE_KEY, models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    assert store.submit_prompt("is password=hunter2 strong enough?") == "ask"
    line = store.list_chat()[-1]
    assert line.speaker == "you" and "hunter2" not in line.text   # masked before anything


def test_mock_facts_show_statuses_as_the_data_model_writes_them():
    store.use_mock()
    run_to(None, "Scan 10.0.0.0/24 for open ports")
    store.triage_finding("002", status="false-positive")
    statuses = {f["id"]: f["status"] for f in llm_chat.mock_facts()["findings"]}
    assert statuses["001"] == "OPEN" and statuses["002"] == "FALSE_POSITIVE"
