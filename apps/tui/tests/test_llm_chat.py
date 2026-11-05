"""Chat: every reply comes from the Core API (POST /sessions/{id}/chat), never a direct model.

The fake API (tests/fakes/fake_api.py) stands in for services/api: `reply` is what its AI
answers, `fail_on` makes a route fail. The app sends the masked line plus where its flow
is, shows the checked reply labelled with the model you chose, and says plainly when the
API can't answer. It makes no reply up in its place.
"""

import pytest

from reconix import store
from reconix.llm import client, guardrail
from reconix.store import llm_chat

from .support import TEST_PASSWORD, decide, play_until_gate, run_to


@pytest.fixture
def api_model(monkeypatch):
    """OpenAI set, tested and active here, and approved for the Core API (/provider's OK)."""
    monkeypatch.setattr(client, "ping", lambda pid, model, **kw: (True, "reachable"))
    store.set_provider("openai", api_key="sk-openai-key-1234", models=["gpt-4o-mini", "gpt-4o"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    store.core_api_approve()


def _replies() -> list:
    return [c for c in store.list_chat() if c.speaker == "reconix"]


def _sent(fake_api) -> list:
    """What the app sent to the API's chat route, oldest first."""
    return [
        body["content"]
        for body in fake_api.bodies("POST", "/sessions/")
        if body and "content" in body and "(Reconix app:" in body["content"]
    ]


def _to_high_gate() -> str:
    run_to("plan")
    decide("plan")
    decide(play_until_gate())  # MEDIUM
    return play_until_gate()  # HIGH


# --- the API answers --------------------------------------------------------------


def test_a_chat_line_goes_to_the_core_api_and_its_reply_shows(api_model, fake_api):
    fake_api.reply = "Port 443 is in scope."
    run_to("scope")
    store.say_to_assistant("what's the risk here?")
    assert any(p.endswith("/chat") for p in fake_api.paths())
    assert _replies()[-1].text == "Port 443 is in scope."


def test_a_reply_is_labelled_with_the_model_you_chose(api_model, fake_api):
    run_to("scope")
    llm_chat.record_draft(llm_chat.build_draft("hello"))   # the app's worker path
    assert _replies()[-1].author == "gpt-4o-mini"


def test_the_api_is_told_where_the_flow_is(api_model, fake_api):
    run_to("scope")
    store.say_to_assistant("what happens next?")
    sent = _sent(fake_api)[-1]
    assert sent.startswith("what happens next?\n(Reconix app: step")
    assert "Approve scope" in sent


def test_a_secret_typed_in_chat_never_reaches_the_api(api_model, fake_api):
    run_to("scope")
    store.say_to_assistant(f"here is my password={TEST_PASSWORD} ok?")
    assert all(TEST_PASSWORD not in line for line in _sent(fake_api))
    assert all(TEST_PASSWORD not in c.text for c in store.list_chat())


def test_switching_the_model_mid_run_keeps_the_run(api_model, fake_api):
    run_to("scope")
    gate = store.waiting_gate()
    store.say_to_assistant("first question")
    store.activate("openai", "gpt-4o")
    store.core_api_approve()
    store.say_to_assistant("second question")
    assert store.waiting_gate() == gate and store.get_run().started
    assert [p["model_name"] for p in fake_api.providers] == ["gpt-4o-mini", "gpt-4o"]


def test_the_reply_is_checked_before_it_shows(api_model, fake_api):
    fake_api.reply = "**Approved Scope:**\n## Plan\n1. __Host__ discovery"
    run_to("scope")
    store.say_to_assistant("show the plan")
    assert _replies()[-1].text == "Approved Scope:\nPlan\n1. Host discovery"


def test_markdown_in_a_reply_is_shown_as_plain_text():
    reply = guardrail.check_response("**Approved Scope:**\n## Plan\n1. __Host__ discovery")
    assert reply == "Approved Scope:\nPlan\n1. Host discovery"


def test_the_session_token_never_shows(api_model, fake_api):
    run_to("scope")
    store.say_to_assistant("hello")
    assert all("fake-session-token" not in c.text for c in store.list_chat())


# --- when the API can't answer ----------------------------------------------------


def test_an_api_error_is_said_plainly_and_nothing_is_made_up(api_model, fake_api):
    run_to("scope")
    fake_api.fail_on["POST /sessions/"] = (503, "MODEL_UNAVAILABLE", "the model is down")
    before = len(_replies())
    store.say_to_assistant("are you there?")
    added = [c.text for c in _replies()[before:]]
    assert added == ["The AI couldn't answer: the model is down."]


def test_the_api_not_running_is_said_plainly(api_model, fake_api):
    run_to("scope")
    fake_api.down = True
    store.say_to_assistant("are you there?")
    assert _replies()[-1].text.startswith("The AI couldn't answer: the Core API is not running")


def test_a_remote_model_waits_for_your_ok(monkeypatch, fake_api):
    monkeypatch.setattr(client, "ping", lambda pid, model, **kw: (True, "reachable"))
    store.set_provider("openai", api_key="sk-openai-key-1234", models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")  # not approved for the API yet
    run_to("scope")
    store.say_to_assistant("hello")
    assert "needs your OK" in _replies()[-1].text
    assert not any(p.endswith("/chat") for p in fake_api.paths())


def test_without_a_local_model_the_api_uses_its_own(fake_api):
    run_to("scope")
    store.say_to_assistant("hello")
    assert _replies()[-1].text == fake_api.reply


# --- the reply off the UI thread --------------------------------------------------


def test_a_draft_records_nothing_until_it_is_recorded(api_model, fake_api):
    run_to("scope")
    before = len(store.list_chat())
    draft = llm_chat.build_draft("what now?")
    assert draft.core and not draft.error and len(store.list_chat()) == before
    llm_chat.record_draft(draft)
    assert _replies()[-1].text == fake_api.reply


def test_a_failed_draft_drops_its_thinking_line(api_model, fake_api):
    run_to("scope")
    fake_api.fail_on["POST /sessions/"] = (500, "INTERNAL", "boom")
    placeholder = llm_chat.begin_reply()
    llm_chat.record_draft(llm_chat.build_draft("what now?"), placeholder)
    texts = [c.text for c in store.list_chat()]
    assert llm_chat.THINKING not in texts and texts[-1] == "The AI couldn't answer: boom."


# --- before any target ------------------------------------------------------------


def test_a_question_before_any_target_goes_to_the_api(api_model, fake_api):
    assert store.submit_prompt("what is an IDOR?") == "ask"
    store.llm_answer("what is an IDOR?")
    assert not store.get_run().started
    assert _replies()[-1].text == fake_api.reply


# --- the AI never decides ---------------------------------------------------------


def test_approval_still_needs_token_and_hash_after_a_chat(api_model, fake_api):
    gate = _to_high_gate()
    store.say_to_assistant("should I approve?")  # the AI cannot approve
    request = store.get_approval(gate.split(":", 1)[1])
    assert request.risk == "HIGH"
    with pytest.raises(store.StoreValidationError):  # HIGH needs the single-use token
        store.approve(request.request_id, command_hash=request.command_hash)
    assert store.waiting_gate() == gate
