"""Flexible LLM: chat replies, mid-task model switching, history and guardrails."""

import pytest

from reconix import store
from reconix.llm import LLMError, client, db, guardrail
from reconix.store.snapshot import uid_for
from reconix.store.transcript import add_chat

from .support import TEST_PASSWORD, run_to


@pytest.fixture
def two_models(monkeypatch):
    """Ollama and OpenAI both configured and REACHABLE; records every completion call."""
    monkeypatch.setattr(client, "ping", lambda pid, model, **kw: (True, "reachable"))
    store.set_provider("ollama", models=["llama3.1"])
    store.set_provider("openai", api_key="sk-openai-key-1234", models=["gpt-4o-mini", "gpt-4o"])
    store.test_provider("ollama")
    store.test_provider("openai")

    calls = []

    def complete(pid, model, messages, **kw):
        calls.append({"provider": pid, "model": model, "messages": messages})
        return f"reply from {pid}/{model}"

    monkeypatch.setattr(client, "complete", complete)
    return calls


def _last_reply() -> str:
    return [c for c in store.list_chat() if c.speaker == "reconix"][-1].text


# --- a model answers --------------------------------------------------------------

def test_chat_line_uses_active_model(two_models):
    run_to("scope")
    store.activate("ollama", "llama3.1")
    store.say_to_assistant("what's the risk here?")
    assert two_models[-1]["provider"] == "ollama"
    assert _last_reply() == "reply from ollama/llama3.1"


def test_switch_model_between_lines(two_models):
    run_to("scope")
    store.activate("ollama", "llama3.1")
    store.say_to_assistant("first question")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("second question")
    assert two_models[-1]["provider"] == "openai"
    assert two_models[-1]["model"] == "gpt-4o-mini"


def test_switch_provider_mid_task_preserves_run(two_models):
    run_to("scope")                                    # a gate is waiting
    gate_before = store.waiting_gate()
    findings_before = [f.fid for f in store.list_findings()]
    decisions_before = len(store.list_approval_decisions())

    store.activate("ollama", "llama3.1")
    store.say_to_assistant("talk to me on ollama")
    store.activate("openai", "gpt-4o-mini")            # switch while the gate waits
    store.say_to_assistant("now on openai")

    assert store.waiting_gate() == gate_before
    assert [f.fid for f in store.list_findings()] == findings_before
    assert len(store.list_approval_decisions()) == decisions_before
    assert store.get_run().started


def test_history_carries_across_the_switch(two_models):
    run_to("scope")
    store.activate("ollama", "llama3.1")
    store.say_to_assistant("remember apples")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("what did I say?")
    sent = " ".join(m["content"] for m in two_models[-1]["messages"])
    assert "remember apples" in sent                   # operator line to the old model
    assert "reply from ollama/llama3.1" in sent        # the old model's reply


def test_context_lists_findings_and_decisions(two_models):
    run_to(None)                                       # run to the end: findings exist
    store.activate("openai", "gpt-4o-mini")
    store.say_operator_line("summarize")
    store.llm_answer("summarize")
    context = two_models[-1]["messages"][0]["content"]
    assert store.list_findings()[0].fid in context
    assert "findings" in context


def test_history_saved_to_db(two_models):
    run_to("scope")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("log this")
    rows = db.list_chat_messages(uid_for(store.get_assessment()))
    roles = [(r["role"], r["provider_id"], r["model"]) for r in rows]
    assert ("user", None, None) in roles
    assert ("assistant", "openai", "gpt-4o-mini") in roles


# --- guardrails stay identical and strict -----------------------------------------

def test_system_prompt_identical_across_models(two_models):
    run_to("scope")
    store.activate("ollama", "llama3.1")
    store.say_to_assistant("a")
    system_a = two_models[-1]["messages"][0]["content"]
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("b")
    system_b = two_models[-1]["messages"][0]["content"]
    assert system_a.startswith(guardrail.SYSTEM_PROMPT)
    assert system_b.startswith(guardrail.SYSTEM_PROMPT)


def test_secret_typed_in_chat_is_redacted(two_models):
    run_to("scope")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant(f"here is my password={TEST_PASSWORD} ok?")
    sent = " ".join(m["content"] for m in two_models[-1]["messages"])
    assert TEST_PASSWORD not in sent                   # masked before it reaches the model


def test_approval_still_needs_token_and_hash_after_switch(two_models):
    run_to("approval:approval-002")                    # the HIGH-risk gate
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("should I approve?")        # the model cannot approve
    request = store.get_approval("approval-002")
    with pytest.raises(store.StoreValidationError):    # HIGH needs the single-use token
        store.approve(request.request_id, command_hash=request.command_hash)


# --- fallback keeps the demo working ----------------------------------------------

def test_no_active_model_uses_builtin_reply():
    run_to("scope")
    store.say_to_assistant("hello there")
    assert _last_reply()                               # a built-in reply was produced


def test_llm_error_falls_back_with_a_note(two_models, monkeypatch):
    from reconix.llm import LLMError

    def boom(*a, **k):
        raise LLMError("timed out")

    monkeypatch.setattr(client, "complete", boom)
    run_to("scope")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("are you there?")
    replies = [c.text for c in store.list_chat() if c.speaker == "reconix"]
    assert any("LLM unavailable" in r for r in replies)


# --- before any target -------------------------------------------------------------

def test_a_question_before_any_target_goes_to_the_active_model(two_models):
    store.activate("openai", "gpt-4o-mini")
    assert store.submit_prompt("what is an IDOR?") == "ask"
    store.llm_answer("what is an IDOR?")
    assert not store.get_run().started
    assert _last_reply() == "reply from openai/gpt-4o-mini"


def test_without_a_model_a_question_before_any_target_gets_the_builtin_reply():
    assert store.submit_prompt("what is an IDOR?") == "answered"
    assert _last_reply()


def test_picking_a_model_without_the_harness_does_not_crash(two_models):
    from reconix.store import agent_run

    store.activate("openai", "gpt-4o-mini")
    assert agent_run.switch_model() is False        # no agent: nothing to switch


def test_the_history_sent_to_a_model_starts_with_a_user_turn(two_models):
    add_chat("text", "reconix", "Welcome to Reconix.")     # the opening line
    store.activate("openai", "gpt-4o-mini")
    store.submit_prompt("hi")
    store.llm_answer("hi")
    store.submit_prompt("who are you")
    store.llm_answer("who are you")
    roles = [m["role"] for m in two_models[-1]["messages"]]
    assert roles[:2] == ["system", "user"]
    assert roles[-1] == "user"


# --- a streamed reply ---------------------------------------------------------------

def _stream_words(monkeypatch, words, fail_after=None):
    """`client.stream` fed `words` one by one; records the chat line the screen would show."""
    shown = []

    def fake_stream(pid, model, messages, on_text, **kw):
        text = ""
        for i, word in enumerate(words):
            if fail_after is not None and i == fail_after:
                raise LLMError("timed out")
            text += word
            on_text(text)
            shown.append(_last_reply())
        return text

    monkeypatch.setattr(client, "stream", fake_stream)
    monkeypatch.setattr("reconix.store.llm_chat.STREAM_REDRAW", 0)
    return shown


def test_a_streamed_reply_grows_in_one_line(two_models, monkeypatch):
    shown = _stream_words(monkeypatch, ["Reconix ", "tests ", "web ", "apps."])
    store.activate("openai", "gpt-4o-mini")
    redraws = []
    store.submit_prompt("what do you do?")
    store.llm_answer("what do you do?", on_update=lambda: redraws.append(1))
    assert shown[:3] == ["Reconix", "Reconix tests", "Reconix tests web"]
    assert _last_reply() == "Reconix tests web apps."
    texts = [c.text for c in store.list_chat()]
    assert texts.count("Reconix tests web apps.") == 1 and "thinking…" not in texts
    assert redraws
    saved = db.list_chat_messages(uid_for(store.get_assessment()))
    assert saved[-1]["content"] == "Reconix tests web apps."


def test_a_secret_in_a_streamed_reply_never_shows(two_models, monkeypatch):
    secret = f"password={TEST_PASSWORD}"
    shown = _stream_words(monkeypatch, ["Use ", secret[:9], secret[9:], " here."])
    store.activate("openai", "gpt-4o-mini")
    store.submit_prompt("hint?")
    store.llm_answer("hint?", on_update=lambda: None)
    assert all(TEST_PASSWORD[:4] not in line for line in shown + [_last_reply()])


def test_a_stream_that_fails_leaves_the_builtin_reply(two_models, monkeypatch):
    _stream_words(monkeypatch, ["Half ", "a ", "reply"], fail_after=2)
    store.activate("openai", "gpt-4o-mini")
    store.submit_prompt("hi")
    store.llm_answer("hi", on_update=lambda: None)
    replies = [c.text for c in store.list_chat() if c.speaker == "reconix"]
    assert not any(r.startswith("Half") for r in replies)
    assert any("LLM unavailable (timed out)" in r for r in replies)


def test_the_client_streams_reply_text_and_skips_reasoning(monkeypatch):
    from types import SimpleNamespace as NS

    monkeypatch.undo()            # the real client.stream, not conftest's stand-in

    def chunk(content):
        return NS(choices=[NS(delta=NS(content=content, reasoning_content="hmm"))])

    monkeypatch.setattr(client.litellm, "completion",
                        lambda **kw: iter([chunk(None), chunk("Hel"), chunk("lo")]))
    seen = []
    assert client.stream("openai", "gpt-4o-mini", [], seen.append) == "Hello"
    assert seen == ["", "Hel", "Hello"]
    monkeypatch.setattr(client.litellm, "completion", lambda **kw: iter([chunk(None)]))
    with pytest.raises(LLMError, match="empty"):
        client.stream("openai", "gpt-4o-mini", [], seen.append)


# --- what the model remembers --------------------------------------------------------

def test_the_run_s_scripted_lines_never_crowd_out_your_questions(two_models):
    run_to("scope")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("remember the codeword: PELICAN")
    for i in range(60):                                   # a long run says a lot
        add_chat("text", "reconix", f"scripted line {i}")
    store.say_to_assistant("what was the codeword?")
    sent = two_models[-1]["messages"]
    turns = [m["content"] for m in sent if m["role"] in ("user", "assistant")]
    assert "remember the codeword: PELICAN" in turns
    assert not any(t.startswith("scripted line") for t in turns)


def test_the_model_sees_the_scope_and_the_plan(two_models):
    run_to("scope")
    store.activate("openai", "gpt-4o-mini")
    store.say_to_assistant("which ports may you test?")
    context = two_models[-1]["messages"][0]["content"]
    scope = store.get_scope()
    assert f"tools: {', '.join(scope.tools)}" in context
    assert f"time limit: {scope.time_limit_minutes} min" in context
    first = store.plan_overview()[0]
    assert f"{first.num} {first.label}" in context
    assert store.list_requests()[0].text in context
