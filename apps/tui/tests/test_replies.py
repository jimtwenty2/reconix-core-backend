"""A prompt line that is not a target gets a short answer and starts nothing."""

import pytest

from reconix import store

from .support import run_to


def last_reply() -> str:
    return store.list_chat()[-1].text


@pytest.mark.parametrize("text, starts_with", [
    ("scan my network", "Network needs"),
    ("test my API please", "API needs"),
    ("review the sourcecode", "Source Code needs"),
    ("check my website", "Web URL needs"),
])
def test_a_kind_of_test_without_a_target_gets_the_hint_and_nothing_starts(text, starts_with):
    assert store.submit_prompt(text) == "answered"
    assert not store.get_run().started
    you, reply = store.list_chat()[-2:]
    assert (you.speaker, you.text) == ("you", text)
    assert reply.speaker == "reconix" and reply.text.startswith(starts_with)
    assert store.list_requests() == []          # an answer is not a request


@pytest.mark.parametrize("text", ["hi", "thanks", "what can you do?", "do the thing"])
def test_other_lines_go_to_the_core_apis_ai_and_nothing_starts(text):
    assert store.submit_prompt(text) == "ask"   # the app asks the API in a worker
    assert not store.get_run().started
    assert store.list_chat()[-1].speaker == "you"
    assert store.list_requests() == []


def test_a_target_starts_the_run():
    assert store.submit_prompt("scan 10.0.0.0/24") == "started"
    assert store.get_run().started
    assert store.selected_template().id == "network"


def test_a_malformed_target_is_refused_and_not_recorded():
    before = len(store.list_chat())
    with pytest.raises(store.StoreValidationError, match="isn't a valid IPv4 address"):
        store.submit_prompt("192.0.2.300")
    assert len(store.list_chat()) == before


def test_empty_and_overlong_lines_are_refused():
    for text in ("   ", "x" * 600):
        with pytest.raises(store.StoreValidationError):
            store.submit_prompt(text)


def test_during_a_run_a_line_goes_to_the_core_apis_ai(reachable, fake_api):
    store.set_provider("openai", api_key="sk-5678", models=["gpt-4o-mini"])
    store.test_provider("openai")
    store.activate("openai", "gpt-4o-mini")
    store.core_api_approve()
    run_to("scope")
    assert store.submit_prompt("run nmap on everything") == "answered"
    assert last_reply() == fake_api.reply
    assert store.waiting_gate() == "scope"      # a chat line changes nothing
