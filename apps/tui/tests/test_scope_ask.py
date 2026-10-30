"""Asking in the step chat to change the scope: keyword check, typed ports, the tick rows."""

import pytest

from reconix import store
from reconix.store import scope_ask

from .support import run_to

NETWORK = "10.0.0.0/24"


@pytest.mark.parametrize(
    "text",
    [
        "add port 3389",
        "Remove the tool nmap",
        "can you allow ports 8000",
        "change the scope please",
    ],
)
def test_a_scope_change_is_spotted(text):
    assert store.wants_scope_change(text)


@pytest.mark.parametrize(
    "text", ["what is port 22?", "why these tools?", "add more detail", "looks fine"]
)
def test_other_lines_are_questions(text):
    assert not store.wants_scope_change(text)


def test_typed_ports_keep_valid_numbers_once():
    assert scope_ask.typed_ports("add 3389, 0, 99999, 8080 and 3389") == [3389, 8080]


def test_the_rows_start_with_exactly_the_scope():
    run_to("scope", NETWORK)
    scope = store.get_scope()
    choices = scope_ask.scope_choices("add port 3389")
    ticked_ports = [port for port, ticked in choices.ports if ticked]
    assert ticked_ports == sorted(scope.allowed_ports)
    assert (3389, False) in choices.ports  # typed: offered, never ticked
    assert [tool for tool, ticked in choices.tools if ticked] == scope.tools


def test_a_removed_tool_is_offered_again_unticked():
    run_to("scope", NETWORK)
    store.edit_scope(tools=["nmap"])
    assert ("testssl.sh", False) in scope_ask.scope_choices("add a tool").tools


def test_a_scope_without_ports_offers_only_tools():
    run_to("scope")  # the demo: a web target
    choices = scope_ask.scope_choices("add port 8080")
    assert choices.ports == []
    assert choices.tools


def test_the_reply_is_recorded_and_locks_after_approval():
    run_to("scope", NETWORK)
    assert store.answer_scope_change("add port 3389") is not None
    assert store.list_chat()[-1].text == scope_ask.ONLY_YOU
    store.approve_scope()
    assert store.answer_scope_change("add port 3389") is None
    assert store.list_chat()[-1].text == scope_ask.LOCKED
