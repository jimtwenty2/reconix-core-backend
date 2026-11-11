"""Asking in the step chat to change the scope: keyword check, typed ports, the tick rows."""

import pytest

from reconix import store
from reconix.store import scope_ask

from .support import run_to

NETWORK = "10.0.0.0/24"


@pytest.mark.parametrize(
    "text",
    [
        "add port 7070",
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
    assert scope_ask.typed_ports("add 7070, 0, 99999, 8080 and 7070") == [7070, 8080]


def test_the_rows_start_with_exactly_the_scope():
    run_to("scope", NETWORK)
    scope = store.get_scope()
    choices = scope_ask.scope_choices("add port 7070")
    ticked_ports = [port for port, ticked in choices.ports if ticked]
    assert ticked_ports == sorted(scope.allowed_ports)
    assert (7070, False) in choices.ports  # typed: offered, never ticked
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


def test_the_reply_is_recorded_and_changeable_until_the_plan_runs():
    run_to("scope", NETWORK)
    assert store.answer_scope_change("add port 7070") is not None
    assert store.list_chat()[-1].text == scope_ask.ONLY_YOU
    store.approve_scope()
    # at the Plan step the scope can still change (a tick re-opens it for a fresh approval)
    assert store.answer_scope_change("add port 7070") is not None
    # once the plan runs it is locked
    store.get_run().plan_started = True
    assert store.answer_scope_change("add port 7070") is None
    assert store.list_chat()[-1].text == scope_ask.LOCKED


def test_a_count_or_an_address_is_not_a_port():
    from reconix.store.scope_ask import typed_ports

    line = "i need to add more port to 4000 also and i need 12 port to scan please"
    assert typed_ports(line) == [4000]
    assert typed_ports("scan 1.1.1.0/24 on 8080") == [8080]
    assert typed_ports("add 12 more ports and 9000") == [9000]


def test_the_model_s_named_ports_become_suggestions():
    from reconix.store.scope_ask import suggested_ports

    reply = ("To scan 12 ports, add port 4000 and 21 (FTP), 23 (Telnet), 53 (DNS). Step 1 "
             "runs nmap on 1.1.1.0/24; TLS 1.2 on 5432/tcp.")
    assert suggested_ports(reply) == [4000, 21, 23, 53, 5432]


def test_suggested_ports_are_offered_unticked():
    run_to("scope", NETWORK)
    allowed = list(store.get_scope().allowed_ports)
    choices = scope_ask.scope_choices("add more ports", "Try ports 7071 and 7072.")
    assert choices.suggested == (7071, 7072)
    ticked = {port for port, on in choices.ports if on}
    assert ticked == set(allowed)                          # nothing new ticked for you
    assert store.get_scope().allowed_ports == allowed


def test_a_list_in_a_sentence_about_ports_is_suggested():
    """Qwen3.6's real reply: the list after "I recommend adding" has no "port" before it."""
    from reconix.store.scope_ask import suggested_ports

    reply = ("The current draft scope lists ports 22, 80, 443, 8080, and 8443. Adding port 4000 "
             "and seven additional common service ports will give you a focused set of 12. I "
             "recommend adding 4000, 3000, 5432, 3306, 6379, 8000, and 9090.")
    assert suggested_ports(reply)[-7:] == [4000, 3000, 5432, 3306, 6379, 8000, 9090]
    assert 12 not in suggested_ports(reply)
    assert suggested_ports("Ports matter. Steps 1 and 2 run first. Use 10, 20 hosts.") == []
