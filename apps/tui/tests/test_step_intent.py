"""A decision typed in the step chat ("approve that scope", "yes"): spotted without a model,
and Reconix's own reply says where the flow is and that nothing changed."""

import pytest

from reconix import store

from .support import decide, play_until_gate, run_to

NETWORK = "10.0.0.0/24"


@pytest.mark.parametrize(
    "text", ["apporve that scope", "approve", "yes", "Ok", "go ahead", "run the plan",
             "reject", "proceed", "let's go", "confirm it"],
)
def test_a_decision_is_spotted(text):
    assert store.wants_decision(text)
    assert not store.asks_about_decision(text)


@pytest.mark.parametrize("text", ["should I approve?", "can you run it now?",
                                  "what will run first?"])
def test_a_question_about_the_decision_is_answered_first(text):
    assert store.asks_about_decision(text)
    assert not store.wants_decision(text)


@pytest.mark.parametrize(
    "text", ["what ports are open", "add port 3389", "looks fine", "why these tools?",
             "is this ok?", "hello", "remove nmap"],
)
def test_other_lines_go_to_the_model(text):
    assert not store.wants_decision(text)
    assert not store.asks_about_decision(text)


@pytest.mark.parametrize(
    "text, view",
    [("scope", "scope"), ("show the scope", "scope"), ("what is the scope?", "scope"),
     ("show me my scope manifest", "scope"), ("give the plan", "plan"),
     ("show me the test plan please", "plan"), ("plan the attack", ""),
     ("why these ports?", "")],
)
def test_asking_to_see_the_scope_or_the_plan_is_spotted(text, view):
    assert store.wants_view(text) == view


def test_at_the_scope_the_reply_says_nothing_is_approved():
    run_to("scope", NETWORK)
    status = store.step_status()
    assert status.pending and status.step == "Template · scope review"
    reply = store.decision_reply()
    assert reply.startswith("The scope is a draft: nothing is approved")
    assert "Only you decide this" in reply
    assert store.list_chat()[-1].text == reply           # recorded for the model's history
    assert not store.is_scope_approved()


def test_at_the_plan_the_reply_says_nothing_has_run():
    run_to("plan", NETWORK)
    status = store.step_status()
    assert status.pending and status.step == "Plan"
    assert "nothing has run" in store.decision_reply()
    assert not store.is_plan_started()


def test_at_an_approval_the_reply_names_the_action():
    run_to("plan")
    decide("plan")
    request = store.get_approval(play_until_gate().split(":", 1)[1])
    status = store.step_status()
    assert status.step == "Approval" and request.action in status.state
    assert store.decision_for(request.request_id) is None


def test_with_nothing_to_decide_the_reply_says_so():
    status = store.step_status()
    assert status.step == "Start" and not status.pending
    assert "Nothing waits for your decision here" in store.decision_reply()
