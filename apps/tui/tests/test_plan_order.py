"""Reordering the plan: only the gated checks move, and the run follows the new order."""

import pytest

from reconix import store
from reconix.store import plan_order

from .support import play_until_gate, run_to

NETWORK = "10.0.0.0/24"


@pytest.mark.parametrize("text", ["can we change the 3a and 3b to first 1", "move 3b before 3a",
                                  "swap step 3a and 3b", "change the order of steps"])
def test_a_reorder_request_is_spotted(text):
    assert store.wants_plan_reorder(text)


@pytest.mark.parametrize("text", ["what does step 2 do?", "run step 1", "give the plan"])
def test_other_lines_are_not_reorders(text):
    assert not store.wants_plan_reorder(text)


def test_the_gated_checks_swap_and_the_run_follows():
    run_to("plan", NETWORK)
    first, second = [a.request_id for a in store.get_assessment().approvals]
    store.reorder_gated([second, first])
    assert [a.request_id for a in store.get_assessment().approvals] == [second, first]
    rows = [r for r in store.plan_overview() if r.gate == "approve"]
    assert rows[0].label == store.get_approval(second).action
    store.run_plan()
    assert play_until_gate() == f"approval:{second}"       # the run meets it first now


def test_the_order_is_fixed_before_the_plan_and_once_it_runs():
    run_to("scope", NETWORK)
    assert "approve the scope" in plan_order.why_fixed()
    with pytest.raises(store.StoreValidationError):
        store.reorder_gated([])


def test_a_bad_order_is_refused():
    run_to("plan", NETWORK)
    first, _ = [a.request_id for a in store.get_assessment().approvals]
    with pytest.raises(store.StoreValidationError, match="each gated check once"):
        store.reorder_gated([first, first])


def test_once_the_plan_runs_nothing_moves():
    run_to("plan", NETWORK)
    store.run_plan()
    assert "already running" in plan_order.why_fixed()
    assert not store.answer_plan_reorder()
    assert store.movable_checks() == []
