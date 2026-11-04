"""The run plays its steps in order and never passes a gate without a recorded decision."""

import pytest

from reconix import store

from .support import ASK_REQUEST, decide, event_kinds, play_until_gate, run_to

GATES = ["scope", "plan", "account", "code", "approval:approval-001", "approval:approval-002"]


def test_nothing_plays_before_the_run_starts():
    assert store.advance() is None
    assert store.display_phase() == "planning"
    assert [c.text for c in store.list_chat()][0].startswith("Welcome to Reconix")


def test_start_validates_the_request_and_echoes_it():
    with pytest.raises(store.StoreValidationError):
        store.start_run("   ")
    store.start_run("  Assess   https://staging.example.com  ")
    you = store.list_chat()[-1]
    assert (you.speaker, you.text) == ("you", "Assess https://staging.example.com")
    with pytest.raises(store.StoreValidationError):
        store.start_run("again")


@pytest.mark.parametrize("request_text, gates", [
    (store.DEMO_REQUEST, GATES),                  # a URL: the template is matched
    (ASK_REQUEST, ["template"] + GATES),          # a bare hostname: the operator picks
])
def test_the_run_stops_at_every_gate_in_order(request_text, gates):
    store.start_run(request_text)
    seen = []
    while True:
        gate = play_until_gate()
        if gate is None:
            break
        seen.append(gate)
        # Asking again without a decision stays at the same gate.
        assert store.advance().name == gate
        assert store.waiting_gate() == gate
        decide(gate)
    assert seen == gates
    assert store.is_completed()
    assert store.display_phase() == "completed"


@pytest.mark.parametrize("gate, phase", [
    ("template", "planning"),
    ("scope", "scope_pending"),
    ("account", "waiting_account"),
    ("approval:approval-001", "awaiting_approval"),
])
def test_a_waiting_gate_shows_its_waiting_phase(gate, phase):
    run_to(gate, ASK_REQUEST)
    assert store.display_phase() == phase
    assert store.pipeline_stage() == "policy"


def test_testing_does_not_start_before_the_scope_is_approved():
    run_to("scope")
    assert store.counters()["requests"] == 0
    assert store.phase_progress()["discovery"] == 0
    assert store.elapsed() is None


def test_out_of_scope_request_is_blocked_by_policy():
    run_to("account")
    assert store.counters()["blocked"] == 1
    blocked = [a for a in store.list_activity() if a.tone == "block"]
    assert [a.message for a in blocked] == ["Blocked: Path outside approved scope"]
    assert any(c.kind == "banner" and "GET /admin" in c.text for c in store.list_chat())
    assert "policy.blocked" in event_kinds()


def test_findings_are_revealed_as_the_run_finds_them():
    run_to("approval:approval-001")
    assert [f.fid for f in store.list_findings()] == ["001"]
    run_to_end_from_here()
    assert [f.fid for f in store.list_findings()] == ["001", "002", "003"]
    assert store.findings_line() == "3 findings: 1 confirmed, 2 marked for review"


def run_to_end_from_here():
    gate = store.waiting_gate()
    while gate:
        decide(gate)
        gate = play_until_gate()


def test_a_full_run_matches_the_design_counts():
    run_to(None)
    counters = store.counters()
    assert counters["blocked"] == 1
    assert counters["approvals"] == 2
    assert counters["findings"] == 3
    assert counters["requests"] > 1000
    assert all(v == 100 for k, v in store.phase_progress().items() if k != "report")
    assert store.pipeline_stage() == ""


def test_rejecting_an_approval_skips_it_and_the_plan_goes_on():
    run_to("approval:approval-001")
    store.reject("approval-001")
    assert play_until_gate() == "approval:approval-002"     # the next action still asks
    assert "run.stopped" not in event_kinds()
    chat = [entry.text for entry in store.get_assessment().chat]
    assert any("Rejected: Baseline request (read-only). Not executed" in t for t in chat)
    assert not any("MEDIUM action approved" in t for t in chat)   # its own steps dropped
    activity = [entry.message for entry in store.list_activity()]
    assert "Executing baseline request" not in activity
    assert store.get_finding("001").validation == "UNCONFIRMED"   # nothing confirmed it


def test_rejecting_every_approval_still_completes_the_run():
    run_to("approval:approval-001")
    store.reject("approval-001")
    assert play_until_gate() == "approval:approval-002"
    store.reject("approval-002")
    assert play_until_gate() is None
    assert store.is_completed() and not store.get_run().stopped
    assert store.step_states()["approval"] == "done"
    kinds = event_kinds()
    assert kinds.count("approval.rejected") == 2           # one audit line per decision
    assert "run.completed" in kinds


def test_new_assessment_keeps_the_audit_trail():
    run_to("scope")
    store.new_assessment()
    assert not store.get_run().started
    assert store.list_events()[-1].kind == "assessment.new"
    assert "run.started" in event_kinds()
