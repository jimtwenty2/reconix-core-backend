"""The run plays its steps in order and never passes a gate without a recorded decision.

After the plan, the steps are the Core API's (the fake API in tests): LOW runs at once,
MEDIUM and HIGH wait at an approval gate named after the API's own approval.
"""

import pytest

from reconix import store
from reconix.core_api import run_api

from .support import (
    ASK_REQUEST,
    DEMO_REQUEST,
    decide,
    event_kinds,
    play_until_gate,
    run_to,
    run_to_end,
)


def _label(gate: str) -> str:
    """A gate as the tests compare it: approval gates by their risk (the API names them)."""
    if gate.startswith("approval:"):
        return "approval:" + store.get_approval(gate.split(":", 1)[1]).risk
    return gate


GATES = ["scope", "plan", "approval:MEDIUM", "approval:HIGH"]


def run_to_first_approval(request: str = DEMO_REQUEST) -> str:
    run_to("plan", request)
    decide("plan")
    gate = play_until_gate()
    assert gate.startswith("approval:")
    return gate


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


@pytest.mark.parametrize(
    "request_text, gates",
    [
        (DEMO_REQUEST, GATES),  # a URL: the template is matched
        (ASK_REQUEST, ["template"] + GATES),  # a bare hostname: the operator picks
    ],
)
def test_the_run_stops_at_every_gate_in_order(request_text, gates):
    store.start_run(request_text)
    seen = []
    while True:
        gate = play_until_gate()
        if gate is None:
            break
        seen.append(_label(gate))
        # Asking again without a decision stays at the same gate.
        assert store.advance().name == gate
        assert store.waiting_gate() == gate
        decide(gate)
    assert seen == gates
    assert store.is_completed()
    assert store.display_phase() == "completed"


@pytest.mark.parametrize(
    "gate, phase",
    [
        ("template", "planning"),
        ("scope", "scope_pending"),
    ],
)
def test_a_waiting_gate_shows_its_waiting_phase(gate, phase):
    run_to(gate, ASK_REQUEST)
    assert store.display_phase() == phase
    assert store.pipeline_stage() == "policy"


def test_an_approval_gate_shows_its_waiting_phase():
    run_to_first_approval()
    assert store.display_phase() == "awaiting_approval"
    assert store.pipeline_stage() == "policy"


def test_testing_does_not_start_before_the_scope_is_approved(fake_api):
    run_to("scope")
    assert store.counters()["requests"] == 0
    assert store.phase_progress()["discovery"] == 0
    assert store.elapsed() is None
    assert fake_api.tool_runs() == []


def test_a_step_the_api_blocks_never_runs(fake_api, monkeypatch):
    real = run_api.send_plan

    def blocked(agent_run_id, assessment_id):
        out = real(agent_run_id, assessment_id)
        out["action"] = {
            **out["action"],
            "action_status": "BLOCKED",
            "tool_runs": [],
            "approval_id": None,
            "guardrail_report": {
                "decision": "BLOCKED",
                "risk": "LOW",
                "blocked_by": "SCOPE",
                "reason": "TARGET_OUT_OF_SCOPE",
            },
        }
        return out

    monkeypatch.setattr(run_api, "send_plan", blocked)
    run_to("plan")
    decide("plan")
    play_until_gate()
    lines = [a.message for a in store.list_activity() if a.tone == "block"]
    assert "Blocked: TARGET_OUT_OF_SCOPE" in lines


def test_findings_are_revealed_as_the_run_finds_them():
    run_to_first_approval()  # the LOW nmap step ran
    assert [f.fid for f in store.list_findings()] == ["001"]
    run_to_end()
    assert sorted(f.fid for f in store.list_findings()) == ["001", "002"]
    assert store.findings_line() == "2 findings: 0 confirmed, 2 marked for review"


def test_a_full_run_counts_what_the_api_did(fake_api):
    run_to(None)
    counters = store.counters()
    assert counters["approvals"] == 2
    assert counters["findings"] == 2
    assert fake_api.tool_runs() == ["NMAP", "NUCLEI", "SQLMAP"]
    assert store.pipeline_stage() == ""


def test_rejecting_an_approval_skips_it_and_the_plan_goes_on(fake_api):
    gate = run_to_first_approval()
    approval_id = gate.split(":", 1)[1]
    store.reject(approval_id)
    nxt = play_until_gate()
    assert _label(nxt) == "approval:HIGH"  # the next action still asks
    assert "run.stopped" not in event_kinds()
    assert fake_api.approvals[approval_id]["approval_status"] == "REJECTED"
    assert "NUCLEI" not in fake_api.tool_runs()
    activity = [entry.message for entry in store.list_activity()]
    assert any("Skipped: you rejected this step" in line for line in activity)


def test_rejecting_every_approval_still_completes_the_run(fake_api):
    gate = run_to_first_approval()
    store.reject(gate.split(":", 1)[1])
    gate = play_until_gate()
    store.reject(gate.split(":", 1)[1])
    assert play_until_gate() is None
    assert store.is_completed() and not store.get_run().stopped
    assert fake_api.tool_runs() == ["NMAP"]
    kinds = event_kinds()
    assert kinds.count("approval.rejected") == 2  # one audit line per decision
    assert "run.completed" in kinds


def test_new_assessment_keeps_the_audit_trail():
    run_to("scope")
    store.new_assessment()
    assert not store.get_run().started
    assert store.list_events()[-1].kind == "assessment.new"
    assert "run.started" in event_kinds()
