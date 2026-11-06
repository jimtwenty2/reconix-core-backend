"""The run on the Core API: scope, plan, steps, approvals and findings all come from it.

The fake API (tests/fakes/fake_api.py) answers like services/api: LOW runs at once,
MEDIUM and HIGH wait for a person, HIGH needs the typed target, and the findings are the
ones its "Kali" output gives. Nothing here is made up by the app.
"""

import pytest

from reconix import store
from reconix.core_api import client

from .fakes.fake_api import finding_row
from .support import decide, draft_plan, play_until_gate, run_to, run_to_end
from .support import DEMO_REQUEST


def test_the_scope_is_approved_on_the_core_api(fake_api):
    run_to("plan")
    assert store.get_assessment().live.assessment_id in fake_api.assessments
    assert any(p.endswith("/submit") for p in fake_api.paths())
    assert fake_api.assessments[store.get_assessment().live.assessment_id]["status"] == "ACTIVE"


def test_a_scope_the_api_refuses_stays_a_draft(fake_api):
    fake_api.fail_on["POST /scope-manifests/"] = (422, "VALIDATION_ERROR", "unknown tool")
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    with pytest.raises(store.StoreValidationError, match="did not approve the scope"):
        store.approve_scope()
    assert store.get_scope().status == "DRAFT"
    assert not store.get_assessment().live.assessment_id


def test_the_api_not_running_is_said_plainly(fake_api):
    fake_api.down = True
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    with pytest.raises(store.StoreValidationError, match="Core API is not running"):
        store.approve_scope()


def test_the_plan_is_the_apis_draft_and_nothing_runs_before_run_plan(fake_api):
    run_to("plan")
    live = store.get_assessment().live
    assert live.agent_run_id and len(live.plan_steps) == 3
    assert store.plan_author() == "fake-model"
    assert fake_api.tool_runs() == []  # nothing ran yet
    assert not any(p.endswith("/send") for p in fake_api.paths())


def test_run_plan_needs_the_apis_draft(fake_api):
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    store.approve_scope()  # no draft fetched
    assert play_until_gate() == "plan"
    with pytest.raises(store.StoreValidationError, match="no plan from the AI"):
        store.run_plan()


def test_a_failed_draft_says_why(fake_api):
    fake_api.fail_on["POST /assessments/"] = (503, "MODEL_UNAVAILABLE", "the model is down")
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    store.approve_scope()
    draft_plan()
    assert "the model is down" in store.get_assessment().chat[-1].text
    assert not store.plan_drafting()


def test_a_low_step_runs_at_once_and_its_findings_show(fake_api):
    run_to("plan")
    decide("plan")
    gate = play_until_gate()  # LOW nmap ran, MEDIUM waits
    assert fake_api.tool_runs() == ["NMAP"]
    assert gate.startswith("approval:")
    titles = [f.title for f in store.list_findings()]
    assert titles == ["Open port 3000/tcp (http)"]
    log = " ".join(e.message for e in store.get_assessment().activity)
    assert "nmap on https://staging.example.com/: completed" in log


def test_medium_waits_for_you_then_runs(fake_api):
    run_to("plan")
    decide("plan")
    gate = play_until_gate()
    request = store.get_approval(gate.split(":", 1)[1])
    assert request.risk == "MEDIUM" and request.api_approval_id
    assert "NUCLEI" not in fake_api.tool_runs()
    decide(gate)
    play_until_gate()
    assert "NUCLEI" in fake_api.tool_runs()


def test_high_needs_the_typed_target(fake_api):
    run_to("plan")
    decide("plan")
    decide(play_until_gate())  # MEDIUM
    gate = play_until_gate()  # HIGH
    request = store.get_approval(gate.split(":", 1)[1])
    assert request.risk == "HIGH"
    token = store.request_confirmation(request.request_id, request.command_hash)
    with pytest.raises(store.StoreValidationError, match="Type the target"):
        store.approve(
            request.request_id, command_hash=request.command_hash, confirmation_token=token
        )


def test_a_wrong_typed_target_is_refused_and_the_gate_asks_again(fake_api):
    run_to("plan")
    decide("plan")
    decide(play_until_gate())
    gate = play_until_gate()
    request = store.get_approval(gate.split(":", 1)[1])
    token = store.request_confirmation(request.request_id, request.command_hash)
    store.approve(
        request.request_id,
        command_hash=request.command_hash,
        confirmation_token=token,
        typed_target="https://other.example.com/",
    )
    assert play_until_gate() == gate  # asked again
    assert "SQLMAP" not in fake_api.tool_runs()
    banners = [e.text for e in store.get_assessment().chat if e.kind == "banner"]
    assert any("Type the exact target" in text for text in banners)
    decide(gate)
    run_to_end()
    assert "SQLMAP" in fake_api.tool_runs()


def test_a_rejected_step_never_runs(fake_api):
    run_to("plan")
    decide("plan")
    gate = play_until_gate()
    store.reject(gate.split(":", 1)[1])
    play_until_gate()
    assert "NUCLEI" not in fake_api.tool_runs()
    assert fake_api.approvals[gate.split(":", 1)[1]]["approval_status"] == "REJECTED"


def test_the_whole_run_ends_with_each_finding_analyzed(fake_api):
    run_to(None)
    assert store.is_completed()
    assert fake_api.tool_runs() == ["NMAP", "NUCLEI", "SQLMAP"]
    shown = store.list_findings()
    assert sorted(f.severity for f in shown) == ["LOW", "MEDIUM"]
    # each finding was analyzed as its step found it (per step, not one end-of-run batch)
    assert all(f.impact for f in shown)


def test_each_step_is_analyzed_as_it_is_found_with_reasoning_shown(fake_api):
    run_to(None)
    analyze_calls = [b for (m, p, b, _) in fake_api.calls if m == "POST" and p.endswith("/analyze")]
    # per-step analysis: each call targets the step's own findings (a batch would send no body)
    assert analyze_calls
    assert all(b and b.get("finding_ids") for b in analyze_calls)
    assert all(f.impact for f in store.list_findings())  # each finding got its analysis
    # the AI's per-step reasoning is shown in the run log
    texts = " ".join(getattr(s, "text", "") or "" for s in store.get_assessment().script)
    assert "Next." in texts


def test_the_analysis_fills_each_finding_with_plain_language(fake_api):
    # Fix #4: the ANALYZE step persists the analysis onto findings, and the app refreshes
    # the ones it already showed, so the detail view reads in plain language, not raw JSON.
    run_to(None)

    shown = store.list_findings()
    assert shown  # the run found something to analyze
    for finding in shown:
        assert finding.description.startswith("In plain terms:")
        assert "abuse" in finding.impact
        assert finding.remediation


def test_a_none_finding_is_shown_not_dropped(fake_api):
    fake_api.findings_for["NMAP"] = [
        finding_row("NMAP-OPEN", "Open port 22/tcp (ssh)", "{target}:22", "NONE", "NMAP")
    ]
    run_to(None)
    assert [f.severity for f in store.list_findings()][-1] == "NONE"


def test_a_failed_call_stops_the_run_until_you_retry(fake_api):
    run_to("plan")
    decide("plan")
    gate = play_until_gate()                                # MEDIUM waits
    fake_api.fail_on["POST /assessments/"] = (500, "INTERNAL", "the agent crashed")
    decide(gate)
    assert play_until_gate() is None                        # next-step failed
    assert "the agent crashed" in store.live_failed()
    assert not store.is_finished()
    assert play_until_gate() is None                        # no retry on its own
    del fake_api.fail_on["POST /assessments/"]
    assert store.retry_live()
    run_to_end()
    assert store.is_completed()


def test_the_token_never_shows_in_the_app(fake_api):
    run_to(None)
    assessment = store.get_assessment()
    shown = " ".join([e.text for e in assessment.chat] + [e.message for e in assessment.activity])
    assert "fake-session-token" not in shown


def test_the_api_address_must_be_this_computer(fake_api, monkeypatch):
    monkeypatch.setenv(client.ENV_URL, "http://10.0.0.5:8000")
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    with pytest.raises(store.StoreValidationError, match="must be this computer"):
        store.approve_scope()


def test_a_lab_host_name_works_once_you_pick_the_template(fake_api):
    store.start_run("juice-shop port 3000", "network")
    assert store.get_assessment().target == "juice-shop"
    assert store.get_assessment().requested_ports == [3000]


def test_free_text_never_takes_a_lone_word_as_a_target():
    assert store.submit_prompt("juice-shop") != "started"


def test_a_saved_model_whose_provider_is_gone_counts_as_none(monkeypatch):
    from reconix.llm import db

    monkeypatch.setattr(db, "get_active", lambda: {"provider_id": "mock",
                                                   "model": "reconix-mock-1",
                                                   "activated_at": ""})
    assert store.active_model() is None


def test_chat_with_no_model_of_your_own_uses_the_apis(fake_api):
    fake_api.reply = "The API's own model answered."
    store.llm_answer("what is open on the target?")
    assert store.get_assessment().chat[-1].text == "The API's own model answered."
    assert not fake_api.bodies("POST", "/llm-providers")


def test_a_run_that_finds_nothing_completes_cleanly(fake_api):
    fake_api.findings_for = {}          # Kali's tools find nothing this run
    run_to(None)
    assert store.is_completed()
    assert not store.live_failed()
    assert store.list_findings() == []
    says = " ".join(e.text for e in store.get_assessment().chat)
    assert "0 findings" in says and "No findings were recorded" in says
    # no analyze call was made (nothing to analyze)
    assert not any(p.endswith("/analyze") for p in fake_api.paths())


def test_a_tool_that_fails_does_not_stop_the_run(fake_api):
    fake_api.outputs = {}
    fake_api.findings_for = {}
    # NMAP (LOW) "fails" by producing no findings; the run still ends completed, not failed.
    run_to(None)
    assert store.is_completed() and not store.live_failed()



def test_no_time_limit_by_default(fake_api):
    run_to("plan")
    assert store.get_scope().time_limit_minutes == 0
    assert not store.time_limit_pending()


def _run_with_limit(minutes: str) -> None:
    """Start a run, set a time limit at the scope gate, approve, draft and run the plan."""
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    store.edit_scope(time_limit_minutes=minutes)
    decide("scope")        # approves the scope on the API
    draft_plan()
    assert play_until_gate() == "plan"
    decide("plan")


def test_a_reached_time_limit_pauses_then_continues(fake_api):
    from datetime import timedelta
    from reconix.models.base import utc_now

    _run_with_limit("1")
    assert store.get_scope().time_limit_minutes == 1
    store.get_run().started_at = utc_now() - timedelta(minutes=2)
    assert store.time_limit_pending()
    assert store.next_live_job() is None          # the run pauses, no API call
    store.approve_more_time()
    assert not store.time_limit_pending()
    assert store.get_scope().time_limit_minutes == 0
    run_to_end()
    assert store.is_completed()


def test_stop_at_the_time_limit_ends_the_run(fake_api):
    from datetime import timedelta
    from reconix.models.base import utc_now

    _run_with_limit("1")
    store.get_run().started_at = utc_now() - timedelta(minutes=2)
    assert store.time_limit_pending()
    store.stop_for_time()
    assert store.is_finished() and store.get_run().stopped


def test_zero_is_accepted_as_no_limit(fake_api):
    store.start_run(DEMO_REQUEST)
    assert play_until_gate() == "scope"
    store.edit_scope(time_limit_minutes="0")
    assert store.get_scope().time_limit_minutes == 0


def test_reopen_scope_from_the_plan_step(fake_api):
    run_to("plan")
    old = store.get_assessment().live.assessment_id
    assert store.is_scope_approved() and old
    store.reopen_scope()
    assert not store.is_scope_approved()
    assert store.get_scope().status == "DRAFT"
    assert store.waiting_gate() == "scope"
    assert store.get_assessment().live.assessment_id == ""   # the API assessment is dropped
    # changing a tool is allowed again, then re-approving makes a fresh API assessment
    store.edit_scope(tools=["Nuclei", "OWASP ZAP"])
    store.approve_scope()
    new = store.get_assessment().live.assessment_id
    assert new and new != old
    submits = [p for p in fake_api.paths() if p.endswith("/submit")]
    assert len(submits) == 2                                  # the original and the re-approval


def test_reopen_refused_once_the_plan_runs(fake_api):
    run_to("plan")
    decide("plan")
    with pytest.raises(store.StoreValidationError, match="already running"):
        store.reopen_scope()


def test_scope_is_changeable_at_the_plan_step_not_after_running(fake_api):
    run_to("plan")
    assert store.scope_changeable()
    decide("plan")
    assert not store.scope_changeable()


def test_a_plan_change_request_is_spotted():
    assert store.wants_plan_change("add a login brute-force step")
    assert store.wants_plan_change("redraft the plan")
    assert not store.wants_plan_change("should i approve it")
