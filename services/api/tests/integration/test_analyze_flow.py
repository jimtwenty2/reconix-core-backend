"""nmap run -> findings -> analyze, through the API and a real database. The agent is the
fake: it gives each finding back unchanged, marked for a person to decide."""

from reconix_api.core.interfaces import AgentTask
from tests.integration.test_action_flow import active_assessment, event_types, send
from tests.integration.test_findings_flow import findings, run_nmap
from tests.integration.test_plan_flow import runs
from tests.integration.test_scope_flow import open_session


def analyze(client, headers, assessment_id):
    return client.post(f"/assessments/{assessment_id}/analyze", headers=headers)


def test_open_findings_are_analyzed_and_the_analysis_is_applied(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)

    response = analyze(db_client, headers, assessment_id)

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["summary"] == "Fake analysis."
    assert [a["code"] for a in body["analysis"]] == ["RCX-001", "RCX-002"]
    assert body["agent_run"]["agent_runs_status"] == "COMPLETED"
    assert body["agent_run"]["plan"]["task"] == "ANALYZE"
    request = db_app.state.parts["agent"].requests[-1]
    assert request.task == AgentTask.ANALYZE
    assert [f.code for f in request.findings] == ["RCX-001", "RCX-002"]
    assert 'portid="22"' in request.tool_results[0]  # the run that found them, masked
    # The ANALYZE step now fills each finding's explanation, impact and remediation so the
    # operator reads a plain-language analysis, not just the raw tool evidence.
    after = {f["code"]: f for f in findings(db_client, headers, assessment_id)}
    assert after["RCX-001"]["description"].startswith("In plain terms:")
    assert after["RCX-001"]["impact"] == "Fake impact."
    assert after["RCX-001"]["remediation"] == "Fake remediation."
    # The status a person owns is untouched: the analysis does not accept the finding.
    assert after["RCX-001"]["finding_status"] == "OPEN"
    assert "AGENT_RUN_COMPLETED" in event_types(db_app)


def test_analyze_can_target_specific_findings(db_client, db_app):
    # Per-step analysis: analyze only the finding(s) a step just found, not every OPEN one.
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    rows = {f["code"]: f for f in findings(db_client, headers, assessment_id)}

    response = db_client.post(
        f"/assessments/{assessment_id}/analyze",
        json={"finding_ids": [rows["RCX-001"]["finding_id"]]},
        headers=headers,
    )

    assert response.status_code == 201, response.json()
    assert [a["code"] for a in response.json()["analysis"]] == ["RCX-001"]
    after = {f["code"]: f for f in findings(db_client, headers, assessment_id)}
    assert after["RCX-001"]["impact"] == "Fake impact."  # the targeted finding was analyzed
    assert after["RCX-002"]["impact"] is None  # the other was left for its own step


def test_findings_are_sent_10_at_a_time(db_client, db_app, monkeypatch):
    from reconix_api.services import analysis

    monkeypatch.setattr(analysis, "GROUP_SIZE", 1)
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)

    body = analyze(db_client, headers, assessment_id).json()

    asks = [r for r in db_app.state.parts["agent"].requests if r.task == AgentTask.ANALYZE]
    assert [[f.code for f in r.findings] for r in asks] == [["RCX-001"], ["RCX-002"]]
    assert [a["code"] for a in body["analysis"]] == ["RCX-001", "RCX-002"]
    assert len({r.agent_run_id for r in asks}) == 1  # one run for the whole analysis


def test_closed_findings_are_left_out(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    first = findings(db_client, headers, assessment_id)[0]
    db_client.patch(
        f"/findings/{first['finding_id']}",
        json={"finding_status": "FALSE_POSITIVE"},
        headers=headers,
    )

    body = analyze(db_client, headers, assessment_id).json()

    assert [a["code"] for a in body["analysis"]] == ["RCX-002"]


def test_no_open_findings_is_a_422(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    response = analyze(db_client, headers, assessment_id)

    assert response.status_code == 422
    assert response.json()["code"] == "NO_FINDINGS"
    assert runs(db_client, headers) == []  # no run was opened


def test_the_model_down_fails_the_run(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    db_app.state.parts["agent"].down = True

    response = analyze(db_client, headers, assessment_id)

    assert response.status_code == 503
    analysis_runs = [
        r for r in runs(db_client, headers) if (r["plan"] or {}).get("task") == "ANALYZE"
    ]
    assert [r["agent_runs_status"] for r in analysis_runs] == ["FAILED"]


def test_a_suggested_validation_step_still_waits_for_approval(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    # An operator sends a suggested next_step as a validation action.
    response = send(
        db_client,
        headers,
        assessment_id,
        tool="NMAP",
        target="172.20.0.5",
        arguments=["-sV"],
        purpose="validation",
    )

    assert response.status_code == 201, response.json()
    assert response.json()["risk_level"] == "MEDIUM"  # a LOW nmap becomes MEDIUM
    assert response.json()["approval_id"] is not None
    assert db_app.state.parts["mcp"].jobs == []


def test_what_the_agent_writes_is_masked_before_it_is_saved(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    fake = db_app.state.parts["agent"]
    real_analyze = fake.analyze

    def leaky(request):
        response = real_analyze(request)
        leaked = response.analysis[0].model_copy(update={"impact": "password=Sup3rS3cret!"})
        return response.model_copy(update={"analysis": [leaked, *response.analysis[1:]]})

    fake.analyze = leaky

    body = analyze(db_client, headers, assessment_id).json()

    assert "Sup3rS3cret!" not in str(body)
    assert "Sup3rS3cret!" not in str(runs(db_client, headers))
    # The analysis is written onto the finding too, so it must be masked there as well.
    assert "Sup3rS3cret!" not in str(findings(db_client, headers, assessment_id))
