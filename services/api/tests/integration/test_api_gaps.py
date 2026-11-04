"""The API pieces the terminal app and the web still needed, through the API and a database:
finding filters, PoC finding checks, the next step, stopping a run and its actions,
combined reports, and testing an AI provider."""

import json

import pytest

from reconix_api.core import provider_checks
from reconix_api.core.interfaces import AgentTask
from tests.integration.test_action_flow import active_assessment, event_types
from tests.integration.test_findings_flow import findings, run_nmap
from tests.integration.test_plan_flow import NUCLEI_STEP, plan
from tests.integration.test_report_flow import (  # noqa: F401 - reports_dir is a fixture
    reports_dir,
    scanned_assessment,
    sign_off,
)
from tests.integration.test_scope_flow import open_session

UNKNOWN_ID = "00000000-0000-0000-0000-000000000099"


def get(client, headers, path, **params):
    response = client.get(path, params=params, headers=headers)
    assert response.status_code == 200, response.json()
    return response.json()


# --- finding filters --------------------------------------------------------------------


def test_findings_filter_by_tool_target_and_text(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)

    def codes(**params) -> list[str]:
        return [f["code"] for f in get(db_client, headers, "/findings", **params)]

    mine = {"assessment_id": assessment_id}
    assert codes(**mine, tool="NMAP") == ["RCX-001", "RCX-002"]
    assert codes(**mine, tool="nmap") == ["RCX-001", "RCX-002"]  # any case
    assert codes(**mine, tool="NUCLEI") == []
    assert codes(**mine, target="172.20") == ["RCX-001", "RCX-002"]
    assert codes(**mine, target="10.9.9") == []
    assert codes(**mine, q="3000") == ["RCX-002"]  # in the title
    assert codes(**mine, q="rcx-001") == ["RCX-001"]  # code, any case
    assert codes(**mine, q="%") == []  # a typed % matches only itself


def test_an_unknown_tool_filter_is_422(db_client):
    headers = open_session(db_client)
    response = db_client.get("/findings", params={"tool": "not_a_tool"}, headers=headers)
    assert response.status_code == 422
    assert response.json()["code"] == "UNKNOWN_TOOL"


@pytest.mark.parametrize("tool", ["nmap", "NMAP", "masscan"])
def test_any_catalog_tool_filter_in_any_case_is_200(db_client, tool):
    headers = open_session(db_client)
    assert db_client.get("/findings", params={"tool": tool}, headers=headers).status_code == 200


# --- PoC finding checks (the AI judges a completed tool run) -------------------------------


def test_a_poc_confirms_a_finding(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)
    finding = findings(db_client, headers, assessment_id)[0]
    tool_run_id = finding["source_tool_run_ids"][0]
    path = f"/findings/{finding['finding_id']}/validation-runs"

    response = db_client.post(path, json={"tool_run_id": tool_run_id}, headers=headers)

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["method"] == "poc"
    assert body["validation_status"] == "CONFIRMED"  # the fake agent's default verdict
    assert body["tool_run_id"] == tool_run_id
    assert body["reviewed_by"] == "agent"  # the verdict is the AI's, not a person's
    saved = get(db_client, headers, f"/findings/{finding['finding_id']}")
    assert saved["validation_status"] == "CONFIRMED"
    assert saved["latest_validation"]["validation_run_id"] == body["validation_run_id"]
    assert [run["method"] for run in get(db_client, headers, path)] == ["poc"]
    assert event_types(db_app).count("FINDING_CHECKED") == 1


def test_a_poc_cannot_use_another_assessments_tool_run(db_client):
    headers = open_session(db_client)
    mine = active_assessment(db_client, headers)
    run_nmap(db_client, headers, mine)
    finding = findings(db_client, headers, mine)[0]

    # A session has one assessment, so the other assessment needs a session of its own.
    other_headers = open_session(db_client)
    other = active_assessment(db_client, other_headers)
    run_nmap(db_client, other_headers, other)
    other_run = findings(db_client, other_headers, other)[0]["source_tool_run_ids"][0]

    response = db_client.post(
        f"/findings/{finding['finding_id']}/validation-runs",
        json={"tool_run_id": other_run},
        headers=headers,
    )
    assert response.status_code == 404
    assert response.json()["code"] == "TOOL_RUN_NOT_FOUND"


def test_checking_an_unknown_finding_is_404(db_client):
    headers = open_session(db_client)
    response = db_client.post(
        f"/findings/{UNKNOWN_ID}/validation-runs",
        json={"tool_run_id": UNKNOWN_ID},
        headers=headers,
    )
    assert response.status_code == 404


# --- the next step, a run's actions, stopping a run ------------------------------------------


def test_the_next_step_needs_a_tool_run_first(db_client):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    response = db_client.post(f"/assessments/{assessment_id}/next-step", headers=headers)

    assert response.status_code == 409
    assert response.json()["code"] == "NO_TOOL_RESULTS"


def test_the_next_step_reads_the_newest_tool_outputs(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    run_nmap(db_client, headers, assessment_id)

    response = db_client.post(f"/assessments/{assessment_id}/next-step", headers=headers)

    assert response.status_code == 201, response.json()
    request = db_app.state.parts["agent"].requests[-1]
    assert request.task == AgentTask.SUGGEST
    assert len(request.tool_results) == 1
    assert 'portid="22"' in request.tool_results[0]
    assert response.json()["agent_run"]["plan"]["task"] == "SUGGEST"
    assert "STEP_SUGGESTED" in event_types(db_app)


def test_a_run_shows_its_step_and_can_be_stopped_while_it_waits(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["agent"].suggest = NUCLEI_STEP  # MEDIUM: waits for a person
    planned = plan(db_client, headers, assessment_id).json()
    run_id = planned["agent_run"]["agent_run_id"]
    approval_id = planned["action"]["approval_id"]

    detail = get(db_client, headers, f"/agent-runs/{run_id}")
    assert detail["agent_runs_status"] == "WAITING_APPROVAL"
    assert [(a["tool"], a["action_status"]) for a in detail["actions"]] == [("NUCLEI", "PENDING")]

    stopped = db_client.post(f"/agent-runs/{run_id}/cancel", headers=headers)

    assert stopped.status_code == 200, stopped.json()
    assert stopped.json()["agent_runs_status"] == "CANCELLED"
    assert get(db_client, headers, f"/agent-runs/{run_id}")["actions"][0]["action_status"] == (
        "CANCELLED"
    )
    approval = get(db_client, headers, f"/approvals/{approval_id}")
    assert (approval["approval_status"], approval["reason"]) == ("EXPIRED", "RUN_CANCELLED")
    late = db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    assert late.status_code == 409
    assert db_app.state.parts["mcp"].jobs == []  # the stopped step never ran
    again = db_client.post(f"/agent-runs/{run_id}/cancel", headers=headers)
    assert again.json()["code"] == "RUN_FINISHED"
    assert "AGENT_RUN_CANCELLED" in event_types(db_app)


def test_stopping_an_unknown_run_is_404(db_client):
    headers = open_session(db_client)
    response = db_client.post(f"/agent-runs/{UNKNOWN_ID}/cancel", headers=headers)
    assert response.status_code == 404
    assert db_client.get(f"/agent-runs/{UNKNOWN_ID}", headers=headers).status_code == 404


# --- combined reports ------------------------------------------------------------------------


def test_one_report_covers_two_assessments(db_client, reports_dir):  # noqa: F811
    headers = open_session(db_client)
    first = scanned_assessment(db_client, headers)
    other_headers = open_session(db_client)
    second = scanned_assessment(db_client, other_headers)

    response = db_client.post(
        f"/assessments/{first}/combined-reports", json={"combined_with": [second]}, headers=headers
    )

    assert response.status_code == 201, response.json()
    report = response.json()
    assert report["report_status"] == "READY"
    assert report["assessment_id"] == first
    assert set(report["assessment_ids"]) == {first, second}
    for assessment_id in (first, second):
        listed = get(db_client, headers, f"/assessments/{assessment_id}/reports")
        assert report["report_id"] in [r["report_id"] for r in listed]
    sign_off(db_client, headers, report["report_id"])
    files = db_client.get(
        f"/reports/{report['report_id']}/download", params={"format": "JSON"}, headers=headers
    )
    assert files.status_code == 200
    codes = [finding["code"] for finding in json.loads(files.content)["findings"]]
    assert len(codes) == 4
    assert all("/RCX-00" in code for code in codes)  # e.g. RCX-2026-0001/RCX-001


def test_a_combined_report_refuses_repeats_and_more_than_five(db_client, reports_dir):  # noqa: F811
    headers = open_session(db_client)
    first = scanned_assessment(db_client, headers)
    path = f"/assessments/{first}/combined-reports"

    repeated = db_client.post(path, json={"combined_with": [first]}, headers=headers)
    too_many = db_client.post(path, json={"combined_with": [UNKNOWN_ID] * 5}, headers=headers)
    unknown = db_client.post(path, json={"combined_with": [UNKNOWN_ID]}, headers=headers)

    assert repeated.json()["code"] == "DUPLICATE_ASSESSMENT"
    assert too_many.status_code == 422
    assert unknown.status_code == 404


# --- testing an AI provider ------------------------------------------------------------------


def builtin_provider_id(client, headers) -> str:
    providers = get(client, headers, "/llm-providers")
    return next(p["llm_provider_id"] for p in providers if p["provider_type"] == "RECONIX")


def test_testing_a_provider_says_whether_the_model_answered(db_client, monkeypatch):
    headers = open_session(db_client)
    provider_id = builtin_provider_id(db_client, headers)
    sent = []

    async def answers(messages, config):
        sent.append(messages)

    monkeypatch.setattr(provider_checks, "complete", answers)
    result = db_client.post(f"/llm-providers/{provider_id}/test", headers=headers).json()

    assert result["ok"] is True
    assert result["model_name"] == "reconix"
    assert sent[0][0].content == provider_checks.TEST_PROMPT  # nothing from Reconix


def test_a_provider_that_does_not_answer_is_not_ok(db_client, monkeypatch):
    from reconix_ai.providers import ProviderError

    headers = open_session(db_client)
    provider_id = builtin_provider_id(db_client, headers)

    async def down(messages, config):
        raise ProviderError("MODEL_UNAVAILABLE", "The model is not running.")

    monkeypatch.setattr(provider_checks, "complete", down)
    result = db_client.post(f"/llm-providers/{provider_id}/test", headers=headers).json()

    assert (result["ok"], result["code"]) == (False, "MODEL_UNAVAILABLE")


def test_an_ollama_provider_lists_its_models(db_client, monkeypatch):
    headers = open_session(db_client)
    provider_id = builtin_provider_id(db_client, headers)

    async def models(base_url):
        return ["bge-m3:latest", "reconix:latest"]

    monkeypatch.setattr(provider_checks, "local_models", models)
    listed = get(db_client, headers, f"/llm-providers/{provider_id}/models")

    assert listed == {"models": ["bge-m3:latest", "reconix:latest"]}


def add_compatible(client, headers, base_url="https://llm.example.com/v1") -> str:
    body = {
        "provider_type": "OPENAI_API_COMPATIBLE",
        "display_name": "Example",
        "model_name": "some-model",
        "base_url": base_url,
        "api_key": "example-test-key-00000001",  # a fake
    }
    response = client.post("/llm-providers", json=body, headers=headers)
    assert response.status_code == 201, response.json()
    return response.json()["llm_provider_id"]


def test_a_new_address_never_gets_the_old_key(db_client):
    headers = open_session(db_client)
    provider_id = add_compatible(db_client, headers)

    moved = db_client.patch(
        f"/llm-providers/{provider_id}",
        json={"base_url": "https://other.example.com/v1"},
        headers=headers,
    )

    assert moved.status_code == 200, moved.json()
    assert moved.json()["api_key_last4"] is None  # typed again for the new address


def test_testing_refuses_a_private_address_and_is_audited(db_client, db_app, monkeypatch):
    headers = open_session(db_client)
    private = add_compatible(db_client, headers, base_url="https://10.0.0.5/v1")
    public = add_compatible(db_client, headers)

    async def answers(messages, config):
        return None

    monkeypatch.setattr(provider_checks, "complete", answers)
    refused = db_client.post(f"/llm-providers/{private}/test", headers=headers)
    assert refused.status_code == 422
    assert refused.json()["code"] == "PROVIDER_URL_NOT_ALLOWED"

    monkeypatch.setattr(provider_checks, "ensure_public_host", lambda url: None)
    tested = db_client.post(f"/llm-providers/{public}/test", headers=headers)
    assert tested.json()["ok"] is True
    assert event_types(db_app).count("LLM_PROVIDER_TESTED") == 1


def test_a_cloud_provider_cannot_list_models(db_client):
    headers = open_session(db_client)
    provider_id = add_compatible(db_client, headers)
    listed = db_client.get(f"/llm-providers/{provider_id}/models", headers=headers)
    assert listed.json()["code"] == "MODEL_LIST_NOT_SUPPORTED"
