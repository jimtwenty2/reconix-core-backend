"""AI providers through the API and a real database: add, edit, remove, and make one
active. A provider off this computer is active only after its `configuration` approval."""

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select, update

from reconix_api.core import provider_keys
from reconix_api.core.config import get_settings
from reconix_api.core.errors import ApiError
from reconix_api.models import AgentRun, Approval, LlmProvider
from reconix_api.services.agent_runs import make_provider_for_run
from tests.integration.test_action_flow import active_assessment, event_types
from tests.integration.test_plan_flow import plan, runs
from tests.integration.test_scope_flow import open_session

FAKE_API_KEY = "sk-fake-integration-key-wxyz"  # noqa: S105
OPENAI = {
    "provider_type": "OPENAI",
    "display_name": "OpenAI",
    "model_name": "gpt-4o",
    "api_key": FAKE_API_KEY,
}
OLLAMA = {"provider_type": "OLLAMA", "display_name": "My Ollama", "model_name": "llama3.1:8b"}


def add(client, headers, body: dict) -> dict:
    response = client.post("/llm-providers", json=body, headers=headers)
    assert response.status_code == 201, response.json()
    return response.json()


def activate(client, headers, provider_id: str) -> dict:
    response = client.post(f"/llm-providers/{provider_id}/activate", headers=headers)
    assert response.status_code == 200, response.json()
    return response.json()


def approve(client, headers, approval_id: str):
    return client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)


def active(client, headers) -> list[str]:
    providers = client.get("/llm-providers", headers=headers).json()
    return [provider["provider_type"] for provider in providers if provider["is_active"]]


def built_in_id(client, headers) -> str:
    providers = client.get("/llm-providers", headers=headers).json()
    return next(p["llm_provider_id"] for p in providers if p["provider_type"] == "RECONIX")


def saved(session_factory, provider_id: str) -> LlmProvider:
    with session_factory() as db:
        return db.get(LlmProvider, provider_id)


def test_the_built_in_provider_is_there_and_active(db_client):
    headers = open_session(db_client)

    providers = db_client.get("/llm-providers", headers=headers).json()

    # Not local: RECONIX is the Reconix team's server (RECONIX_MODEL_URL), not this computer.
    assert [(p["provider_type"], p["is_active"], p["is_local"]) for p in providers] == [
        ("RECONIX", True, False)
    ]


def test_a_new_provider_is_saved_inactive_with_its_key_encrypted(
    db_client, db_app, session_factory
):
    headers = open_session(db_client)

    response = db_client.post("/llm-providers", json=OPENAI, headers=headers)

    assert response.status_code == 201, response.json()
    provider = response.json()
    assert provider["is_active"] is False
    assert provider["is_local"] is False
    assert provider["api_key_last4"] == "wxyz"
    assert "api_key" not in provider
    assert FAKE_API_KEY not in response.text
    row = saved(session_factory, provider["llm_provider_id"])
    assert FAKE_API_KEY.encode() not in row.api_key_encrypted
    settings = db_app.dependency_overrides[get_settings]()
    assert provider_keys.decrypt(settings, row.api_key_encrypted) == FAKE_API_KEY
    assert event_types(db_app)[-1] == "LLM_PROVIDER_ADDED"
    audit = json.dumps([event.details for event in db_app.state.parts["audit"].events])
    assert FAKE_API_KEY not in audit


def test_bad_settings_are_refused_without_echoing_the_key(db_client):
    headers = open_session(db_client)
    cases = [
        ({**OPENAI, "provider_type": "RECONIX"}, "PROVIDER_TYPE_NOT_ALLOWED"),  # already there
        ({**OPENAI, "api_key": None}, "PROVIDER_KEY_MISSING"),
        ({**OLLAMA, "provider_type": "OPENAI_API_COMPATIBLE"}, "PROVIDER_URL_MISSING"),
        ({**OPENAI, "base_url": "http://llm.example.com"}, "PROVIDER_URL_NOT_ALLOWED"),
        ({**OPENAI, "base_url": "https://169.254.169.254"}, "PROVIDER_URL_NOT_ALLOWED"),
        ({**OPENAI, "model_name": "gpt 4o"}, "VALIDATION_ERROR"),
        ({**OPENAI, "model_name": "token:fake-model-secret"}, "SECRET_NOT_ALLOWED"),
        ({**OPENAI, "base_url": " https://llm.example.com"}, "PROVIDER_URL_NOT_ALLOWED"),
        ({**OPENAI, "api_key": "sk-short"}, "VALIDATION_ERROR"),  # under 16 characters
    ]
    for body, code in cases:
        response = db_client.post("/llm-providers", json=body, headers=headers)
        assert response.status_code == 422, body
        assert response.json()["code"] == code
        assert FAKE_API_KEY not in response.text
        assert "fake-model-secret" not in response.text
        assert "sk-short" not in response.text
    assert db_client.get("/llm-providers", headers=headers).json()[1:] == []


def test_a_provider_on_this_computer_is_active_at_once(db_client, db_app):
    headers = open_session(db_client)
    ollama = add(db_client, headers, OLLAMA)

    activation = activate(db_client, headers, ollama["llm_provider_id"])

    assert activation["approval"] is None
    assert activation["llm_provider"]["is_active"] is True
    assert active(db_client, headers) == ["OLLAMA"]
    assert event_types(db_app)[-1] == "LLM_PROVIDER_ACTIVATED"


def test_a_new_run_asks_the_agent_for_the_active_provider(db_client, db_app):
    """The run records the model the agent is asked for."""
    headers = open_session(db_client)
    activate(db_client, headers, add(db_client, headers, OLLAMA)["llm_provider_id"])
    assessment_id = active_assessment(db_client, headers)

    response = plan(db_client, headers, assessment_id)

    assert response.status_code == 201, response.json()
    request = db_app.state.parts["agent"].requests[-1]
    assert (request.provider, request.model) == ("OLLAMA", "llama3.1:8b")
    assert runs(db_client, headers)[0]["model_name"] == "llama3.1:8b"


def test_the_model_call_gets_the_runs_provider_and_its_key(db_client, db_app, session_factory):
    """The settings the AI Service calls the model with: the run's own provider and
    model, with the saved key decrypted."""
    headers = open_session(db_client)
    openai = add(db_client, headers, OPENAI)
    activation = activate(db_client, headers, openai["llm_provider_id"])
    assert approve(db_client, headers, activation["approval"]["approval_id"]).status_code == 200
    assessment_id = active_assessment(db_client, headers)
    assert plan(db_client, headers, assessment_id).status_code == 201
    run_id = UUID(runs(db_client, headers)[0]["agent_run_id"])
    settings = db_app.dependency_overrides[get_settings]()

    config = make_provider_for_run(session_factory, settings)(run_id)

    assert (config.provider_type, config.model_name) == ("OPENAI", "gpt-4o")
    assert config.api_key == FAKE_API_KEY
    assert FAKE_API_KEY not in repr(config)


def test_a_run_never_calls_its_provider_once_it_was_changed(db_client, db_app, session_factory):
    """Switch away, point the old row elsewhere (no approval needed for an inactive row),
    and the run that started on it must not follow the new address."""
    headers = open_session(db_client)
    ollama = add(db_client, headers, OLLAMA)
    activate(db_client, headers, ollama["llm_provider_id"])
    assert plan(db_client, headers, active_assessment(db_client, headers)).status_code == 201
    run_id = UUID(runs(db_client, headers)[0]["agent_run_id"])
    activate(db_client, headers, built_in_id(db_client, headers))
    moved = {"base_url": "https://collector.example.com/v1"}
    edit = db_client.patch(
        f"/llm-providers/{ollama['llm_provider_id']}", json=moved, headers=headers
    )
    assert edit.status_code == 200, edit.json()
    provider_for_run = make_provider_for_run(
        session_factory, db_app.dependency_overrides[get_settings]()
    )

    with pytest.raises(ApiError) as error:
        provider_for_run(run_id)

    assert (error.value.status, error.value.code) == (409, "PROVIDER_CHANGED")


def test_the_built_in_provider_asks_the_agent_for_its_own_model(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    assert plan(db_client, headers, assessment_id).status_code == 201

    request = db_app.state.parts["agent"].requests[-1]
    assert (request.provider, request.model) == ("RECONIX", None)


def test_a_cloud_service_on_this_computer_still_needs_an_approval(db_client):
    """A local address for OpenAI is a proxy or a tunnel: the key and the prompts still
    leave this computer."""
    headers = open_session(db_client)
    proxy = add(db_client, headers, {**OPENAI, "base_url": "http://127.0.0.1:4000"})

    activation = activate(db_client, headers, proxy["llm_provider_id"])

    assert proxy["is_local"] is False
    assert activation["approval"]["kind"] == "configuration"
    assert active(db_client, headers) == ["RECONIX"]


def test_a_cloud_provider_is_active_only_after_its_approval(db_client, db_app):
    headers = open_session(db_client)
    openai = add(db_client, headers, OPENAI)

    activation = activate(db_client, headers, openai["llm_provider_id"])

    approval = activation["approval"]
    assert approval["kind"] == "configuration"
    assert approval["approval_status"] == "PENDING"
    assert approval["config_change"] == {
        "change": "ACTIVATE_LLM_PROVIDER",
        "llm_provider_id": openai["llm_provider_id"],
    }
    assert approval["subject_snapshot"]["api_key_last4"] == "wxyz"
    assert FAKE_API_KEY not in json.dumps(approval)
    assert activation["llm_provider"]["is_active"] is False
    assert active(db_client, headers) == ["RECONIX"]  # nothing changed yet
    waiting = db_client.get("/approvals?kind=configuration", headers=headers).json()
    assert [a["approval_id"] for a in waiting] == [approval["approval_id"]]

    approved = approve(db_client, headers, approval["approval_id"])

    assert approved.status_code == 200, approved.json()
    assert approved.json()["consumed_at"] is not None
    assert active(db_client, headers) == ["OPENAI"]
    assert event_types(db_app)[-2:] == ["APPROVAL_REQUESTED", "APPROVAL_GRANTED"]
    # Single use: the same approval cannot switch the provider again.
    assert approve(db_client, headers, approval["approval_id"]).json()["code"] == (
        "APPROVAL_ALREADY_DECIDED"
    )


def test_rejecting_keeps_the_active_provider(db_client, db_app):
    headers = open_session(db_client)
    openai = add(db_client, headers, OPENAI)
    approval = activate(db_client, headers, openai["llm_provider_id"])["approval"]

    rejected = db_client.post(
        f"/approvals/{approval['approval_id']}/reject",
        json={"reason": "No cloud models for this client."},
        headers=headers,
    )

    assert rejected.status_code == 200, rejected.json()
    assert rejected.json()["approval_status"] == "REJECTED"
    assert active(db_client, headers) == ["RECONIX"]
    assert event_types(db_app)[-1] == "APPROVAL_REJECTED"


def test_a_provider_changed_after_the_request_is_refused(db_client, db_app):
    headers = open_session(db_client)
    openai = add(db_client, headers, OPENAI)
    provider_id = openai["llm_provider_id"]
    first = activate(db_client, headers, provider_id)["approval"]
    # A new address needs its key typed again: the old one is never sent elsewhere.
    changed = db_client.patch(
        f"/llm-providers/{provider_id}",
        json={"base_url": "https://llm.example.com", "api_key": OPENAI["api_key"]},
        headers=headers,
    )
    assert changed.status_code == 200, changed.json()

    refused = approve(db_client, headers, first["approval_id"])

    assert refused.status_code == 409
    assert refused.json()["code"] == "PROVIDER_CHANGED"
    assert active(db_client, headers) == ["RECONIX"]
    # The refusal spends the approval at once and is recorded.
    old = db_client.get(f"/approvals/{first['approval_id']}", headers=headers).json()
    assert (old["approval_status"], old["reason"]) == ("EXPIRED", "PROVIDER_CHANGED")
    assert event_types(db_app)[-1] == "APPROVAL_EXPIRED"
    # Asking again closes the old approval and opens one for the new settings.
    second = activate(db_client, headers, provider_id)["approval"]
    assert second["subject_snapshot"]["base_url"] == "https://llm.example.com"
    old = db_client.get(f"/approvals/{first['approval_id']}", headers=headers).json()
    assert old["approval_status"] == "EXPIRED"
    assert approve(db_client, headers, second["approval_id"]).status_code == 200


def test_one_open_approval_per_provider(db_client):
    headers = open_session(db_client)
    openai = add(db_client, headers, OPENAI)
    first = activate(db_client, headers, openai["llm_provider_id"])["approval"]

    again = db_client.post(f"/llm-providers/{openai['llm_provider_id']}/activate", headers=headers)

    assert again.status_code == 409
    assert again.json()["code"] == "APPROVAL_PENDING"
    assert again.json()["details"] == {"approval_id": first["approval_id"]}


def test_an_expired_activation_cannot_be_approved(db_client, session_factory):
    headers = open_session(db_client)
    openai = add(db_client, headers, OPENAI)
    approval = activate(db_client, headers, openai["llm_provider_id"])["approval"]
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == approval["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        db.commit()

    refused = approve(db_client, headers, approval["approval_id"])

    assert refused.json()["code"] == "APPROVAL_EXPIRED"
    assert active(db_client, headers) == ["RECONIX"]


def test_an_edit_changes_only_the_fields_sent(db_client, db_app, session_factory):
    headers = open_session(db_client)
    provider_id = add(db_client, headers, OPENAI)["llm_provider_id"]
    path = f"/llm-providers/{provider_id}"

    renamed = db_client.patch(path, json={"display_name": "Work OpenAI"}, headers=headers)
    rekeyed = db_client.patch(path, json={"api_key": "sk-fake-second-key-5678"}, headers=headers)
    no_key = db_client.patch(path, json={"api_key": None}, headers=headers)
    no_name = db_client.patch(path, json={"display_name": None}, headers=headers)

    assert renamed.status_code == 200, renamed.json()
    assert (renamed.json()["display_name"], renamed.json()["model_name"]) == (
        "Work OpenAI",
        "gpt-4o",
    )
    assert rekeyed.json()["api_key_last4"] == "5678"
    settings = db_app.dependency_overrides[get_settings]()
    row = saved(session_factory, provider_id)
    assert provider_keys.decrypt(settings, row.api_key_encrypted) == "sk-fake-second-key-5678"
    assert no_key.json()["code"] == "PROVIDER_KEY_MISSING"  # OpenAI always needs one
    assert no_name.json()["code"] == "VALIDATION_ERROR"
    assert event_types(db_app).count("LLM_PROVIDER_EDITED") == 2


def test_the_built_in_provider_can_be_rekeyed_removed_and_added_back(db_client):
    headers = open_session(db_client)
    reconix_id = built_in_id(db_client, headers)
    url = f"/llm-providers/{reconix_id}"

    rekeyed = db_client.patch(url, json={"api_key": FAKE_API_KEY}, headers=headers)
    other_field = db_client.patch(url, json={"model_name": "other"}, headers=headers)
    second = db_client.post(
        "/llm-providers", json={**OPENAI, "provider_type": "RECONIX"}, headers=headers
    )
    removed = db_client.delete(url, headers=headers)
    with_url = {**OPENAI, "provider_type": "RECONIX", "base_url": "http://127.0.0.1:1"}
    refused_url = db_client.post("/llm-providers", json=with_url, headers=headers)
    added = db_client.post(
        "/llm-providers", json={**OPENAI, "provider_type": "RECONIX"}, headers=headers
    )

    assert rekeyed.status_code == 200, rekeyed.json()  # even while it is the active one
    assert rekeyed.json()["api_key_last4"] == "wxyz"
    assert FAKE_API_KEY not in rekeyed.text
    assert (other_field.status_code, other_field.json()["code"]) == (409, "BUILT_IN_PROVIDER")
    assert (second.status_code, second.json()["code"]) == (422, "PROVIDER_TYPE_NOT_ALLOWED")
    assert removed.status_code == 204
    assert (refused_url.status_code, refused_url.json()["code"]) == (422, "BUILT_IN_PROVIDER")
    assert added.status_code == 201, added.json()
    assert added.json()["provider_type"] == "RECONIX"


def test_only_the_active_provider_cannot_be_changed(db_client, db_app):
    headers = open_session(db_client)
    reconix_id = built_in_id(db_client, headers)
    ollama_id = add(db_client, headers, OLLAMA)["llm_provider_id"]
    activate(db_client, headers, ollama_id)

    edit_active = db_client.patch(
        f"/llm-providers/{ollama_id}", json={"base_url": "https://gpu.example.com"}, headers=headers
    )
    remove_active = db_client.delete(f"/llm-providers/{ollama_id}", headers=headers)

    assert edit_active.json()["code"] == "PROVIDER_IS_ACTIVE"  # the active one never changes
    assert remove_active.status_code == 204  # ...but Unset removes it
    assert active(db_client, headers) == []  # nothing is active in its place

    # With no model chosen, nothing runs: the person is told, not quietly served another one.
    session_id = db_client.get("/operator", headers=headers).json()["session_id"]
    refused = db_client.post(
        f"/sessions/{session_id}/chat", json={"content": "who are you?"}, headers=headers
    )
    assert refused.status_code == 503
    assert refused.json()["code"] == "NO_ACTIVE_PROVIDER"

    # The one line still says what was answering and that the person is now model-less.
    removed = [
        e for e in db_app.state.parts["audit"].events if e.event_type == "LLM_PROVIDER_REMOVED"
    ][-1]
    assert removed.details["model_name"] == "llama3.1:8b"
    assert removed.details["reason"] == "no model is active until the person chooses one"
    # The built-in one can always be made active again, at once.
    assert activate(db_client, headers, reconix_id)["approval"] is None
    assert active(db_client, headers) == ["RECONIX"]


def test_an_unused_provider_can_be_removed(db_client, db_app):
    headers = open_session(db_client)
    provider_id = add(db_client, headers, OLLAMA)["llm_provider_id"]

    removed = db_client.delete(f"/llm-providers/{provider_id}", headers=headers)

    assert removed.status_code == 204
    assert db_client.get(f"/llm-providers/{provider_id}", headers=headers).status_code == 404
    assert event_types(db_app)[-1] == "LLM_PROVIDER_REMOVED"


def test_removing_a_provider_closes_its_open_approval(db_client, db_app):
    headers = open_session(db_client)
    provider_id = add(db_client, headers, OPENAI)["llm_provider_id"]
    approval = activate(db_client, headers, provider_id)["approval"]

    removed = db_client.delete(f"/llm-providers/{provider_id}", headers=headers)

    assert removed.status_code == 204
    closed = db_client.get(f"/approvals/{approval['approval_id']}", headers=headers).json()
    assert closed["approval_status"] == "EXPIRED"
    waiting = db_client.get("/approvals?kind=configuration", headers=headers).json()
    assert waiting == []
    assert event_types(db_app)[-2:] == ["APPROVAL_EXPIRED", "LLM_PROVIDER_REMOVED"]


def test_a_provider_that_agent_runs_used_is_archived(db_client, session_factory, db_app):
    headers = open_session(db_client)
    provider_id = add(db_client, headers, OLLAMA)["llm_provider_id"]
    session_id = db_client.get("/operator", headers=headers).json()["session_id"]
    with session_factory() as db:
        db.add(
            AgentRun(model_name="llama3.1:8b", session_id=session_id, llm_provider_id=provider_id)
        )
        db.commit()
    activate(db_client, headers, provider_id)  # the archived row must not stay the active one

    archived = db_client.delete(f"/llm-providers/{provider_id}", headers=headers)

    assert archived.status_code == 204
    assert db_client.get(f"/llm-providers/{provider_id}", headers=headers).status_code == 404
    listed = db_client.get("/llm-providers", headers=headers).json()
    assert provider_id not in [row["llm_provider_id"] for row in listed]
    assert active(db_client, headers) == []
    with session_factory() as db:
        row = db.scalar(select(LlmProvider).where(LlmProvider.llm_provider_id == provider_id))
        assert row is not None and row.archived is True and row.is_active is False
    assert event_types(db_app)[-1] == "LLM_PROVIDER_ARCHIVED"


def test_moving_a_provider_drops_its_key(db_client, session_factory):
    """A key is never sent to an address it wasn't given for: send it again."""
    headers = open_session(db_client)
    compatible = add(
        db_client,
        headers,
        {
            "provider_type": "OPENAI_API_COMPATIBLE",
            "display_name": "Lab model",
            "model_name": "qwen",
            "base_url": "https://llm.example.com/v1",
            "api_key": FAKE_API_KEY,
        },
    )
    provider_id = compatible["llm_provider_id"]

    moved = db_client.patch(
        f"/llm-providers/{provider_id}",
        json={"base_url": "https://other.example.com/v1"},
        headers=headers,
    )

    assert moved.status_code == 200, moved.json()
    assert moved.json()["api_key_last4"] is None
    assert saved(session_factory, provider_id).api_key_encrypted is None
    # A cloud service needs its key, so moving one without it is refused.
    openai = add(db_client, headers, OPENAI)
    refused = db_client.patch(
        f"/llm-providers/{openai['llm_provider_id']}",
        json={"base_url": "https://api.example.com/v1"},
        headers=headers,
    )
    assert refused.json()["code"] == "PROVIDER_KEY_MISSING"
