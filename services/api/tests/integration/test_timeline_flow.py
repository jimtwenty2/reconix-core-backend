"""GET /assessments/{id}/timeline with the real harness audit writer and a database."""

import dataclasses

from reconix_ai.harness import make_audit_writer
from reconix_api.core.config import get_settings
from tests.integration.test_action_flow import active_assessment
from tests.integration.test_scope_flow import open_session

UNKNOWN_ID = "00000000-0000-0000-0000-000000000099"


def with_real_audit_log(db_app, path) -> None:
    """The real writer to a file, and the endpoint reading that same file."""
    write_audit = make_audit_writer(path)
    db_app.state.interfaces = dataclasses.replace(db_app.state.interfaces, write_audit=write_audit)
    settings = db_app.dependency_overrides[get_settings]()
    with_log = settings.model_copy(update={"audit_log_path": str(path)})
    db_app.dependency_overrides[get_settings] = lambda: with_log


def timeline(client, headers, assessment_id, **params):
    return client.get(f"/assessments/{assessment_id}/timeline", params=params, headers=headers)


def test_the_scope_flow_shows_on_the_timeline(db_client, db_app, tmp_path):
    with_real_audit_log(db_app, tmp_path / "audit.jsonl")
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    response = timeline(db_client, headers, assessment_id)

    assert response.status_code == 200, response.json()
    body = response.json()
    assert [event["event_type"] for event in body["events"]] == [
        "SCOPE_SUBMITTED",
        "SCOPE_APPROVED",
    ]
    assert body["has_older"] is False


def test_event_types_and_limit_narrow_it(db_client, db_app, tmp_path):
    with_real_audit_log(db_app, tmp_path / "audit.jsonl")
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    only = timeline(db_client, headers, assessment_id, event_type="SCOPE_APPROVED").json()
    newest = timeline(db_client, headers, assessment_id, limit=1).json()

    assert [event["event_type"] for event in only["events"]] == ["SCOPE_APPROVED"]
    assert [event["event_type"] for event in newest["events"]] == ["SCOPE_APPROVED"]
    assert newest["has_older"] is True


def test_bad_parameters_are_422(db_client):
    headers = open_session(db_client)
    for params in ({"event_type": "scope_approved"}, {"limit": 0}, {"limit": 2001}):
        assert timeline(db_client, headers, UNKNOWN_ID, **params).status_code == 422


def test_an_unknown_assessment_is_404(db_client):
    headers = open_session(db_client)
    response = timeline(db_client, headers, UNKNOWN_ID)
    assert response.status_code == 404
    assert response.json()["code"] == "ASSESSMENT_NOT_FOUND"
