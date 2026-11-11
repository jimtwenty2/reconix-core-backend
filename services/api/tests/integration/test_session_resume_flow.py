"""Resuming a web session: tokens live in memory only, so after a restart an open web
session has none. POST /sessions/{id}/resume gives it a new one, so its chat can go on."""

import uuid

from tests.integration.test_action_flow import event_types
from tests.integration.test_scope_flow import open_session


def open_web(client) -> dict:
    response = client.post("/sessions", json={"interface": "web"})
    assert response.status_code == 201, response.json()
    return response.json()


def resume(client, headers, session_id):
    return client.post(f"/sessions/{session_id}/resume", headers=headers)


def test_a_web_session_resumed_by_another_token_can_write_in_itself_again(db_client, db_app):
    web = open_web(db_client)  # its token is "lost": another session resumes it
    headers = open_session(db_client)

    response = resume(db_client, headers, web["session_id"])

    assert response.status_code == 201, response.json()
    resumed = response.json()
    assert resumed["session_id"] == web["session_id"]
    assert resumed["token"] != web["token"]
    own = {"Authorization": f"Bearer {resumed['token']}"}
    written = db_client.post(
        f"/sessions/{web['session_id']}/messages", json={"content": "still here"}, headers=own
    )
    assert written.status_code == 201, written.json()
    assert db_client.get("/operator", headers=own).json()["session_id"] == web["session_id"]
    assert event_types(db_app).count("SESSION_RESUMED") == 1


def test_the_old_token_keeps_working(db_client):
    web = open_web(db_client)
    headers = open_session(db_client)
    assert resume(db_client, headers, web["session_id"]).status_code == 201
    old = {"Authorization": f"Bearer {web['token']}"}
    assert db_client.get("/operator", headers=old).status_code == 200


def test_only_an_open_web_session_is_resumed(db_client):
    headers = open_session(db_client)  # a cli session
    cli = db_client.get("/operator", headers=headers).json()["session_id"]
    refused = resume(db_client, headers, cli)
    assert (refused.status_code, refused.json()["code"]) == (403, "NOT_A_WEB_SESSION")

    web = open_web(db_client)
    web_headers = {"Authorization": f"Bearer {web['token']}"}
    assert (
        db_client.post(f"/sessions/{web['session_id']}/close", headers=web_headers).status_code
        == 200
    )
    closed = resume(db_client, headers, web["session_id"])
    assert (closed.status_code, closed.json()["code"]) == (409, "SESSION_CLOSED")
    # a closed session stays closed: its token does not come back
    assert db_client.get("/operator", headers=web_headers).status_code == 401

    unknown = resume(db_client, headers, uuid.uuid4())
    assert (unknown.status_code, unknown.json()["code"]) == (404, "SESSION_NOT_FOUND")


def test_resuming_needs_a_session_token(db_client):
    web = open_web(db_client)
    assert db_client.post(f"/sessions/{web['session_id']}/resume").status_code == 401
