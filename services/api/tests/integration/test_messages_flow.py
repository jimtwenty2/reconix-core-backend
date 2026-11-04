"""Chat messages: the person writes in their own session, secrets are masked, everyone can read."""

from tests.integration.test_scope_flow import open_session


def new_session(client) -> tuple[str, dict]:
    response = client.post("/sessions", json={"interface": "cli"})
    body = response.json()
    return body["session_id"], {"Authorization": f"Bearer {body['token']}"}


def post(client, headers, session_id, content: str):
    return client.post(
        f"/sessions/{session_id}/messages", json={"content": content}, headers=headers
    )


def test_messages_are_numbered_in_order(db_client):
    session_id, headers = new_session(db_client)
    first = post(db_client, headers, session_id, "scan juice-shop for open ports")
    second = post(db_client, headers, session_id, "then check the web app")
    assert first.status_code == 201, first.json()
    assert (first.json()["sequence_no"], second.json()["sequence_no"]) == (1, 2)
    assert first.json()["role"] == "user"

    listed = db_client.get(f"/sessions/{session_id}/messages", headers=headers).json()
    assert [m["content_masked"] for m in listed] == [
        "scan juice-shop for open ports",
        "then check the web app",
    ]


def test_secret_is_masked_before_it_is_saved(db_client, db_app):
    session_id, headers = new_session(db_client)
    saved = post(db_client, headers, session_id, "login with password=hunter2 please").json()
    assert "hunter2" not in saved["content_masked"]

    listed = db_client.get(f"/sessions/{session_id}/messages", headers=headers).json()
    assert "hunter2" not in listed[0]["content_masked"]
    [event] = [e for e in db_app.state.parts["audit"].events if e.event_type == "MESSAGE_ADDED"]
    assert event.details["masked_count"] == 1
    assert "hunter2" not in str(event.details)


def test_cannot_write_in_another_session(db_client):
    other_id, _ = new_session(db_client)
    headers = open_session(db_client)
    response = post(db_client, headers, other_id, "hello")
    assert response.status_code == 403
    assert response.json()["code"] == "NOT_YOUR_SESSION"


def test_messages_of_an_unknown_session_is_404(db_client):
    headers = open_session(db_client)
    response = db_client.get(
        "/sessions/00000000-0000-0000-0000-000000000000/messages", headers=headers
    )
    assert response.status_code == 404
    assert response.json()["code"] == "SESSION_NOT_FOUND"


def test_empty_message_is_refused(db_client):
    session_id, headers = new_session(db_client)
    assert post(db_client, headers, session_id, "").status_code == 422
