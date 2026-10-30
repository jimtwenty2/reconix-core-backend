"""`/web` sign-in: a signed-in person asks for a one-time code, and the web trades it for
its own session token. There are no roles: the web token may do everything."""

from datetime import UTC, datetime

from tests.integration.test_action_flow import event_types
from tests.integration.test_scope_flow import open_session


def issue_code(client, headers) -> dict:
    response = client.post("/sessions/web-sign-in-codes", headers=headers)
    assert response.status_code == 201, response.json()
    return response.json()


def sign_in(client, code: str):
    return client.post("/sessions/web-sign-in", json={"code": code})


def test_the_code_opens_a_web_session_with_its_own_token(db_client, db_app):
    headers = open_session(db_client)
    issued = issue_code(db_client, headers)
    assert datetime.fromisoformat(issued["expires_at"]) > datetime.now(UTC)

    response = sign_in(db_client, issued["code"])

    assert response.status_code == 201, response.json()
    web = response.json()
    assert web["interface"] == "web"
    assert web["token"] not in (issued["code"], headers["Authorization"].split()[1])
    web_headers = {"Authorization": f"Bearer {web['token']}"}
    me = db_client.get("/operator", headers=web_headers).json()
    assert me["session_id"] == web["session_id"]
    assert {"WEB_SIGN_IN_CODE_ISSUED", "SESSION_OPENED"} <= set(event_types(db_app))


def test_a_code_works_only_once(db_client):
    headers = open_session(db_client)
    code = issue_code(db_client, headers)["code"]
    assert sign_in(db_client, code).status_code == 201

    again = sign_in(db_client, code)
    assert again.status_code == 401
    assert again.json()["code"] == "INVALID_SIGN_IN_CODE"


def test_a_code_is_not_a_session_token(db_client):
    headers = open_session(db_client)
    code = issue_code(db_client, headers)["code"]
    response = db_client.get("/operator", headers={"Authorization": f"Bearer {code}"})
    assert response.status_code == 401


def test_only_a_signed_in_person_gets_a_code(db_client):
    assert db_client.post("/sessions/web-sign-in-codes").status_code == 401


def test_the_code_is_not_written_to_the_audit_log(db_client, db_app):
    headers = open_session(db_client)
    code = issue_code(db_client, headers)["code"]
    sign_in(db_client, code)
    assert code not in str(db_app.state.parts["audit"].events)


def test_closing_the_session_cancels_its_code(db_client):
    session = db_client.post("/sessions", json={"interface": "cli"}).json()
    headers = {"Authorization": f"Bearer {session['token']}"}
    code = issue_code(db_client, headers)["code"]
    closed = db_client.post(f"/sessions/{session['session_id']}/close", headers=headers)
    assert closed.status_code == 200, closed.json()

    assert sign_in(db_client, code).status_code == 401


def test_the_web_session_names_the_session_that_asked(db_client, db_app):
    session = db_client.post("/sessions", json={"interface": "cli"}).json()
    headers = {"Authorization": f"Bearer {session['token']}"}
    sign_in(db_client, issue_code(db_client, headers)["code"])

    opened = [e for e in db_app.state.parts["audit"].events if e.event_type == "SESSION_OPENED"]
    assert opened[-1].details["issued_by_session"] == session["session_id"]
