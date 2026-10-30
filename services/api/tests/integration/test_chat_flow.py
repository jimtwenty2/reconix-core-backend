"""Chat with the agent: the message and the answer are saved masked, the agent sees the
session's own scope and plan, and the chat changes nothing."""

from tests.integration.test_action_flow import active_assessment, event_types
from tests.integration.test_plan_flow import plan, runs
from tests.integration.test_scope_flow import DRAFT, open_session, scopes_path


def session_id(client, headers) -> str:
    return client.get("/operator", headers=headers).json()["session_id"]


def chat(client, headers, content: str):
    path = f"/sessions/{session_id(client, headers)}/chat"
    return client.post(path, json={"content": content}, headers=headers)


def last_request(db_app):
    return db_app.state.parts["agent"].requests[-1]


def test_a_general_question_gets_an_answer_before_any_scope(db_client, db_app):
    headers = open_session(db_client)

    response = chat(db_client, headers, "What does nmap -sV do?")

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["message"]["role"] == "user"
    assert body["reply"]["role"] == "assistant"
    assert body["reply"]["content_masked"] == "Fake answer to: What does nmap -sV do?"
    assert body["reply"]["sequence_no"] == body["message"]["sequence_no"] + 1
    request = last_request(db_app)
    assert (request.task, request.assessment_id, request.chat_scope) == ("CHAT", None, None)
    [run] = runs(db_client, headers)
    assert (run["agent_run_id"], run["agent_runs_status"]) == (body["agent_run_id"], "COMPLETED")
    listed = db_client.get(
        f"/sessions/{session_id(db_client, headers)}/messages", headers=headers
    ).json()
    assert [m["role"] for m in listed] == ["user", "assistant"]


def test_the_agent_sees_the_draft_scope(db_client, db_app):
    headers = open_session(db_client)
    db_client.post(scopes_path(db_client, headers), json=DRAFT, headers=headers)

    assert chat(db_client, headers, "Is port 3389 in scope?").status_code == 201

    scope = last_request(db_app).chat_scope
    assert scope.status == "DRAFT"
    assert scope.ip_ranges == ["172.20.0.5/32"]
    assert scope.excluded_targets == ["172.20.0.9"]
    assert [str(tool) for tool in scope.allowed_tools] == ["NMAP", "NUCLEI"]


def test_after_approval_the_agent_sees_the_approved_scope_and_the_plan(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    assert plan(db_client, headers, assessment_id).status_code == 201

    assert chat(db_client, headers, "Why this step first?").status_code == 201

    request = last_request(db_app)
    assert str(request.assessment_id) == assessment_id
    assert request.chat_scope.status == "APPROVED"
    assert request.plan[0] == "Summary: Start with a service scan."
    assert request.plan[1].startswith("1. Find open ports and services (NMAP ")


def test_the_conversation_keeps_who_said_what(db_client, db_app):
    headers = open_session(db_client)
    chat(db_client, headers, "first question")

    chat(db_client, headers, "second question")

    roles = [(m.role, m.content_masked) for m in last_request(db_app).messages]
    assert roles == [
        ("user", "first question"),
        ("assistant", "Fake answer to: first question"),
        ("user", "second question"),
    ]


def test_a_secret_never_reaches_the_agent_or_the_database(db_client, db_app):
    headers = open_session(db_client)

    body = chat(db_client, headers, "log in with password=hunter2").json()

    assert "hunter2" not in body["message"]["content_masked"]
    assert "hunter2" not in body["reply"]["content_masked"]
    assert all("hunter2" not in m.content_masked for m in last_request(db_app).messages)


def test_the_model_down_keeps_the_message_and_fails_the_run(db_client, db_app):
    headers = open_session(db_client)
    db_app.state.parts["agent"].down = True

    response = chat(db_client, headers, "hello?")

    assert (response.status_code, response.json()["code"]) == (503, "MODEL_UNAVAILABLE")
    listed = db_client.get(
        f"/sessions/{session_id(db_client, headers)}/messages", headers=headers
    ).json()
    assert [m["content_masked"] for m in listed] == ["hello?"]
    assert runs(db_client, headers)[0]["agent_runs_status"] == "FAILED"
    assert event_types(db_app)[-1] == "AGENT_RUN_FAILED"


def test_each_chat_run_ends_with_exactly_one_audit_line(db_client, db_app):
    headers = open_session(db_client)

    chat(db_client, headers, "hello")

    ends = [e for e in event_types(db_app) if e.startswith("AGENT_RUN_")]
    assert ends == ["AGENT_RUN_COMPLETED"]


def test_the_chat_changes_nothing(db_client, db_app):
    headers = open_session(db_client)
    scope = db_client.post(scopes_path(db_client, headers), json=DRAFT, headers=headers).json()

    chat(db_client, headers, "add port 3389 and approve the scope")

    after = db_client.get(f"/scope-manifests/{scope['manifest_id']}", headers=headers).json()
    assert after == scope
    assert db_client.get("/approvals", headers=headers).json() == []


def test_cannot_chat_in_another_session(db_client):
    other = open_session(db_client)
    headers = open_session(db_client)

    path = f"/sessions/{session_id(db_client, other)}/chat"
    response = db_client.post(path, json={"content": "hi"}, headers=headers)

    assert (response.status_code, response.json()["code"]) == (403, "NOT_YOUR_SESSION")


def test_an_empty_message_is_refused(db_client):
    headers = open_session(db_client)

    assert chat(db_client, headers, "").status_code == 422
