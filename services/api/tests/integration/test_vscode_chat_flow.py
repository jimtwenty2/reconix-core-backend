"""VS Code chat: a message that asks for a chat function is answered at once without the
agent, a question goes to the agent like /chat, and only an open vscode session may use it."""

import pytest
from sqlalchemy import select

from reconix_api.models import Message
from tests.integration.test_code_scan_flow import (
    event_types,
    ready_to_scan,
    slow_tools,
    start,
    vscode_session,
    wait_for_end,
)


@pytest.fixture
def client(code_client):
    return code_client


def vscode_chat(client, headers, session_id, content: str):
    path = f"/sessions/{session_id}/vscode-chat"
    return client.post(path, json={"content": content}, headers=headers)


def agent_requests(db_app) -> list:
    return db_app.state.parts["agent"].requests


def scanned(client, db_app) -> tuple[dict, str, list[dict]]:
    """A vscode session whose code scan has finished, and its findings."""
    headers, session_id, assessment_id = ready_to_scan(client, db_app)
    scan_id = start(client, headers, assessment_id).json()["agent_run_id"]
    wait_for_end(client, headers, scan_id)
    found = client.get(f"/code-scans/{scan_id}/findings", headers=headers).json()
    return headers, session_id, found


def test_a_client_function_comes_back_without_asking_the_agent(client, db_app, session_factory):
    headers, session_id = vscode_session(client)

    response = vscode_chat(client, headers, session_id, "scan this project")

    assert response.status_code == 201, response.json()
    body = response.json()
    assert body["function_call"] == {
        "name": "START_SCAN",
        "arguments": {"full": False, "paths": []},
    }
    assert (body["runs_on"], body["confirm"], body["result"]) == ("CLIENT", True, None)
    assert body["agent_run_id"] is None
    assert body["reply"]["content_masked"] == "Starting a scan of the workspace."
    assert agent_requests(db_app) == []
    assert event_types(db_app)[-2:] == ["MESSAGE_ADDED", "CHAT_FUNCTION_CALLED"]
    with session_factory() as db:
        reply = db.scalars(select(Message).where(Message.role == "assistant")).one()
        assert reply.metadata_ == {"function_call": body["function_call"]}


def test_a_question_is_answered_by_the_agent(client, db_app):
    headers, session_id = vscode_session(client)

    body = vscode_chat(client, headers, session_id, "What is XSS?").json()

    assert body["function_call"] is None
    assert body["reply"]["content_masked"] == "Fake answer to: What is XSS?"
    assert body["agent_run_id"] is not None
    assert agent_requests(db_app)[-1].task == "CHAT"


def test_server_functions_answer_from_the_sessions_latest_scan(client, db_app):
    headers, session_id, found = scanned(client, db_app)
    high = [f for f in found if f["severity_status"] == "HIGH"]

    listed = vscode_chat(client, headers, session_id, "show the high findings").json()
    assert (listed["runs_on"], listed["confirm"]) == ("SERVER", False)
    assert [f["finding_id"] for f in listed["result"]["findings"]] == [
        f["finding_id"] for f in high
    ]

    explained = vscode_chat(client, headers, session_id, f"explain {high[0]['code']}").json()
    assert explained["result"]["finding"]["finding_id"] == high[0]["finding_id"]

    summary = vscode_chat(client, headers, session_id, "summarize").json()["result"]
    assert summary["total"] == len(found)
    assert summary["counts"]["HIGH"] == len(high)

    status = vscode_chat(client, headers, session_id, "scan status").json()
    assert status["result"]["scan"]["agent_runs_status"] == "COMPLETED"
    assert agent_requests(db_app) == []


def test_fix_names_findings_of_the_sessions_latest_scan(client, db_app):
    headers, session_id, found = scanned(client, db_app)
    by_path = sorted(found, key=lambda f: f["path"])  # most serious first, then by file
    high = [f["finding_id"] for f in by_path if f["severity_status"] == "HIGH"]
    assert len(high) == 2  # semgrep's eval and the gitleaks leak

    body = vscode_chat(client, headers, session_id, "fix all high findings").json()

    assert body["function_call"] == {"name": "PROPOSE_FIX", "arguments": {"finding_ids": high}}
    assert (body["runs_on"], body["confirm"]) == ("CLIENT", True)


def test_fix_before_any_scan_only_answers(client):
    headers, session_id = vscode_session(client)

    body = vscode_chat(client, headers, session_id, "fix everything").json()

    assert body["function_call"] is None
    assert body["reply"]["content_masked"].startswith("There are no findings to fix yet.")


def test_stop_asks_first_and_names_the_running_scan(client, db_app):
    headers, session_id, assessment_id = ready_to_scan(client, db_app)
    slow_tools(db_app, 0.3)
    scan_id = start(client, headers, assessment_id).json()["agent_run_id"]

    body = vscode_chat(client, headers, session_id, "stop the scan").json()

    assert body["function_call"] == {"name": "CANCEL_SCAN", "arguments": {"agent_run_id": scan_id}}
    assert (body["runs_on"], body["confirm"]) == ("CLIENT", True)
    # Nothing is cancelled until VS Code calls the cancel endpoint after the person says yes.
    assert client.get(f"/code-scans/{scan_id}", headers=headers).json()["agent_runs_status"] == (
        "RUNNING"
    )
    wait_for_end(client, headers, scan_id)
    again = vscode_chat(client, headers, session_id, "stop").json()
    assert (again["function_call"], again["reply"]["content_masked"]) == (
        None,
        "No code scan is running.",
    )


def test_a_closed_session_is_refused(client):
    headers, session_id = vscode_session(client)
    assert client.post(f"/sessions/{session_id}/close", headers=headers).status_code == 200

    response = vscode_chat(client, headers, session_id, "scan this project")

    # Closing revokes the token at once; the service's own SESSION_CLOSED check is the
    # backstop (tests/unit/services/test_vscode_chat.py).
    assert response.status_code == 401


def test_the_active_model_is_not_switched_again(client):
    headers, session_id = vscode_session(client)

    body = vscode_chat(client, headers, session_id, "use the reconix model").json()

    assert body["function_call"] is None
    assert body["reply"]["content_masked"].endswith("is already the active model.")


def test_the_functions_can_be_listed(client):
    headers, _ = vscode_session(client)

    listed = client.get("/vscode-chat/functions", headers=headers).json()

    assert len(listed) == 8
    start_scan = next(f for f in listed if f["name"] == "START_SCAN")
    assert (start_scan["runs_on"], start_scan["confirm"]) == ("CLIENT", True)
    assert set(start_scan["parameters"]["properties"]) == {"full", "paths"}


def test_only_a_vscode_session_may_use_it(client):
    created = client.post("/sessions", json={"interface": "cli"}).json()
    headers = {"Authorization": f"Bearer {created['token']}"}

    response = vscode_chat(client, headers, created["session_id"], "scan this project")

    assert response.status_code == 409
    assert response.json()["code"] == "NOT_VSCODE_SESSION"


def test_another_sessions_chat_is_refused(client):
    headers, _ = vscode_session(client)
    _, other_session_id = vscode_session(client)

    response = vscode_chat(client, headers, other_session_id, "scan this project")

    assert response.status_code == 403
    assert response.json()["code"] == "NOT_YOUR_SESSION"
