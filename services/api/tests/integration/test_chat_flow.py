"""Chat with the agent: the message and the answer are saved masked, the agent sees the
session's own scope and plan, and the chat changes nothing."""

import asyncio
import dataclasses
import json
from uuid import UUID

import pytest

from reconix_api.core.interfaces import Operator, SourceRef
from reconix_api.services import agent_runs
from reconix_api.services import chat as chat_service
from tests.fakes import fake_mask_secrets
from tests.integration.test_action_flow import active_assessment, event_types
from tests.integration.test_findings_flow import findings as assessment_findings
from tests.integration.test_findings_flow import run_nmap
from tests.integration.test_plan_flow import plan, runs
from tests.integration.test_scope_flow import DRAFT, open_session, scopes_path

# One knowledge piece an answer cites, as the AI Service sends it, and as the apps read it.
CITED = SourceRef(
    ref_id="CWE-89",
    title="Improper Neutralization of Special Elements used in an SQL Command",
    url="https://cwe.mitre.org/data/definitions/89.html",
    source="CWE",
    section="Description",
)
CITED_JSON = {
    "ref_id": "CWE-89",
    "title": "Improper Neutralization of Special Elements used in an SQL Command",
    "url": "https://cwe.mitre.org/data/definitions/89.html",
    "source": "CWE",
    "section": "Description",
}


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
    assert body["sources"] == []  # the answer cited no knowledge: nothing to show
    request = last_request(db_app)
    assert (request.task, request.assessment_id, request.chat_scope) == ("CHAT", None, None)
    [run] = runs(db_client, headers)
    assert (run["agent_run_id"], run["agent_runs_status"]) == (body["agent_run_id"], "COMPLETED")
    listed = db_client.get(
        f"/sessions/{session_id(db_client, headers)}/messages", headers=headers
    ).json()
    assert [m["role"] for m in listed] == ["user", "assistant"]


def test_an_answer_carries_the_knowledge_it_cites(db_client, db_app):
    """An app shows where an answer came from, so the API passes the cited knowledge on:
    a title and a link, not the bare id the agent used to cite it."""
    db_app.state.parts["agent"].sources = [CITED]
    headers = open_session(db_client)

    body = chat(db_client, headers, "What is an SQL injection?").json()

    assert body["sources"] == [CITED_JSON]


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


def test_a_draft_scope_reaches_the_agent_masked(db_client, db_app):
    """A draft can hold anything half written: its targets are masked too (S8)."""
    headers = open_session(db_client)
    leaky = {"type": "url", "value": "http://juice-shop:3000/login?password=hunter2-in-a-draft"}
    draft = {**DRAFT, "targets": [*DRAFT["targets"], leaky]}
    assert db_client.post(scopes_path(db_client, headers), json=draft, headers=headers).is_success

    assert chat(db_client, headers, "Is the login page in scope?").status_code == 201

    prefixes = last_request(db_app).chat_scope.url_prefixes
    assert "hunter2-in-a-draft" not in " ".join(prefixes)
    assert any("[MASKED" in prefix for prefix in prefixes)


def test_one_chat_at_a_time_in_a_session(db_client, session_factory):
    headers = open_session(db_client)
    with session_factory() as db:  # a chat still waiting on the agent
        operator = Operator(session_id=UUID(session_id(db_client, headers)), actor="test")
        agent_runs.new_agent_run(db, operator, None, task="CHAT")
        db.commit()

    response = chat(db_client, headers, "And now?")

    assert (response.status_code, response.json()["code"]) == (409, "CHAT_IN_PROGRESS")


def chat_stream(client, headers, content: str):
    path = f"/sessions/{session_id(client, headers)}/chat/stream"
    return client.post(path, json={"content": content}, headers=headers)


def sse_events(text: str) -> list[tuple[str, dict]]:
    events = []
    for message in text.strip().split("\n\n"):
        event, data = message.split("\n")
        events.append((event.removeprefix("event: "), json.loads(data.removeprefix("data: "))))
    return events


def test_a_streamed_chat_sends_pieces_then_the_saved_answer(db_client, db_app):
    headers = open_session(db_client)
    question = "What does nmap -sV do? " + "Please explain it in plain words. " * 8

    response = chat_stream(db_client, headers, question)

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    events = sse_events(response.text)
    names = [name for name, _ in events]
    assert names[-1] == "DONE" and set(names[:-1]) == {"PIECE"}
    shown = "".join(data["text"] for name, data in events if name == "PIECE")
    done = events[-1][1]
    assert done["reply"]["content_masked"].startswith(shown.strip()[:20])
    [run] = runs(db_client, headers)
    assert (run["agent_run_id"], run["agent_runs_status"]) == (done["agent_run_id"], "COMPLETED")
    listed = db_client.get(
        f"/sessions/{session_id(db_client, headers)}/messages", headers=headers
    ).json()
    assert [m["role"] for m in listed] == ["user", "assistant"]
    assert event_types(db_app)[-1] == "AGENT_RUN_COMPLETED"  # still one line for the run


def test_a_streamed_answer_ends_with_the_sources_it_cited(db_client, db_app):
    """The streamed chat ends with the same saved answer, so it carries the same sources."""
    db_app.state.parts["agent"].sources = [CITED]
    headers = open_session(db_client)

    response = chat_stream(db_client, headers, "What is an SQL injection?")

    done = sse_events(response.text)[-1][1]
    assert done["sources"] == [CITED_JSON]


def test_a_failed_streamed_chat_ends_with_an_error_and_a_failed_run(db_client, db_app):
    headers = open_session(db_client)
    db_app.state.parts["agent"].fail_after_pieces = True

    response = chat_stream(db_client, headers, "What does nmap -sV do?")

    name, data = sse_events(response.text)[-1]
    assert (name, data["code"]) == ("ERROR", "MODEL_UNAVAILABLE")
    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "FAILED"
    assert event_types(db_app)[-1] == "AGENT_RUN_FAILED"


def test_a_streamed_chat_in_another_session_fails_before_streaming(db_client):
    headers = open_session(db_client)
    path = f"/sessions/{UUID(int=1)}/chat/stream"

    response = db_client.post(path, json={"content": "hello"}, headers=headers)

    assert response.status_code == 403
    assert response.json()["code"] == "NOT_YOUR_SESSION"


def start_unread_ask(db_client, db_app, session_factory) -> tuple[dict, chat_service.StreamedAsk]:
    """A streamed ask whose request session is closed and whose events nobody reads,
    as when the client leaves at once."""
    headers = open_session(db_client)
    interfaces = db_app.state.interfaces
    operator = interfaces.get_operator(headers["Authorization"].removeprefix("Bearer "))
    with session_factory() as db:
        started = chat_service.start(
            db, interfaces, fake_mask_secrets, operator, operator.session_id, "hello"
        )
        ask = chat_service.ask_in_background(db, interfaces, fake_mask_secrets, operator, started)
    return headers, ask


async def test_a_streamed_ask_ends_its_run_when_nobody_reads_it(db_client, db_app, session_factory):
    headers, ask = start_unread_ask(db_client, db_app, session_factory)

    await ask.task

    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "COMPLETED"
    assert chat(db_client, headers, "and again?").status_code == 201  # not locked


async def test_a_cancelled_ask_ends_its_run_failed(db_client, db_app, session_factory):
    async def slow(request, on_piece=None):
        await asyncio.sleep(30)

    db_app.state.interfaces = dataclasses.replace(db_app.state.interfaces, ask_agent=slow)
    headers, ask = start_unread_ask(db_client, db_app, session_factory)
    await asyncio.sleep(0.05)

    ask.task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await ask.task

    [run] = runs(db_client, headers)
    assert run["agent_runs_status"] == "FAILED"
    assert event_types(db_app)[-1] == "AGENT_RUN_FAILED"


def test_web_chat_passes_findings_scope_and_plan_for_requested_assessment(db_client, db_app):
    headers_a = open_session(db_client)
    aid = active_assessment(db_client, headers_a)
    plan(db_client, headers_a, aid)
    run_nmap(db_client, headers_a, aid)
    listed = assessment_findings(db_client, headers_a, aid)
    assert [f["code"] for f in listed] == ["RCX-001", "RCX-002"]
    db_client.patch(
        f"/findings/{listed[1]['finding_id']}",
        json={"finding_status": "FALSE_POSITIVE"},
        headers=headers_a,
    )

    headers_b = open_session(db_client)
    sid_b = session_id(db_client, headers_b)
    response = db_client.post(
        f"/sessions/{sid_b}/chat",
        json={"content": "Analyze the current findings", "assessment_id": aid},
        headers=headers_b,
    )

    assert response.status_code == 201, response.json()
    req = last_request(db_app)
    assert req.assessment_id == UUID(aid)
    assert req.chat_scope is not None
    assert req.plan != []
    assert [f.code for f in req.findings] == ["RCX-001"]


def test_web_chat_without_assessment_id_passes_all_open_findings(db_client, db_app):
    headers_a = open_session(db_client)
    aid = active_assessment(db_client, headers_a)
    run_nmap(db_client, headers_a, aid)

    headers_b = open_session(db_client)
    sid_b = session_id(db_client, headers_b)
    response = db_client.post(
        f"/sessions/{sid_b}/chat",
        json={"content": "Analyze the current findings"},
        headers=headers_b,
    )

    assert response.status_code == 201, response.json()
    req = last_request(db_app)
    assert req.assessment_id is None
    assert {f.code for f in req.findings} >= {"RCX-001", "RCX-002"}


def test_chat_with_unknown_assessment_id_returns_404(db_client):
    headers = open_session(db_client)
    sid = session_id(db_client, headers)
    res = db_client.post(
        f"/sessions/{sid}/chat",
        json={"content": "hi", "assessment_id": "00000000-0000-4000-8000-000000000999"},
        headers=headers,
    )
    assert res.status_code == 404
    assert res.json()["code"] == "ASSESSMENT_NOT_FOUND"


def test_chat_on_assessment_session_with_mismatched_assessment_id_returns_409(db_client):
    headers_1 = open_session(db_client)
    active_assessment(db_client, headers_1)
    headers_2 = open_session(db_client)
    aid_2 = active_assessment(db_client, headers_2)

    sid_1 = session_id(db_client, headers_1)
    res = db_client.post(
        f"/sessions/{sid_1}/chat",
        json={"content": "hi", "assessment_id": aid_2},
        headers=headers_1,
    )
    assert res.status_code == 409
    assert res.json()["code"] == "ASSESSMENT_MISMATCH"
