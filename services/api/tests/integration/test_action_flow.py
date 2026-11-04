"""Send action -> check -> (approve) -> tool run, through the API and a real database."""

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, update

from reconix_api.core.interfaces import RiskLevel, ToolName
from reconix_api.models import Action, AgentRun, Approval, ScopeManifest
from reconix_api.models.enums import AgentRunStatus
from tests.fakes.fake_core import FAKE_RISK
from tests.integration.test_scope_flow import draft_and_submit, open_session, scopes_path

SCOPE = {
    "max_risk": "HIGH",
    "allowed_tools": ["NMAP", "NUCLEI", "ZAP"],
    "targets": [
        {"type": "ip", "value": "172.20.0.5"},
        {"type": "url", "value": "http://juice-shop:3000/"},
    ],
}


def active_assessment(client, headers, scope_draft: dict = SCOPE) -> str:
    scope = client.post(scopes_path(client, headers), json=scope_draft, headers=headers).json()
    submitted = client.post(
        f"/scope-manifests/{scope['manifest_id']}/submit",
        json={"name": "Juice Shop", "type": "web_url"},
        headers=headers,
    ).json()
    client.post(f"/approvals/{submitted['approval_id']}/approve", json={}, headers=headers)
    return submitted["assessment"]["assessment_id"]


def send(client, headers, assessment_id, **action):
    return client.post(f"/assessments/{assessment_id}/actions", json=action, headers=headers)


def event_types(db_app) -> list[str]:
    return [event.event_type for event in db_app.state.parts["audit"].events]


def test_terminal_codes_in_stderr_are_not_saved(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    # gitleaks's own log line, as it writes it
    db_app.state.parts[
        "mcp"
    ].stderr = "\x1b[90m3:22AM\x1b[0m \x1b[32mINF\x1b[0m \x1b[1mscanned ~253 bytes\x1b[0m\n\x07"

    action = send(
        db_client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    ).json()

    [run] = action["tool_runs"]
    assert run["error"] == "3:22AM INF scanned ~253 bytes\n"


def test_low_action_runs_right_away(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    response = send(
        db_client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    )
    assert response.status_code == 201, response.json()
    action = response.json()
    assert action["risk_level"] == "LOW"
    assert action["action_status"] == "COMPLETED"
    assert action["approval_id"] is None
    [run] = action["tool_runs"]
    assert run["tool_run_status"] == "COMPLETED"
    assert run["approval_id"] is None
    assert 'portid="22"' in run["output_masked"]

    [job] = db_app.state.parts["mcp"].jobs
    assert job.tool_run_id.hex == run["tool_run_id"].replace("-", "")
    assert job.arguments == ["-sV"]
    assert "TOOL_RUN_FINISHED" in event_types(db_app)

    listed = db_client.get(f"/assessments/{assessment_id}/actions", headers=headers).json()
    assert [a["action_id"] for a in listed] == [action["action_id"]]


def test_blocked_action_is_422_and_saved(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    response = send(db_client, headers, assessment_id, tool="NMAP", target="10.0.0.1")
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "ACTION_BLOCKED"
    assert body["details"]["reason"] == "TARGET_OUT_OF_SCOPE"

    action = db_client.get(f"/actions/{body['details']['action_id']}", headers=headers).json()
    assert action["action_status"] == "BLOCKED"
    assert action["tool_runs"] == []
    assert "ACTION_BLOCKED" in event_types(db_app)
    assert db_app.state.parts["mcp"].jobs == []


def test_medium_action_waits_then_runs_once_approved(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)

    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    assert action["risk_level"] == "MEDIUM"
    assert action["action_status"] == "PENDING"
    assert action["tool_runs"] == []
    approval_id = action["approval_id"]

    approved = db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    assert approved.status_code == 200, approved.json()
    assert approved.json()["consumed_at"] is not None

    action = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert action["action_status"] == "COMPLETED"
    [run] = action["tool_runs"]
    assert run["approval_id"] == approval_id

    again = db_client.post(f"/approvals/{approval_id}/approve", json={}, headers=headers)
    assert again.json()["code"] == "APPROVAL_ALREADY_DECIDED"


def test_high_action_needs_the_typed_target(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    target = "http://juice-shop:3000/"
    action = send(db_client, headers, assessment_id, tool="ZAP", target=target).json()
    assert action["risk_level"] == "HIGH"
    path = f"/approvals/{action['approval_id']}/approve"

    wrong = db_client.post(path, json={"typed_target": "juice-shop"}, headers=headers)
    assert wrong.json()["code"] == "TARGET_CONFIRMATION_MISMATCH"
    # A typo is recorded, but the approval stays open for the right target.
    assert event_types(db_app).count("APPROVAL_REFUSED") == 1
    approval = db_client.get(f"/approvals/{action['approval_id']}", headers=headers).json()
    assert approval["approval_status"] == "PENDING"

    right = db_client.post(path, json={"typed_target": target}, headers=headers)
    assert right.status_code == 200
    assert right.json()["confirmation_verified"] is True


def test_rejected_action_never_runs(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()

    rejected = db_client.post(
        f"/approvals/{action['approval_id']}/reject", json={"reason": "not now"}, headers=headers
    )
    assert rejected.status_code == 200
    action = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert action["action_status"] == "REJECTED"
    assert db_app.state.parts["mcp"].jobs == []


def test_expired_action_approval_is_refused(db_client, db_app, session_factory):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    with session_factory() as db:
        db.execute(
            update(Approval)
            .where(Approval.approval_id == action["approval_id"])
            .values(requested_at=datetime.now(UTC) - timedelta(minutes=31))
        )
        db.commit()

    response = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )
    assert response.json()["code"] == "APPROVAL_EXPIRED"
    assert event_types(db_app).count("APPROVAL_EXPIRED") == 1


def test_an_action_changed_after_sending_is_refused_and_ended(db_client, db_app, session_factory):
    """Someone edits the saved action: approving refuses it, ends it and records it once."""
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    with session_factory() as db:
        db.execute(
            update(Action)
            .where(Action.action_id == action["action_id"])
            .values(target="http://172.20.0.5/")
        )
        db.commit()

    response = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )

    assert (response.status_code, response.json()["code"]) == (409, "ACTION_CHANGED")
    assert db_app.state.parts["mcp"].jobs == []
    saved = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert (saved["action_status"], saved["tool_runs"]) == ("BLOCKED", [])
    approval = db_client.get(f"/approvals/{action['approval_id']}", headers=headers).json()
    assert (approval["approval_status"], approval["reason"]) == ("EXPIRED", "ACTION_CHANGED")
    assert event_types(db_app).count("ACTION_BLOCKED") == 1
    again = db_client.post(f"/approvals/{action['approval_id']}/approve", json={}, headers=headers)
    assert again.json()["code"] == "APPROVAL_ALREADY_DECIDED"


def test_action_needs_an_active_assessment(db_client):
    headers = open_session(db_client)
    submitted = draft_and_submit(db_client, headers)
    assessment_id = submitted["assessment"]["assessment_id"]

    response = send(db_client, headers, assessment_id, tool="NMAP", target="172.20.0.5")
    assert response.status_code == 409
    assert response.json()["code"] == "ASSESSMENT_NOT_ACTIVE"


def test_unreachable_kali_saves_a_failed_run(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    db_app.state.parts["mcp"].down = True

    action = send(db_client, headers, assessment_id, tool="NMAP", target="172.20.0.5").json()
    assert action["action_status"] == "FAILED"
    [run] = action["tool_runs"]
    assert run["tool_run_status"] == "FAILED"
    assert "KALI_UNREACHABLE" in run["error"]


def test_a_persons_actions_share_one_open_agent_run(db_client, session_factory):
    headers = open_session(db_client)
    other = open_session(db_client)  # e.g. the web while the terminal app is open
    assessment_id = active_assessment(db_client, headers)

    ran = send(
        db_client, headers, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    )
    blocked = send(db_client, headers, assessment_id, tool="NMAP", target="10.0.0.1")
    from_other = send(
        db_client, other, assessment_id, tool="NMAP", target="172.20.0.5", arguments=["-sV"]
    )
    assert (ran.status_code, blocked.status_code, from_other.status_code) == (201, 422, 201)
    action_ids = {
        "ran": ran.json()["action_id"],
        "blocked": blocked.json()["details"]["action_id"],  # blocked, still filed
        "other": from_other.json()["action_id"],
    }

    with session_factory() as db:
        run_of = {name: db.get(Action, UUID(i)).agent_run_id for name, i in action_ids.items()}
        runs = db.scalars(select(AgentRun).where(AgentRun.assessment_id == assessment_id)).all()
        # A run with no plan is stored as SQL NULL, so the "no plan" lookup can find it.
        without_plan = db.scalar(
            select(func.count())
            .select_from(AgentRun)
            .where(AgentRun.assessment_id == assessment_id, AgentRun.plan.is_(None))
        )
    # One open run per session: the first session's two actions share theirs.
    assert run_of["ran"] == run_of["blocked"] != run_of["other"]
    assert [run.agent_runs_status for run in runs] == [AgentRunStatus.RUNNING] * 2
    assert without_plan == 2


def test_approving_after_the_assessment_is_cancelled_runs_nothing(db_client, db_app):
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    cancelled = db_client.delete(f"/assessments/{assessment_id}", headers=headers)
    assert cancelled.json()["assessment_status"] == "CANCELLED"

    response = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )
    assert response.status_code == 409
    assert response.json()["code"] == "ASSESSMENT_NOT_ACTIVE"
    assert db_app.state.parts["mcp"].jobs == []
    saved = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert (saved["action_status"], saved["tool_runs"]) == ("CANCELLED", [])
    approval = db_client.get(f"/approvals/{action['approval_id']}", headers=headers).json()
    assert (approval["approval_status"], approval["consumed_at"]) == ("EXPIRED", None)
    assert event_types(db_app).count("ACTION_BLOCKED") == 1


def test_approving_runs_the_checks_again(db_client, db_app, session_factory):
    """The scope changed after the action was sent, so the second check blocks it."""
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    with session_factory() as db:
        db.execute(
            update(ScopeManifest)
            .where(ScopeManifest.assessment_id == assessment_id)
            .values(allowed_tools=["NMAP", "ZAP"])
        )
        db.commit()

    response = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )
    assert response.status_code == 422
    body = response.json()
    assert (body["code"], body["details"]["reason"]) == ("ACTION_BLOCKED", "TOOL_NOT_ALLOWED")
    assert body["details"]["action_id"] == action["action_id"]
    assert db_app.state.parts["mcp"].jobs == []
    saved = db_client.get(f"/actions/{action['action_id']}", headers=headers).json()
    assert (saved["action_status"], saved["tool_runs"]) == ("BLOCKED", [])
    assert saved["guardrail_report"]["reason"] == "TOOL_NOT_ALLOWED"
    approval = db_client.get(f"/approvals/{action['approval_id']}", headers=headers).json()
    assert (approval["approval_status"], approval["reason"]) == ("EXPIRED", "TOOL_NOT_ALLOWED")
    assert approval["consumed_at"] is None
    assert event_types(db_app).count("ACTION_BLOCKED") == 1

    # The approval can no longer be used, so a blocked action never runs later.
    again = db_client.post(f"/approvals/{action['approval_id']}/approve", json={}, headers=headers)
    assert again.json()["code"] == "APPROVAL_ALREADY_DECIDED"
    assert db_app.state.parts["mcp"].jobs == []


def test_approving_refuses_an_action_whose_risk_rose(db_client, db_app, monkeypatch):
    """A MEDIUM approval never runs an action the checks now rate HIGH (no typed target)."""
    headers = open_session(db_client)
    assessment_id = active_assessment(db_client, headers)
    action = send(
        db_client, headers, assessment_id, tool="NUCLEI", target="http://juice-shop:3000/"
    ).json()
    assert action["risk_level"] == "MEDIUM"
    monkeypatch.setitem(FAKE_RISK, ToolName.NUCLEI, RiskLevel.HIGH)  # e.g. the risk rules changed

    response = db_client.post(
        f"/approvals/{action['approval_id']}/approve", json={}, headers=headers
    )

    assert response.status_code == 422
    details = response.json()["details"]
    assert (details["blocked_by"], details["reason"], details["risk"]) == (
        "RISK",
        "RISK_CHANGED",
        "HIGH",
    )
    assert db_app.state.parts["mcp"].jobs == []
