from types import SimpleNamespace
from uuid import uuid4

from reconix_api.models.enums import ActionStatus, FindingStatus, SeverityStatus
from reconix_api.services.chat import MAX_CHAT_FINDINGS, plan_lines, rank_chat_findings, step_line
from tests.fakes import fake_mask_secrets

NMAP = {"tool": "NMAP", "target": "172.20.0.5", "arguments": ["-Pn", "-p", "22"]}


def test_a_step_line_names_its_command():
    step = {"order": 1, "title": "Find open ports", "action": NMAP}

    assert step_line(step) == "1. Find open ports (NMAP 172.20.0.5 -Pn -p 22)"


def test_a_step_without_an_action_is_just_its_title():
    assert step_line({"order": 2, "title": "Read the results"}) == "2. Read the results"


def test_rank_chat_findings_excludes_false_positives_ranks_worst_first_and_caps():
    rows = [
        SimpleNamespace(
            finding_status=FindingStatus.FALSE_POSITIVE,
            severity_status=SeverityStatus.CRITICAL,
            code="FP-1",
        ),
        SimpleNamespace(
            finding_status=FindingStatus.OPEN,
            severity_status=SeverityStatus.LOW,
            code="L-1",
        ),
        SimpleNamespace(
            finding_status=FindingStatus.OPEN,
            severity_status=SeverityStatus.CRITICAL,
            code="C-1",
        ),
        *(
            SimpleNamespace(
                finding_status=FindingStatus.OPEN,
                severity_status=SeverityStatus.MEDIUM,
                code=f"M-{i}",
            )
            for i in range(60)
        ),
    ]
    ranked = rank_chat_findings(rows)
    assert len(ranked) == MAX_CHAT_FINDINGS
    assert ranked[0].code == "C-1"
    assert all(r.code != "FP-1" for r in ranked)
    assert all(r.code != "L-1" for r in ranked)


def test_a_step_line_shows_action_status_when_present():
    step = {"order": 1, "title": "Run ZAP", "action": NMAP, "status": "PENDING"}
    assert "PENDING" in step_line(step)


def test_plan_lines_without_assessment_summarizes_assessments_and_waiting_approvals(monkeypatch):
    a1 = SimpleNamespace(
        assessment_id="id-1",
        engagement_code="RCX-2026-0001",
        name="Juice Shop",
        type="WEB",
        assessment_status=SimpleNamespace(value="ACTIVE"),
    )
    monkeypatch.setattr("reconix_api.services.chat.assessment_repo.list_all", lambda _db: [a1])
    monkeypatch.setattr(
        "reconix_api.services.chat.approval_repo.count_waiting",
        lambda _db, ids, _after: {"id-1": 2} if ids == ["id-1"] else {},
    )
    lines = plan_lines(SimpleNamespace(), None, fake_mask_secrets)
    assert len(lines) == 1
    assert "RCX-2026-0001" in lines[0]
    assert "ACTIVE" in lines[0]
    assert "2 waiting approval" in lines[0]


def test_plan_lines_masks_sensitive_assessment_name_and_step_values(monkeypatch):
    aid = uuid4()
    secret = "FAKE_SECRET_1234567890"
    a1 = SimpleNamespace(
        assessment_id=aid,
        engagement_code="RCX-2026-0002",
        name=f"Audit token={secret} lab",
        type="WEB",
        assessment_status=SimpleNamespace(value="ACTIVE"),
    )
    monkeypatch.setattr("reconix_api.services.chat.assessment_repo.list_all", lambda _db: [a1])
    monkeypatch.setattr("reconix_api.services.chat.assessment_repo.get", lambda _db, _id: a1)
    monkeypatch.setattr(
        "reconix_api.services.chat.approval_repo.count_waiting", lambda _db, _ids, _after: {}
    )
    monkeypatch.setattr(
        "reconix_api.services.chat.agent_run_repo.latest_plan",
        lambda _db, _id: SimpleNamespace(
            plan={
                "text": f"Check token={secret}",
                "steps": [
                    {
                        "order": 1,
                        "title": "Scan endpoint",
                        "action": {
                            "tool": "NMAP",
                            "target": f"https://example.com?token={secret}",
                            "arguments": [],
                        },
                    }
                ],
            }
        ),
    )
    monkeypatch.setattr(
        "reconix_api.services.chat.action_repo.list_by_assessment", lambda _db, _id: []
    )

    global_lines = plan_lines(SimpleNamespace(), None, fake_mask_secrets)
    scoped_lines = plan_lines(SimpleNamespace(), aid, fake_mask_secrets)

    assert all(secret not in line for line in global_lines)
    assert all(secret not in line for line in scoped_lines)
    assert any("[MASKED:secret]" in line for line in global_lines)
    assert any("[MASKED:secret]" in line for line in scoped_lines)


def test_plan_lines_for_assessment_includes_status_and_waiting_approvals_even_without_plan(
    monkeypatch,
):
    aid = uuid4()
    a1 = SimpleNamespace(
        assessment_id=aid,
        engagement_code="RCX-2026-0003",
        name="API Pentest",
        type="API",
        assessment_status=SimpleNamespace(value="ACTIVE"),
    )
    monkeypatch.setattr("reconix_api.services.chat.assessment_repo.get", lambda _db, _id: a1)
    monkeypatch.setattr(
        "reconix_api.services.chat.approval_repo.count_waiting", lambda _db, _ids, _after: {aid: 1}
    )
    monkeypatch.setattr(
        "reconix_api.services.chat.agent_run_repo.latest_plan", lambda _db, _id: None
    )
    monkeypatch.setattr(
        "reconix_api.services.chat.action_repo.list_by_assessment", lambda _db, _id: []
    )

    lines = plan_lines(SimpleNamespace(), aid, fake_mask_secrets)

    assert any(
        "RCX-2026-0003" in line and "ACTIVE" in line and "1 waiting approval" in line
        for line in lines
    )


def test_plan_lines_annotates_steps_with_latest_real_action_status(monkeypatch):
    aid = uuid4()
    a1 = SimpleNamespace(
        assessment_id=aid,
        engagement_code="RCX-2026-0004",
        name="Lab",
        type="NETWORK",
        assessment_status=SimpleNamespace(value="ACTIVE"),
    )
    action_row = SimpleNamespace(
        tool="NMAP",
        target="172.20.0.5",
        args=["-Pn", "-p", "22"],
        action_status=ActionStatus.COMPLETED,
    )
    monkeypatch.setattr("reconix_api.services.chat.assessment_repo.get", lambda _db, _id: a1)
    monkeypatch.setattr(
        "reconix_api.services.chat.approval_repo.count_waiting", lambda _db, _ids, _after: {}
    )
    monkeypatch.setattr(
        "reconix_api.services.chat.agent_run_repo.latest_plan",
        lambda _db, _id: SimpleNamespace(
            plan={
                "text": "Start scan.",
                "steps": [{"order": 1, "title": "Find open ports", "action": NMAP}],
            }
        ),
    )
    monkeypatch.setattr(
        "reconix_api.services.chat.action_repo.list_by_assessment",
        lambda _db, _id: [action_row],
    )

    lines = plan_lines(SimpleNamespace(), aid, fake_mask_secrets)

    assert any("1. Find open ports" in line and "COMPLETED" in line for line in lines)
