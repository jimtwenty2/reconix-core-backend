from types import SimpleNamespace

from reconix_api.models.enums import FindingStatus, SeverityStatus
from reconix_api.services.chat import MAX_CHAT_FINDINGS, plan_lines, rank_chat_findings, step_line

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
    lines = plan_lines(SimpleNamespace(), None)
    assert len(lines) == 1
    assert "RCX-2026-0001" in lines[0]
    assert "ACTIVE" in lines[0]
    assert "2 waiting approval" in lines[0]
