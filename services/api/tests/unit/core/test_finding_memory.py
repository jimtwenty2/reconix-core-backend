from datetime import UTC, datetime
from uuid import uuid4

import pytest

from reconix_ai import memory
from reconix_ai.knowledge import KnowledgeError
from reconix_api.core.finding_memory import MemoryUnavailable, ai_finding_memory
from reconix_api.schemas.findings import FindingOut


def reviewed(finding_status: str = "OPEN") -> FindingOut:
    return FindingOut(
        finding_id=uuid4(),
        code="RCX-001",
        title="Anonymous FTP login",
        target="172.20.0.5",
        description="vsftpd allows anonymous login.",
        severity_status="MEDIUM",
        cvss_score=None,
        cwe_ids=["CWE-287"],
        owasp_id=[],
        cve_ids=[],
        impact="Anyone can read the files.",
        remediation=None,
        validation_status="UNCONFIRMED",
        finding_status=finding_status,
        reviewed_by="operator",
        reviewed_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
        assessment_id=uuid4(),
    )


@pytest.fixture
def calls(monkeypatch) -> list:
    seen: list = []

    async def remember(finding):
        seen.append(("remember", finding))

    async def forget(finding_id):
        seen.append(("forget", finding_id))

    monkeypatch.setattr(memory, "remember_finding", remember)
    monkeypatch.setattr(memory, "forget_finding", forget)
    return seen


async def test_an_accepted_finding_is_remembered_with_its_erd_fields(calls):
    finding = reviewed("FIXED")

    await ai_finding_memory(finding, accepted=True)

    [(what, saved)] = calls
    assert what == "remember"
    assert (saved.finding_id, saved.assessment_id) == (
        str(finding.finding_id),
        str(finding.assessment_id),
    )
    assert (saved.severity_status, saved.finding_status) == ("MEDIUM", "FIXED")
    assert (saved.cwe_ids, saved.impact) == (["CWE-287"], "Anyone can read the files.")


async def test_a_finding_that_is_not_accepted_is_forgotten(calls):
    finding = reviewed("FALSE_POSITIVE")

    await ai_finding_memory(finding, accepted=False)

    assert calls == [("forget", str(finding.finding_id))]


async def test_an_outage_keeps_only_its_code(monkeypatch):
    async def down(finding):
        raise KnowledgeError("KNOWLEDGE_UNAVAILABLE", "Qdrant at http://127.0.0.1:6333 is down")

    monkeypatch.setattr(memory, "remember_finding", down)

    with pytest.raises(MemoryUnavailable) as error:
        await ai_finding_memory(reviewed(), accepted=True)

    assert error.value.code == "KNOWLEDGE_UNAVAILABLE"
    assert "127.0.0.1" not in str(error.value)
    assert error.value.__context__ is None
