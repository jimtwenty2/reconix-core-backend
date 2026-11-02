import asyncio
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from reconix_api.schemas.findings import FindingOut
from reconix_api.services import findings as findings_service
from reconix_api.services.findings import READERS, parse_run, update_memory
from tests.fakes import FakeFindingMemory

FIXTURES = Path(__file__).parents[2] / "fixtures"


def test_parse_run_picks_the_reader_by_tool_name():
    output = (FIXTURES / "nuclei" / "juice_shop.jsonl").read_text()
    found, _ = parse_run("NUCLEI", output)
    assert len(found) == 3


def test_every_reader_is_named_like_its_kali_tool():
    assert all(name == name.lower() for name in READERS)
    assert {"nmap", "nuclei", "semgrep", "gitleaks"} <= READERS.keys()


def test_tool_without_a_reader_gives_no_findings():
    assert parse_run("whatweb", "anything") == ([], 0)


def reviewed(finding_status: str) -> FindingOut:
    return FindingOut(
        finding_id=uuid4(),
        code="RCX-001",
        title="Anonymous FTP login",
        target="172.20.0.5",
        description="vsftpd allows anonymous login.",
        severity_status="MEDIUM",
        cvss_score=None,
        cwe_ids=[],
        owasp_id=[],
        cve_ids=[],
        impact=None,
        remediation=None,
        validation_status="UNCONFIRMED",
        finding_status=finding_status,
        reviewed_by="operator",
        reviewed_at=datetime.now(UTC),
        created_at=datetime.now(UTC),
        assessment_id=uuid4(),
    )


@pytest.mark.parametrize(
    ("finding_status", "accepted"), [("OPEN", True), ("FIXED", True), ("FALSE_POSITIVE", False)]
)
async def test_open_and_fixed_are_accepted_and_a_false_positive_is_forgotten(
    finding_status, accepted
):
    memory = FakeFindingMemory()

    await update_memory(memory.update, reviewed(finding_status))

    assert memory.calls == [("RCX-001", accepted)]


async def test_a_memory_that_is_down_never_blocks_the_review(caplog):
    memory = FakeFindingMemory()
    memory.down = True

    await update_memory(memory.update, reviewed("OPEN"))  # no error

    assert "RCX-001" in caplog.text and "KNOWLEDGE_UNAVAILABLE" in caplog.text


async def test_a_memory_that_never_answers_times_out(monkeypatch, caplog):
    async def hangs(finding, accepted):
        await asyncio.sleep(60)

    monkeypatch.setattr(findings_service, "MEMORY_TIMEOUT_SECONDS", 0.01)

    await update_memory(hangs, reviewed("OPEN"))

    assert "TIMEOUT" in caplog.text


async def test_a_bug_in_the_memory_is_raised_not_hidden():
    async def broken(finding, accepted):
        raise KeyError("severity")

    with pytest.raises(KeyError):
        await update_memory(broken, reviewed("OPEN"))
