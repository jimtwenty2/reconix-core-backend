import json
from io import BytesIO

import pytest
from docx import Document

from reconix_ai.agent.state import masked_report
from reconix_ai.contracts import FindingInput, ReportInput, ToolRunInput
from reconix_ai.reports.files import (
    refuse_fetch,
    report_document,
    to_docx,
    to_html,
    to_json,
    to_pdf,
)
from tests.unit.analysis.cases import CASES

SECRET = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
META = {"title": "Juice Shop test", "Assessment": "RCX-2026-0001", "Version": "1"}


def locked_copy(**overrides) -> ReportInput:
    findings = [FindingInput(**case.finding) for case in (CASES[0], CASES[4], CASES[8])]
    runs = [
        ToolRunInput(
            "NMAP", "172.20.0.5", ["-sV"], "MEDIUM", "COMPLETED", "APPROVED", "2026-10-29T09:00:00"
        ),
        ToolRunInput("NUCLEI", "http://juice-shop:3000/", [], "MEDIUM", "COMPLETED", "MISSING"),
    ]
    values = {
        "findings": findings,
        "severity_counts": {"HIGH": 1, "MEDIUM": 1, "CRITICAL": 1},
        "tool_runs": runs,
    }
    return ReportInput(**(values | overrides))


def document(report: ReportInput | None = None, summary: str = "Fix the AWS key first.") -> dict:
    copy, _ = masked_report(report or locked_copy())
    return report_document(copy, summary, "We scanned the lab in 2 steps.", META)


def test_counts_and_findings_come_from_the_locked_copy() -> None:
    doc = document()

    assert doc["severity_counts"] == {
        "CRITICAL": 1,
        "HIGH": 1,
        "MEDIUM": 1,
        "LOW": 0,
        "NONE": 0,
        "UNKNOWN": 0,
    }
    assert [f["code"] for f in doc["findings"]] == ["RCX-009", "RCX-005", "RCX-001"]  # worst first


def test_json_round_trips() -> None:
    doc = document()

    assert json.loads(to_json(doc)) == doc


def test_pdf_is_a_pdf() -> None:
    pdf = to_pdf(document())

    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1000


def test_docx_opens_and_holds_every_part() -> None:
    word = Document(BytesIO(to_docx(document())))
    text = "\n".join(p.text for p in word.paragraphs)
    cells = {cell.text for table in word.tables for row in table.rows for cell in row.cells}

    assert "Fix the AWS key first." in text
    assert "RCX-005 SQL injection in product search" in text
    assert "RCX-2026-0001" in text
    assert "MISSING" in cells  # the run without an approval is named


def test_html_escapes_what_the_target_wrote() -> None:
    finding = FindingInput(**{**CASES[5].finding, "description": "<script>alert(1)</script>"})

    html = to_html(document(locked_copy(findings=[finding])))

    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


@pytest.mark.parametrize("render", [to_json, to_html, to_docx], ids=["json", "html", "docx"])
def test_no_secret_reaches_any_file(render) -> None:
    leaked = FindingInput(**{**CASES[0].finding, "description": f"token={SECRET}"})
    summary = f"The key {SECRET} was found."

    output = render(document(locked_copy(findings=[leaked]), summary=summary))
    if isinstance(output, bytes) and output.startswith(b"PK"):  # a DOCX is a zip
        word = Document(BytesIO(output))
        output = "\n".join(p.text for p in word.paragraphs)
    text = output.decode() if isinstance(output, bytes) else output

    assert SECRET not in text
    assert "[MASKED:" in text


def test_a_report_without_findings_still_renders() -> None:
    doc = document(locked_copy(findings=[], severity_counts={}, tool_runs=[]))

    assert "No findings." in to_html(doc)
    assert to_pdf(doc).startswith(b"%PDF-")


def test_an_unknown_severity_in_the_counts_fails_loudly() -> None:
    copy, _ = masked_report(locked_copy(severity_counts={"INFO": 2}))

    with pytest.raises(ValueError, match="INFO"):
        report_document(copy, "x", "y", META)


def test_a_report_never_fetches_anything() -> None:
    with pytest.raises(ValueError, match="never loads"):
        refuse_fetch("file:///etc/passwd")


def test_only_known_severities_become_a_css_class() -> None:
    odd = FindingInput(**{**CASES[0].finding, "severity_status": "x CRITICAL"})

    html = to_html(document(locked_copy(findings=[odd])))

    assert 'class="sev UNKNOWN"' in html
    assert 'class="sev x CRITICAL"' not in html
