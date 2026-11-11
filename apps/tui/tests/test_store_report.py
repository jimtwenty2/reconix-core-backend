"""Reports: PDF, JSON and DOCX files only, once the assessment is complete."""

import json
import re
import zipfile

import pytest

from reconix import store
from reconix.models.scope import PolicyVerdict
from reconix.store import lists, report
from reconix.store.report_docx import write_docx
from reconix.store.report_html import render_html
from reconix.store.templates import network

from .fakes.fake_api import finding_row
from .support import DEMO_REQUEST, TEST_PASSWORD, add_finding, decide, play_until_gate, run_to


@pytest.fixture(autouse=True)
def api_findings(fake_api):
    """What the fake API's Kali finds in this file's runs: one finding per tool, as the API
    returns them (evidence already masked)."""
    fake_api.findings_for = {
        "NMAP": [finding_row("NMAP-OPEN-PORT", "Open port 3000/tcp (http)", "{target}:3000",
                             "LOW", "NMAP", evidence="3000/tcp open http")],
        "NUCLEI": [dict(finding_row("NUCLEI-EXPOSED-PANEL", "Exposed admin panel", "{target}",
                                    "MEDIUM", "NUCLEI",
                                    evidence="Set-Cookie: session=•••• (masked)"),
                        cvss_score=6.5, cwe_ids=["CWE-284"], owasp_id=["OWASP A01:2021"])],
        "SQLMAP": [dict(finding_row("SQLMAP-SQLI", "SQL injection in login", "{target}login",
                                    "HIGH", "SQLMAP", evidence="parameter 'user' is injectable"),
                        cvss_score=8.6, cwe_ids=["CWE-89"])],
    }
    return fake_api


def _to_medium_approval() -> None:
    run_to("plan")
    decide("plan")
    assert play_until_gate().startswith("approval:")

# What XML 1.0 can't hold (tab, LF and CR are fine)
CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")


def test_no_report_before_the_assessment_is_complete():
    _to_medium_approval()
    with pytest.raises(store.StoreValidationError):
        store.generate_report("json")


def test_report_formats_and_their_availability():
    run_to(None)
    formats = {f.id: f.available for f in store.list_report_formats()}
    assert list(formats) == ["pdf", "json", "docx"]   # nothing else is saved (no HTML, CSV…)
    assert formats["json"]
    assert formats["pdf"] == report.HAS_PDF      # PDF only with WeasyPrint or a Chrome
    assert formats["docx"] == report.HAS_DOCX    # DOCX only when python-docx is installed
    for fid, available in formats.items():
        if not available:
            with pytest.raises(store.StoreValidationError):
                store.generate_report(fid)
    for gone in ("nope", "html", "markdown", "csv", "sarif"):
        with pytest.raises(store.StoreValidationError):
            store.generate_report(gone)


@pytest.mark.skipif(not report.HAS_PDF, reason="no PDF engine (WeasyPrint or Chrome) available")
def test_pdf_report_is_the_styled_report_as_a_pdf(reports_dir):
    run_to(None)
    shown = store.generate_report("pdf")
    path = reports_dir / "RCX-001.pdf"
    assert shown == str(path)
    assert path.read_bytes()[:5] == b"%PDF-"


def test_silence_fds_hides_c_level_writes_then_restores(capfd):
    """A raw write to fd 2 inside the block (as Pango/Fontconfig do) is dropped, and fds
    1 and 2 work again after it — so a report export can't corrupt the TUI screen."""
    import os

    from reconix.store.report_pdf import _silence_fds

    with _silence_fds():
        os.write(2, b"fontconfig error: should vanish\n")
    os.write(2, b"visible-again\n")
    err = capfd.readouterr().err
    assert "fontconfig" not in err
    assert "visible-again" in err


@pytest.mark.skipif(not report.HAS_DOCX, reason="python-docx not installed")
def test_docx_report_is_written_as_a_binary_file(reports_dir):
    run_to(None)
    shown = store.generate_report("docx")
    path = reports_dir / "RCX-001.docx"
    assert shown == str(path)
    assert path.read_bytes()[:2] == b"PK"        # a .docx is a zip archive


def _docx_text(path) -> str:
    with zipfile.ZipFile(path) as docx:
        return docx.read("word/document.xml").decode("utf-8")


def test_json_report_is_written_and_recorded(reports_dir):
    run_to(None)
    shown = store.generate_report("json")
    path = reports_dir / "RCX-001.json"
    assert shown == str(path)
    data = json.loads(path.read_text())
    assert data["assessment_id"] == "RCX-001"
    assert sorted(f["id"] for f in data["findings"]) == ["001", "002", "003"]
    assert data["blocked_requests"] == []                  # the API blocked nothing here
    assert [a["risk"] for a in data["approvals"]] == ["MEDIUM", "HIGH"]
    assert store.get_run().report_path == shown
    assert store.phase_progress()["report"] == 100
    assert store.list_events()[-1].kind == "report.generated"


def _docx_parts(path):
    """The paragraphs (style, text) and the tables (rows of cell texts) of a .docx file."""
    import docx

    doc = docx.Document(str(path))
    paragraphs = [(p.style.name, p.text) for p in doc.paragraphs if p.text.strip()]
    tables = [[[cell.text for cell in row.cells] for row in table.rows] for table in doc.tables]
    return paragraphs, tables


@pytest.mark.skipif(not report.HAS_DOCX, reason="python-docx not installed")
def test_docx_report_has_every_section(reports_dir, monkeypatch):
    """The Word report follows the PDF: its sections, order, headings and content."""
    run_to(None)
    monkeypatch.setattr(lists.current().findings[0], "severity", "CRITICAL")   # 001 first
    store.triage_finding("002", note="Retested: the panel needs a login now.")
    store.generate_report("docx")
    paragraphs, tables = _docx_parts(reports_dir / "RCX-001.docx")
    headings = [text for style, text in paragraphs if style.startswith("Heading")]
    assert headings[:5] == ["1 Executive summary", "2 Findings summary",
                            "3 Approved scope & limitations", "4 Detailed findings",
                            "001 · Open port 3000/tcp (http)"]     # worst first
    assert [h for h in headings if h[0].isdigit() and " · " in h] == [
        "001 · Open port 3000/tcp (http)", "003 · SQL injection in login",
        "002 · Exposed admin panel"]
    assert headings[-1] == "Human approvals · 2"
    html = render_html(store.report_data())                 # the PDF has the same headings
    for heading in ("Executive summary", "Findings summary", "Approved scope &amp; limitations",
                    "Detailed findings", "Policy &amp; governance"):
        assert f"<h2>{heading}</h2>" in html
    text = "\n".join(t for _s, t in paragraphs)
    assert "The highest severity is Critical, led by Open port 3000/tcp (http)" in text
    assert "Retested: the panel needs a login now." in text                # the analyst's note
    assert "Testing was limited to the approved actions" in text            # the disclaimer
    assert "References: CWE-284, OWASP A01:2021" in text
    assert "CONFIDENTIAL — AUTHORIZED RECIPIENTS ONLY" in text
    summary = next(t for t in tables if t[0] == ["ID", "Finding", "Severity", "CVSS", "Status",
                                                  "Category"])
    assert [row[0] for row in summary[1:]] == ["001", "003", "002"]
    scope = dict(next(t for t in tables if t[0][0] == "Approval status"))
    assert scope["Approval status"] == "Approved" and scope["Excluded paths"] == "/admin"
    assert scope["Standards"] == "Guided by OWASP WSTG · OWASP Top 10 (2025)"
    approvals = next(t for t in tables if t[0][0] == "Risk")
    assert [row[0] for row in approvals[1:]] == ["Medium", "High"]
    assert "•••" in _docx_text(reports_dir / "RCX-001.docx")      # evidence stays masked


@pytest.mark.skipif(not report.HAS_DOCX, reason="python-docx not installed")
def test_control_characters_never_stop_the_docx_report(reports_dir, tmp_path):
    """An agent finding and a blocked request holding ESC / NUL: the report is still
    written, and none of those characters reaches it (or the JSON)."""
    run_to(None)
    add_finding("Banner \u001b[31mred\u001b[0m\u0000 leak", "/\u001b[2J",
                description="NUL \u0000 and BEL \u0007 here",
                evidence=["Server: \u001b[2Jnginx\u0000"])
    lists.current().verdicts.append(
        PolicyVerdict("GET", "/a\x00b", False, "Path \x1b[1moutside\x00 approved scope"))
    store.generate_report("docx")
    store.generate_report("json")
    xml = _docx_text(reports_dir / "RCX-001.docx")
    # each escape sequence is a space: no "[31m" left, no two words glued together
    assert re.search(r"Banner\s+red\s+leak", xml) and re.search(r"Path\s+outside\s+approved", xml)
    assert "[31m" not in xml and "[1m" not in xml
    assert not CONTROL.search(xml)
    assert not CONTROL.search((reports_dir / "RCX-001.json").read_text("utf-8"))


@pytest.mark.skipif(not report.HAS_DOCX, reason="python-docx not installed")
def test_a_value_the_docx_cannot_hold_is_the_stores_verdict(tmp_path):
    run_to(None)
    data = store.report_data()
    data["findings"][0]["title"] = "bad \x1b title"            # past report_data's cleaning
    with pytest.raises(store.StoreValidationError):
        write_docx(data, tmp_path / "x.docx")


def test_report_data_carries_cvss_category_and_engagement_metadata():
    run_to(None)
    data = store.report_data()
    assert data["client"] == "Example"                   # derived from staging.example.com
    assert data["mode"] == "Grey-box, Authorized"
    assert data["methodology"] == ["Guided by OWASP WSTG", "OWASP Top 10 (2025)"]
    assert data["window"]["started"] and data["window"]["finished"]
    panel = next(f for f in data["findings"] if f["id"] == "002")
    assert panel["cvss_score"] == 6.5                    # as the API scored it
    assert panel["category"] == "NUCLEI-EXPOSED-PANEL"   # the API's finding code
    assert panel["cwe"] == ["CWE-284"]
    assert panel["owasp"] == ["OWASP A01:2021"]


def test_the_html_the_pdf_prints_is_a_full_styled_document():
    run_to(None)
    text = render_html(store.report_data())
    assert text.startswith("<!doctype html>")
    assert "Security Assessment Report" in text          # masthead title
    assert "RCX-001" in text                         # engagement id
    assert "Exposed admin panel" in text                 # a finding from the API
    assert "Executive summary" in text and "Detailed findings" in text
    assert "CVSS 6.5" in text                             # CVSS on the finding
    assert "OWASP WSTG" in text and "Example" in text     # methodology + client cover
    assert "•••" in text                                  # evidence stays masked


def test_the_html_the_pdf_prints_escapes_dynamic_text(monkeypatch):
    run_to(None)
    finding = lists.current().findings[0]        # the live row: list_findings() copies
    monkeypatch.setattr(finding, "description", '<script>alert("x")</script>')
    text = render_html(store.report_data())
    assert "<script>alert" not in text                    # injected markup is escaped
    assert "&lt;script&gt;" in text


def test_reports_never_contain_the_test_account(reports_dir):
    run_to(None)
    store.generate_report("json")
    texts = [(reports_dir / "RCX-001.json").read_text(), render_html(store.report_data())]
    if report.HAS_DOCX:
        store.generate_report("docx")
        texts.append(_docx_text(reports_dir / "RCX-001.docx"))
    for text in texts:
        assert TEST_PASSWORD not in text
        assert "demo.tester" not in text


@pytest.mark.parametrize("request_text", [
    DEMO_REQUEST,
    "test the API at https://api.example.com/v1",
])
def test_no_report_format_contains_the_login(reports_dir, request_text):
    run_to(None, request_text)
    formats = ["json"]
    if report.HAS_DOCX:
        formats.append("docx")
    for format_id in formats:
        store.generate_report(format_id)
    for path in reports_dir.iterdir():
        text = _docx_text(path) if path.suffix == ".docx" else path.read_text()
        assert TEST_PASSWORD not in text, path.name
        assert "demo.tester" not in text, path.name
    html = render_html(store.report_data())                   # what the PDF prints
    assert TEST_PASSWORD not in html and "demo.tester" not in html


def test_a_triage_note_is_masked_in_the_report():
    run_to(None)
    store.triage_finding("002", note=f"retested with password={TEST_PASSWORD}")
    note = next(f for f in store.report_data()["findings"] if f["id"] == "002")["triage_note"]
    assert note.startswith("retested with")
    assert TEST_PASSWORD not in note


def test_a_network_report_lists_the_approved_ports(reports_dir):
    run_to(None, "port scan 192.0.2.10")
    scope = store.report_data()["scope"]
    assert scope["kind"] == "network"
    assert scope["allowed_ports"] == network.ALLOWED_PORTS
    assert "<dt>Allowed ports</dt>" in render_html(store.report_data())
    if report.HAS_DOCX:
        store.generate_report("docx")
        text = _docx_text(reports_dir / "RCX-001.docx")
        assert "Allowed ports" in text and "21, 22, 23, 25, 53, 80" in text


def test_a_web_report_has_no_ports_line(reports_dir):
    run_to(None)
    assert store.report_data()["scope"]["allowed_ports"] == []
    assert "Allowed ports" not in render_html(store.report_data())
    if report.HAS_DOCX:
        store.generate_report("docx")
        assert "Allowed ports" not in _docx_text(reports_dir / "RCX-001.docx")


def test_summary_counts_every_human_approval():
    run_to(None)
    summary = store.assessment_summary()
    assert summary.status == "Completed"
    assert summary.approvals == ["scope", "MEDIUM", "HIGH"]
    assert (summary.blocked, summary.confirmed, summary.for_review) == (0, 0, 3)


def test_report_dates_use_the_laptop_local_timezone(monkeypatch):
    """Times are stored UTC; the report shows them in the laptop's local zone, labelled so
    they can't be misread. The operator cannot edit a recorded scan time."""
    import os
    import time

    from reconix.store import report_view

    os.environ["TZ"] = "Asia/Bangkok"  # UTC+7
    time.tzset()
    try:
        # a UTC evening is the next local day for UTC+7
        assert report_view.short_date("2026-11-05T19:30:00+00:00") == "2026-11-06"
        assert report_view.short_date("2026-11-05T05:30:00+00:00") == "2026-11-05"
        assert report_view.tz_label() == "UTC+07:00"
    finally:
        del os.environ["TZ"]
        time.tzset()


def test_the_report_reads_the_evidence_in_plain_language(reports_dir):
    """The client report shows the AI's plain reading of the evidence and a validation
    sentence (HTML and DOCX), so a reader sees prose, not a JSON blob. The JSON->lines
    humanizing is the adapter's job and is tested there."""
    run_to(None)
    add_finding(
        "Reflected XSS", "/search", severity="HIGH",
        evidence=["Matched at: http://lab/search?q=x", "Template id: reflected-xss"],
        evidence_summary="The q parameter is reflected unescaped, so a script runs.",
        validation="CONFIRMED", validation_reason="dalfox replayed it and it executed.",
        validation_method="dalfox",
    )

    html = render_html(store.report_data())

    assert "The q parameter is reflected unescaped" in html       # the AI's plain reading
    assert 'class="evidence-summary"' in html
    assert "Confirmed during the run by dalfox" in html           # the validation sentence
    assert "dalfox replayed it and it executed." in html
    assert "Matched at: http://lab/search?q=x" in html            # the readable proof line
