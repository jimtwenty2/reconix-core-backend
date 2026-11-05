"""The report's two safety rules: the preview masks what the exports mask, and a failed export
never breaks the report already saved (nor leaves a temp file behind)."""

import pytest

from reconix import store
from reconix.screens.report import key_finding_rows
from reconix.store import report

from .support import TEST_PASSWORD, add_finding, run_to

SECRET_TITLE = f"Login form echoes password={TEST_PASSWORD}"
SECRET_TOOL = f"https://demo.tester:{TEST_PASSWORD}@tool.example.com"


def test_key_findings_rows_never_show_a_secret_from_a_title_or_tool():
    run_to(None)
    add_finding(SECRET_TITLE, severity="CRITICAL")            # most severe: a key finding
    store.list_findings()[-1].tool = SECRET_TOOL
    shown = " ".join(str(cell) for row in key_finding_rows() for cell in row)
    assert "Login form echoes password=" in shown              # the row is there, masked
    assert TEST_PASSWORD not in shown


def _broken_writer(reports_dir):
    def broken(data, path):
        with open(path, "wb") as out:                       # half a file, then a crash
            out.write(b"PK\x03\x04 partial")
        raise RuntimeError(f"disk full at {reports_dir}")   # internal detail, never shown
    return broken


def _refused_and_untouched(reports_dir, fmt: str) -> None:
    saved = reports_dir / f"RCX-001.{fmt}"
    before = saved.read_bytes()
    with pytest.raises(store.StoreValidationError) as refused:
        store.generate_report(fmt)
    assert str(refused.value) == f"Couldn't save the {fmt.upper()} report."
    assert saved.read_bytes() == before
    assert [p.name for p in reports_dir.iterdir()] == [saved.name]   # no temp file left


@pytest.mark.skipif(not report.HAS_DOCX, reason="needs python-docx")
def test_a_docx_export_failing_midway_keeps_the_saved_report(reports_dir, monkeypatch):
    run_to(None)
    store.generate_report("docx")
    monkeypatch.setattr(report, "write_docx", _broken_writer(reports_dir))
    _refused_and_untouched(reports_dir, "docx")


def test_a_failed_json_export_keeps_the_saved_report(reports_dir, monkeypatch):
    run_to(None)
    store.generate_report("json")

    def broken(data):
        raise RuntimeError(f"disk full at {reports_dir}")

    monkeypatch.setattr(report, "_render_json", broken)
    _refused_and_untouched(reports_dir, "json")
