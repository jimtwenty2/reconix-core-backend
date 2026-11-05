"""Analyst triage: the finding status lifecycle and severity override."""

import pytest

from reconix import store

from .support import run_to


def test_findings_start_open():
    run_to(None)
    assert [f.status for f in store.list_findings()] == ["open", "open"]


def test_triage_sets_status_note_and_audits(fake_api):
    run_to(None)
    finding = store.triage_finding("002", status="fixed", note="patched in build 1823")
    assert finding.status == "fixed"
    finding_id = store.get_assessment().live.finding_ids["002"]
    assert fake_api.findings[finding_id]["finding_status"] == "FIXED"   # the API has it
    assert finding.triage_note == "patched in build 1823"
    assert store.get_finding("002").status == "fixed"
    assert store.list_events()[-1].kind == "finding.triaged"


def test_severity_override_drives_effective_severity():
    run_to(None)
    finding = store.triage_finding("001", severity="HIGH")   # 001 is detected LOW
    assert finding.severity == "LOW"                         # the detected value is kept
    assert finding.severity_override == "HIGH"
    assert finding.effective_severity == "HIGH"


def test_override_matching_detected_severity_clears_it():
    run_to(None)
    finding = store.triage_finding("002", severity="MEDIUM")   # 002 is already MEDIUM
    assert finding.severity_override == ""
    assert finding.effective_severity == "MEDIUM"


def test_unknown_status_or_severity_is_rejected():
    run_to(None)
    with pytest.raises(store.StoreValidationError):
        store.triage_finding("001", status="nope")
    with pytest.raises(store.StoreValidationError):
        store.triage_finding("001", severity="SUPER")


def test_triage_appears_in_report_data():
    run_to(None)
    store.triage_finding("002", status="accepted", note="risk accepted by the owner")
    row = next(f for f in store.report_data()["findings"] if f["id"] == "002")
    assert row["status"] == "accepted"
    assert row["triage_note"] == "risk accepted by the owner"


def test_accepted_stays_on_this_computer(fake_api):
    """The API has no "accepted" status yet: the decision is kept here only."""
    run_to(None)
    store.triage_finding("002", status="accepted")
    assert store.get_finding("002").status == "accepted"
    assert fake_api.bodies("PATCH", "/findings/") == []


def test_a_triage_the_api_refuses_changes_nothing(fake_api):
    run_to(None)
    fake_api.fail_on["PATCH /findings/"] = (409, "FINDING_LOCKED", "the report was signed off")
    with pytest.raises(store.StoreValidationError, match="kept the finding as it was"):
        store.triage_finding("002", status="false-positive")
    assert store.get_finding("002").status == "open"
