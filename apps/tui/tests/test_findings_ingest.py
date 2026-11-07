"""Findings added from outside the API run: the API's six severities only, no repeats."""

from reconix import store
from reconix.models import Finding
from reconix.store.findings import ingest_external

from .support import add_finding, run_to


def _finding(severity: str, title: str = "T") -> Finding:
    return Finding(fid="", severity=severity, title=title, path="/p", validation="UNCONFIRMED",
                   confidence="TENTATIVE",
                   description="", affected_url="/p", impact="", remediation="", tool="agent")


def test_only_the_apis_severities_are_stored():
    run_to(None)
    before = len(store.list_findings())
    added = ingest_external([_finding("INFO", "a"), _finding("", "b"), _finding("BOGUS", "c"),
                             _finding("HIGH", "d")], prefix="AI")
    assert added == 1
    assert len(store.list_findings()) == before + 1
    assert store.severity_counts()["HIGH"] == 1
    assert set(store.severity_counts()) == {"CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE",
                                            "UNKNOWN"}


def test_a_repeat_is_not_added_twice():
    run_to(None)
    add_finding("Same title", "/x")
    add_finding("Same title", "/x")
    ids = [f.fid for f in store.list_findings()]
    assert ids.count("AI-001") == 1 and "AI-002" not in ids
