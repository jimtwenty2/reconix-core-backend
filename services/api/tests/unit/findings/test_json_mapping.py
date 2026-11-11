import json
from pathlib import Path

import pytest

from reconix_ai.harness import mask_secrets
from reconix_api.core.masking import mask_output
from reconix_api.findings.json_mapping import MAPPINGS, read
from reconix_api.findings.shape import OutputUnreadable
from reconix_api.models.enums import SeverityStatus

FIXTURES = Path(__file__).parents[2] / "fixtures"
KALI_REPO = "/tmp/testrepo"  # noqa: S108 - the test project inside the Kali container


def findings_of(tool: str, sample: str):
    found, requests = read(MAPPINGS[tool], (FIXTURES / tool / sample).read_text())
    assert requests == 0
    return found


def test_nuclei_one_finding_per_match():
    header, sqli, odd = findings_of("nuclei", "juice_shop.jsonl")
    assert sqli.title == "SQL Injection in Login"
    assert sqli.target == "http://juice-shop:3000"
    assert sqli.severity == SeverityStatus.CRITICAL
    assert sqli.cwe_ids == ["CWE-89"]
    assert sqli.cve_ids == []
    assert sqli.remediation == "Use parameterized queries."
    assert sqli.evidence[0].location == "http://juice-shop:3000/rest/user/login"
    assert header.severity == SeverityStatus.NONE  # nuclei "info"
    assert odd.severity == SeverityStatus.UNKNOWN  # never guessed


def test_semgrep_maps_severity_and_cwe():
    sql, unclosed = findings_of("semgrep", "vulnerable_app.json")
    assert sql.title == "python.lang.security.audit.formatted-sql-query"
    assert sql.description == "SQL query built from user input."
    assert sql.severity == SeverityStatus.HIGH
    assert sql.cwe_ids == ["CWE-89"]
    assert sql.evidence[0].location == "app/db.py:12"
    assert unclosed.severity == SeverityStatus.MEDIUM


def test_gitleaks_never_keeps_the_secret():
    [leak] = findings_of("gitleaks", "vulnerable_app.json")
    assert leak.title == "AWS Access Key"
    assert leak.target == "config/settings.py"
    assert leak.severity == SeverityStatus.HIGH  # gitleaks gives none; a leak is HIGH
    assert leak.evidence[0].location == "config/settings.py:4"
    for text in (leak.title, leak.description, leak.evidence[0].content):
        assert "AKIAFAKEFAKEFAKE0000" not in text


def test_trivy_reads_nested_results():
    flask, jinja = findings_of("trivy", "vulnerable_app.json")
    assert flask.title == "flask: session cookie disclosure"
    assert flask.severity == SeverityStatus.HIGH
    assert flask.cve_ids == ["CVE-2023-30861"]
    assert flask.cwe_ids == ["CWE-539"]
    assert flask.evidence[0].location == "flask:2.2.0"
    assert jinja.severity == SeverityStatus.UNKNOWN
    assert jinja.cve_ids == []  # a GHSA id is not a CVE


def test_same_result_gives_the_same_dedupe_key():
    first = findings_of("semgrep", "vulnerable_app.json")
    again = findings_of("semgrep", "vulnerable_app.json")
    assert [f.dedupe_key for f in first] == [f.dedupe_key for f in again]
    assert len({f.dedupe_key for f in first}) == 2


@pytest.mark.parametrize("tool", sorted(MAPPINGS))
def test_broken_output_is_unreadable(tool):
    with pytest.raises(OutputUnreadable):
        read(MAPPINGS[tool], "")


# Real output from the Kali container (lab only; gitleaks already redacts its secrets).


def test_real_nuclei_one_finding_per_missing_header():
    found = findings_of("nuclei", "kali_self_scan.jsonl")
    headers = [f for f in found if f.title.startswith("HTTP Missing Security Headers")]
    assert len(headers) == 10
    assert "HTTP Missing Security Headers (x-frame-options)" in {f.title for f in headers}
    assert len({f.dedupe_key for f in found}) == len(found)  # none merged by mistake


def test_nuclei_reader_groups_repeated_info_matches():
    # The raw mapping keeps one finding per match; the registered reader (read_nuclei)
    # collapses the 10 missing-header matches of one template into a single finding.
    from reconix_api.services.findings import parse_run

    found, _ = parse_run("nuclei", (FIXTURES / "nuclei" / "kali_self_scan.jsonl").read_text())
    headers = [f for f in found if f.title.startswith("HTTP Missing Security Headers")]
    assert len(headers) == 1
    assert len(headers[0].evidence) == 10  # the 10 matchers kept as evidence
    assert headers[0].severity == SeverityStatus.NONE


def test_real_nuclei_evidence_leaves_out_request_and_response():
    [first, *_] = findings_of("nuclei", "kali_self_scan.jsonl")
    proof = json.loads(first.evidence[0].content)
    assert not {"request", "response", "curl-command"} & proof.keys()
    assert proof["matched-at"] == "http://172.20.0.2:8096"


def test_real_semgrep():
    found = findings_of("semgrep", "kali_testrepo.json")
    assert len(found) == 4
    assert {f.cwe_ids[0] for f in found} == {"CWE-89", "CWE-78", "CWE-798"}
    assert found[0].evidence[0].location == f"{KALI_REPO}/app/db.py:8"


def test_real_gitleaks_still_reads_after_masking():
    raw = (FIXTURES / "gitleaks" / "kali_testrepo.json").read_text()
    masked, _ = mask_output(mask_secrets, raw)
    found, _ = read(MAPPINGS["gitleaks"], masked)
    assert [f.target for f in found] == [f"{KALI_REPO}/config/settings.py"] * 2
    for finding in found:
        proof = json.loads(finding.evidence[0].content)
        assert not {"Secret", "Match", "Line"} & proof.keys()
