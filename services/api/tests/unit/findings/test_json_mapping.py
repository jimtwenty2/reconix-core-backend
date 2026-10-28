from pathlib import Path

import pytest

from reconix_api.findings.json_mapping import MAPPINGS, read
from reconix_api.findings.shape import OutputUnreadable
from reconix_api.models.enums import SeverityStatus
from reconix_api.services.findings import parse_run

FIXTURES = Path(__file__).parents[2] / "fixtures"


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
    assert leak.severity == SeverityStatus.UNKNOWN
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


def test_parse_run_picks_the_reader_by_tool_name():
    output = (FIXTURES / "nuclei" / "juice_shop.jsonl").read_text()
    found, _ = parse_run("NUCLEI", output)
    assert len(found) == 3


def test_tool_without_a_reader_gives_no_findings():
    assert parse_run("whatweb", "anything") == ([], 0)
