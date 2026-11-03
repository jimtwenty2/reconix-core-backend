import json
from pathlib import Path

import pytest

from reconix_api.parsers.sarif import SarifParseError, parse

# Real ZAP report (zap_report, sarif-json) from a lab host; its secrets are fake.
ZAP = (Path(__file__).parents[2] / "fixtures" / "zap" / "lab_fake_secrets.sarif.json").read_text()


def sarif(results: list, rules: list | None = None) -> str:
    run = {"tool": {"driver": {"name": "t", "rules": rules or []}}, "results": results}
    return json.dumps({"version": "2.1.0", "runs": [run]})


def test_zap_results_are_read_with_their_rules():
    results = parse(ZAP)
    assert len(results) == 7
    clickjacking = next(r for r in results if r.rule_id == "10020")
    assert clickjacking.title == "Missing Anti-clickjacking Header"
    assert clickjacking.level == "warning"
    assert clickjacking.uri == "http://172.23.0.3/"
    assert clickjacking.cwe_ids == ["CWE-1021"]
    assert clickjacking.remediation.startswith("Modern Web browsers support")


def test_request_and_response_bodies_are_not_kept_as_proof():
    for result in parse(ZAP):
        assert "webRequest" not in result.proof and "webResponse" not in result.proof


def test_a_semgrep_style_rule_gives_cwe_from_tags_and_a_line():
    rules = [
        {
            "id": "py.sqli",
            "shortDescription": {"text": "SQL injection"},
            "properties": {"tags": ["CWE-89: SQL Injection"], "security-severity": "8.1"},
        }
    ]
    location = {
        "physicalLocation": {"artifactLocation": {"uri": "app.py"}, "region": {"startLine": 12}}
    }
    [result] = parse(
        sarif([{"ruleId": "py.sqli", "message": {"text": "x"}, "locations": [location]}], rules)
    )
    assert (result.title, result.uri, result.line) == ("SQL injection", "app.py", 12)
    assert result.cwe_ids == ["CWE-89"]
    assert result.security_severity == 8.1


def test_a_result_without_its_rule_still_reads():
    [result] = parse(sarif([{"ruleId": "orphan", "level": "note", "message": "plain string"}]))
    assert (result.title, result.message, result.level, result.uri) == (
        "orphan",
        "plain string",
        "note",
        "",
    )


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "not json", "[]", '{"version": "2.1.0"}', "ZAP report written to /tmp/x.json"],
)
def test_output_that_is_not_sarif_is_refused(raw):
    with pytest.raises(SarifParseError):
        parse(raw)
