import json
import re
from pathlib import Path

import pytest

from reconix_ai.harness import mask_secrets
from reconix_api.core.masking import mask_output
from reconix_api.findings.sarif import read, severity
from reconix_api.findings.shape import OutputUnreadable
from reconix_api.models.enums import SeverityStatus
from reconix_api.parsers.sarif import SarifResult
from reconix_api.services.findings import parse_run

ZAP = (Path(__file__).parents[2] / "fixtures" / "zap" / "lab_fake_secrets.sarif.json").read_text()


def result(level: str = "warning", score: float | None = None) -> SarifResult:
    return SarifResult("r", "t", "m", None, None, level, score, "u", None)


def test_the_zap_report_becomes_findings_by_zap_risk():
    masked, _ = mask_output(mask_secrets, ZAP)  # as it is saved before parsing
    findings, requests = parse_run("ZAP", masked)
    by_title = {f.title: f.severity for f in findings}
    assert len(findings) == 7 and requests == 0
    assert by_title["Missing Anti-clickjacking Header"] == SeverityStatus.MEDIUM
    assert by_title["Cookie No HttpOnly Flag"] == SeverityStatus.LOW
    assert by_title["Session Management Response Identified"] == SeverityStatus.NONE
    assert all(f.evidence[0].kind == "zap_alert" for f in findings)
    assert len({f.dedupe_key for f in findings}) == 7


def test_zap_findings_keep_no_secret_from_the_host():
    masked, _ = mask_output(mask_secrets, ZAP)
    findings, _ = parse_run("ZAP", masked)
    text = json.dumps([[f.description, f.remediation, f.evidence[0].content] for f in findings])
    assert re.findall(r"FAKE\w*", text) == []


def test_the_same_alert_found_again_has_the_same_key():
    first, _ = read("zap_alert", ZAP)
    again, _ = read("zap_alert", ZAP)
    assert [f.dedupe_key for f in first] == [f.dedupe_key for f in again]


@pytest.mark.parametrize(
    ("level", "score", "expected"),
    [
        ("error", None, SeverityStatus.HIGH),
        ("warning", None, SeverityStatus.MEDIUM),
        ("note", None, SeverityStatus.LOW),
        ("none", None, SeverityStatus.NONE),
        ("odd", None, SeverityStatus.UNKNOWN),
        ("note", 9.8, SeverityStatus.CRITICAL),
        ("note", 7.0, SeverityStatus.HIGH),
        ("error", 0.0, SeverityStatus.NONE),
    ],
)
def test_severity_prefers_the_tools_score_then_the_level(level, score, expected):
    assert severity(result(level, score)) == expected


def test_zaps_text_summary_is_unreadable_not_silently_empty():
    with pytest.raises(OutputUnreadable):
        read("zap_alert", "Spider: 3 URL(s) discovered\n\nAlerts (7):\n...")
