"""testssl.sh text output -> TLS findings.

testssl marks each line with its own verdict in parentheses or words: "(OK)" is fine and
makes no finding; "NOT ok" and "VULNERABLE" are problems. We never invent a severity:
a line is CRITICAL/HIGH/MEDIUM/LOW only when testssl's own rating word says so; a clear
problem with no rating is UNKNOWN; everything marked OK is dropped.

Two kinds of line are read:
- a protocol offered that testssl calls "deprecated" (TLS 1, TLS 1.1) -> MEDIUM;
- a "Testing vulnerabilities" line whose verdict is VULNERABLE -> by testssl's rating,
  else UNKNOWN; its CVE is kept.
A certificate line marked "NOT ok" (self-signed, expired, missing SAN) -> LOW.

Limit: testssl reads each line on its own. A verdict testssl wraps onto a second line
(e.g. BEAST's "VULNERABLE" below its cipher list) is attributed to that second line, not
to the labelled line with the CVE. Single-line verdicts (LUCKY13, protocol and cert
lines) are read correctly.
"""

import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.findings.text import cves, lines, title
from reconix_api.models.enums import SeverityStatus

# testssl's own rating words (seen in the line), mapped to our severity.
RATING = {
    "CRITICAL": SeverityStatus.CRITICAL,
    "HIGH": SeverityStatus.HIGH,
    "MEDIUM": SeverityStatus.MEDIUM,
    "LOW": SeverityStatus.LOW,
}
CERT_HINTS = ("self signed", "self-signed", "expired", "subjectaltname", "chain of trust")
# A line's leading label, e.g. "BEAST (CVE-2011-3389)" or "SSLv3".
LABEL = re.compile(r"^\s*([A-Za-z0-9 ._/+()-]+?)\s{2,}")


def read(output: str) -> tuple[list[NewFinding], int]:
    rows = lines(output)
    if not any("testssl" in row.lower() or "Start " in row for row in rows):
        raise OutputUnreadable("not testssl output")
    target = _target(rows)
    findings = []
    for row in rows:
        finding = _row(row, target)
        if finding is not None:
            findings.append(finding)
    return findings, 0


def _target(rows: list[str]) -> str:
    for row in rows:
        match = re.search(r"-->>\s*(\S+)", row)
        if match:
            return match.group(1)
    return "the TLS service"


def _row(row: str, target: str) -> NewFinding | None:
    low = row.lower()
    if "(ok)" in low or low.endswith("ok") and "not ok" not in low:
        return None
    if "offered" in low and "deprecated" in low:
        return _finding(
            row,
            target,
            _label(row),
            SeverityStatus.MEDIUM,
            "weak_protocol",
            "A deprecated TLS protocol is offered.",
        )
    if "vulnerable" in low and "not vulnerable" not in low:
        return _finding(
            row,
            target,
            _label(row),
            _rating(row, SeverityStatus.UNKNOWN),
            "tls_vulnerability",
            "testssl reported a TLS vulnerability.",
        )
    if "not ok" in low and any(hint in low for hint in CERT_HINTS):
        return _finding(
            row,
            target,
            _label(row),
            SeverityStatus.LOW,
            "cert_problem",
            "A certificate problem was reported.",
        )
    return None


def _label(row: str) -> str:
    match = LABEL.match(row)
    return (match.group(1) if match else row).strip()


def _rating(row: str, default: SeverityStatus) -> SeverityStatus:
    for word, severity in RATING.items():
        if re.search(rf"\b{word}\b", row):
            return severity
    return default


def _finding(
    row: str, target: str, label: str, severity: SeverityStatus, kind: str, summary: str
) -> NewFinding:
    return NewFinding(
        title=title(f"TLS: {label}"),
        target=target,
        description=f"{summary} testssl line: {label}.",
        severity=severity,
        dedupe_key=dedupe_key("testssl", target, kind, label.lower()),
        evidence=[NewEvidence(kind="testssl_line", content=row.strip(), location=target)],
        cve_ids=cves(row),
        owasp_id=["A02:2021"],
        remediation="Disable weak protocols and ciphers; fix the certificate chain.",
    )
