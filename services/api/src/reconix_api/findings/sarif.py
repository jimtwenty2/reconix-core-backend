"""SARIF results -> findings. One finding per rule and location.

Severity comes from the tool's own score (security-severity, 0-10) when it gives one, else
from the result's level. A level SARIF does not define is UNKNOWN: never guessed.
"""

import json

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.models.enums import SeverityStatus
from reconix_api.parsers.sarif import SarifParseError, SarifResult, parse

LEVELS = {
    "error": SeverityStatus.HIGH,
    "warning": SeverityStatus.MEDIUM,
    "note": SeverityStatus.LOW,
    "none": SeverityStatus.NONE,  # e.g. ZAP's Informational
}
# security-severity (CVSS-like) -> severity, highest first
SCORES = [
    (9.0, SeverityStatus.CRITICAL),
    (7.0, SeverityStatus.HIGH),
    (4.0, SeverityStatus.MEDIUM),
    (0.1, SeverityStatus.LOW),
]


def read(kind: str, output: str) -> tuple[list[NewFinding], int]:
    """Masked SARIF -> (findings, requests sent). SARIF does not report requests: 0.
    kind names the evidence and starts the dedupe key, e.g. zap_alert."""
    try:
        results = parse(output)
    except SarifParseError as error:
        raise OutputUnreadable(str(error)) from error
    return [_finding(kind, result) for result in results], 0


def _finding(kind: str, result: SarifResult) -> NewFinding:
    location = f"{result.uri}:{result.line}" if result.line and result.line > 1 else result.uri
    return NewFinding(
        title=result.title,
        target=result.uri or result.rule_id,
        description=result.description or result.message or f"{result.title} at {location}.",
        severity=severity(result),
        dedupe_key=dedupe_key(kind, result.rule_id, result.uri, str(result.line or "")),
        evidence=[
            NewEvidence(
                kind=kind,
                content=json.dumps(result.proof, sort_keys=True, default=str),
                location=location,
            )
        ],
        cwe_ids=result.cwe_ids,
        remediation=result.remediation,
    )


def severity(result: SarifResult) -> SeverityStatus:
    if result.security_severity is not None:
        for floor, level in SCORES:
            if result.security_severity >= floor:
                return level
        return SeverityStatus.NONE
    return LEVELS.get(result.level, SeverityStatus.UNKNOWN)
