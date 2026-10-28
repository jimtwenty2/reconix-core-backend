"""JSON tool results -> findings, through one mapping per tool.

A mapping says where each finding field is in one result. Adding a JSON tool is adding
a mapping here, plus a sample output and a test. A severity the tool does not give, or
one the mapping does not know, is UNKNOWN: never guessed.
"""

import json
import re
from dataclasses import dataclass, field
from typing import Any

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.models.enums import SeverityStatus
from reconix_api.parsers.json_report import JsonParseError, get, parse

CWE = re.compile(r"CWE-\d+", re.IGNORECASE)
CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


@dataclass(frozen=True)
class JsonMapping:
    kind: str  # e.g. nuclei_match; the evidence kind and the start of the dedupe key
    title: str  # paths into one result, e.g. "info.name"
    target: str
    location: tuple[str, ...]  # joined with ":", e.g. ("path", "start.line")
    key: tuple[str, ...]  # what makes two results the same finding
    items: str = ""  # where the results are; "" means the document is the list
    lines: bool = False  # one JSON object per line
    detail: str | None = None  # added to the title, e.g. which header is missing
    severity: str | None = None
    severity_map: dict[str, SeverityStatus] = field(default_factory=dict)  # lowercase keys
    description: str | None = None
    remediation: str | None = None
    cwe: str | None = None
    cve: str | None = None
    hidden: tuple[str, ...] = ()  # fields never kept as evidence, e.g. the secret itself


def read(mapping: JsonMapping, output: str) -> tuple[list[NewFinding], int]:
    """Masked JSON output -> (findings, requests sent). JSON tools do not report requests: 0."""
    try:
        results = parse(output, mapping.items, mapping.lines)
    except JsonParseError as error:
        raise OutputUnreadable(str(error)) from error
    return [_finding(mapping, result) for result in results], 0


def _finding(mapping: JsonMapping, result: dict[str, Any]) -> NewFinding:
    location = ":".join(_text(get(result, path)) for path in mapping.location)
    title = _text(get(result, mapping.title)) or mapping.kind
    detail = _optional(result, mapping.detail)
    if detail:
        title = f"{title} ({detail})"
    target = _text(get(result, mapping.target)) or location
    proof = {name: value for name, value in result.items() if name not in mapping.hidden}
    return NewFinding(
        title=title,
        target=target,
        description=_optional(result, mapping.description) or f"{title} at {location}.",
        severity=_severity(mapping, result),
        dedupe_key=dedupe_key(mapping.kind, *(_text(get(result, path)) for path in mapping.key)),
        evidence=[
            NewEvidence(
                kind=mapping.kind,
                content=json.dumps(proof, sort_keys=True, default=str),
                location=location,
            )
        ],
        cwe_ids=_ids(result, mapping.cwe, CWE),
        cve_ids=_ids(result, mapping.cve, CVE),
        remediation=_optional(result, mapping.remediation),
    )


def _severity(mapping: JsonMapping, result: dict[str, Any]) -> SeverityStatus:
    if mapping.severity is None:
        return SeverityStatus.UNKNOWN
    value = _text(get(result, mapping.severity)).lower()
    return mapping.severity_map.get(value, SeverityStatus.UNKNOWN)


def _ids(result: dict[str, Any], path: str | None, pattern: re.Pattern[str]) -> list[str]:
    """e.g. ["CWE-89"] from "CWE-89: SQL Injection" or ["cwe-89"]. Sorted, no repeats."""
    if path is None:
        return []
    value = get(result, path)
    texts = value if isinstance(value, list) else [value]
    return sorted({match.upper() for text in texts for match in pattern.findall(_text(text))})


def _optional(result: dict[str, Any], path: str | None) -> str | None:
    return (_text(get(result, path)) or None) if path else None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


SEVERITY_WORDS = {
    "critical": SeverityStatus.CRITICAL,
    "high": SeverityStatus.HIGH,
    "medium": SeverityStatus.MEDIUM,
    "low": SeverityStatus.LOW,
    "info": SeverityStatus.NONE,
}

MAPPINGS: dict[str, JsonMapping] = {
    "nuclei": JsonMapping(
        kind="nuclei_match",
        lines=True,
        title="info.name",
        target="host",
        location=("matched-at",),
        detail="matcher-name",  # one template can match several things, e.g. each header
        key=("template-id", "matcher-name", "matched-at"),
        severity="info.severity",
        severity_map=SEVERITY_WORDS,
        description="info.description",
        remediation="info.remediation",
        cwe="info.classification.cwe-id",
        cve="info.classification.cve-id",
        hidden=("request", "response", "curl-command"),  # large; kept on the tool run
    ),
    "semgrep": JsonMapping(
        kind="semgrep_match",
        items="results[]",
        title="check_id",
        target="path",
        location=("path", "start.line"),
        key=("check_id", "path", "start.line"),
        severity="extra.severity",
        # semgrep INFO rules still point at code worth a look, so LOW, not NONE.
        severity_map={
            "error": SeverityStatus.HIGH,
            "warning": SeverityStatus.MEDIUM,
            "info": SeverityStatus.LOW,
        },
        description="extra.message",
        cwe="extra.metadata.cwe",
    ),
    "gitleaks": JsonMapping(
        kind="gitleaks_leak",
        title="Description",
        target="File",
        location=("File", "StartLine"),
        key=("RuleID", "File", "StartLine"),
        # The leak itself, the line around it and the commit author never become evidence.
        hidden=("Secret", "Match", "Line", "Commit", "Author", "Email", "Message"),
    ),
    "trivy": JsonMapping(
        kind="trivy_vulnerability",
        items="Results[].Vulnerabilities[]",
        title="Title",
        target="PkgName",
        location=("PkgName", "InstalledVersion"),
        key=("VulnerabilityID", "PkgName", "InstalledVersion"),
        severity="Severity",
        severity_map=SEVERITY_WORDS,
        description="Description",
        cwe="CweIDs",
        cve="VulnerabilityID",
    ),
}
