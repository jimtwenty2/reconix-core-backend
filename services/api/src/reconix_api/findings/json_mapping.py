"""JSON tool results -> findings, through one mapping per tool.

A mapping says where each finding field is in one result. Adding a JSON tool is adding
a mapping here, plus a sample output and a test. A severity the tool does not give, or
one the mapping does not know, is UNKNOWN: never guessed. Only a mapping's stated
default_severity replaces it (every gitleaks leak is a live credential: HIGH).

trivy and grype keep the manifest file (requirements.txt, package-lock.json) outside the
vulnerability, so they have their own reader that makes it the finding's target.
"""

import json
import posixpath
import re
from dataclasses import dataclass, field, replace
from typing import Any

from reconix_api.findings.shape import (
    NewEvidence,
    NewFinding,
    OutputUnreadable,
    dedupe_key,
    sca_dedupe_key,
)
from reconix_api.models.enums import SeverityStatus
from reconix_api.parsers.json_report import JsonParseError, get, parse, pick

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
    default_severity: SeverityStatus = SeverityStatus.UNKNOWN  # when severity is None
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


def read_trivy(output: str) -> tuple[list[NewFinding], int]:
    """trivy fs: dependency vulnerabilities and IaC/config misconfigurations. Each finding's
    target is its file, ArtifactName (the scanned folder) joined with the parent result's
    Target ("requirements.txt", "Dockerfile"). Any other artifact (an image, a repository
    URL) keeps the package name as the target. Only a FAILED misconfig check is a finding."""
    document = _document(output)
    scanned = document.get("ArtifactName") if document.get("ArtifactType") == "filesystem" else ""
    findings = []
    for result in pick(document, "Results[]"):
        manifest = _manifest(scanned, result.get("Target")) if isinstance(result, dict) else ""
        for vulnerability in pick(result, "Vulnerabilities[]"):
            if isinstance(vulnerability, dict):
                findings.append(
                    _dep_finding(
                        MAPPINGS["trivy"],
                        vulnerability,
                        manifest,
                        "VulnerabilityID",
                        "PkgName",
                    )
                )
        for misconfig in pick(result, "Misconfigurations[]"):
            if isinstance(misconfig, dict) and misconfig.get("Status") == "FAIL":
                findings.append(_finding(MAPPINGS["trivy_misconfig"], misconfig, manifest))
    return findings, 0


def read_grype(output: str) -> tuple[list[NewFinding], int]:
    """grype on a directory: each finding's target is the folder joined with the package's
    first location ("/requirements.txt", relative to that folder). An image keeps the
    package name as the target."""
    document = _document(output)
    source = document.get("source") if isinstance(document.get("source"), dict) else {}
    scanned = source.get("target") if source.get("type") == "directory" else ""
    findings = []
    for match in pick(document, "matches[]"):
        if isinstance(match, dict):
            locations = pick(match, "artifact.locations[]")
            first = locations[0] if locations and isinstance(locations[0], dict) else {}
            findings.append(
                _dep_finding(
                    MAPPINGS["grype"],
                    match,
                    _manifest(scanned, first.get("path")),
                    "vulnerability.id",
                    "artifact.name",
                )
            )
    return findings, 0


def _document(output: str) -> dict[str, Any]:
    if not output or not output.strip():
        raise OutputUnreadable("EMPTY_OUTPUT")
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise OutputUnreadable(f"NOT_JSON: {error}") from error
    if not isinstance(document, dict):
        raise OutputUnreadable("NOT_AN_OBJECT")
    return document


def _manifest(scanned: Any, path: Any) -> str:
    """'/workspace/code/s1' + 'api/requirements.txt' (or '/api/...') -> one clean path."""
    if not (isinstance(scanned, str) and scanned and isinstance(path, str) and path.strip()):
        return ""
    return posixpath.normpath(f"{scanned}/{path.strip()}")


def _finding(mapping: JsonMapping, result: dict[str, Any], target: str = "") -> NewFinding:
    """target: the manifest the package is in. It is part of the dedupe key, so one
    package in two manifests is two findings."""
    key = [_text(get(result, path)) for path in mapping.key] + ([target] if target else [])
    location = ":".join(_text(get(result, path)) for path in mapping.location)
    title = _text(get(result, mapping.title)) or mapping.kind
    detail = _optional(result, mapping.detail)
    if detail:
        title = f"{title} ({detail})"
    target = target or _text(get(result, mapping.target)) or location
    proof = {name: value for name, value in result.items() if name not in mapping.hidden}
    return NewFinding(
        title=title,
        target=target,
        description=_optional(result, mapping.description) or f"{title} at {location}.",
        severity=_severity(mapping, result),
        dedupe_key=dedupe_key(mapping.kind, *key),
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


def _dep_finding(
    mapping: JsonMapping,
    result: dict[str, Any],
    manifest: str,
    id_path: str,
    pkg_path: str,
) -> NewFinding:
    """A dependency-vulnerability finding keyed so trivy, grype and osv collapse the same CVE
    in the same package+version+file into one finding (each tool a source), not three."""
    finding = _finding(mapping, result, manifest)
    key = sca_dedupe_key(
        finding.cve_ids,
        _text(get(result, id_path)),
        _text(get(result, pkg_path)).lower(),
        manifest,
    )
    return replace(finding, dedupe_key=key)


def _severity(mapping: JsonMapping, result: dict[str, Any]) -> SeverityStatus:
    if mapping.severity is None:
        return mapping.default_severity
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
        # semgrep INFO rules still point at code worth a look, so LOW, not NONE. Newer
        # semgrep (and Pro rules) write CRITICAL/HIGH/MEDIUM/LOW instead.
        severity_map={
            **SEVERITY_WORDS,
            "error": SeverityStatus.HIGH,
            "warning": SeverityStatus.MEDIUM,
            "info": SeverityStatus.LOW,
        },
        description="extra.message",
        cwe="extra.metadata.cwe",
        # "extra" holds the matched source lines and metavariable values, which can be
        # the secret itself; the message and CWE are kept on the finding.
        hidden=("extra",),
    ),
    "gitleaks": JsonMapping(
        kind="gitleaks_leak",
        title="Description",
        target="File",
        location=("File", "StartLine"),
        key=("RuleID", "File", "StartLine"),
        default_severity=SeverityStatus.HIGH,  # gitleaks gives none; a leak is a credential
        # The leak itself, the line around it and the commit author never become evidence.
        hidden=("Secret", "Match", "Line", "Commit", "Author", "Email", "Message"),
    ),
    "grype": JsonMapping(
        kind="grype_vulnerability",
        items="matches[]",
        title="vulnerability.description",  # e.g. "Improper Input Validation in PyYAML"
        target="artifact.name",
        location=("artifact.name", "artifact.version"),
        key=("vulnerability.id", "artifact.name", "artifact.version"),
        severity="vulnerability.severity",
        severity_map={**SEVERITY_WORDS, "negligible": SeverityStatus.NONE},
        description="vulnerability.description",
        # CWEs are in vulnerability.cwes; the CVE is in relatedVulnerabilities[].id (grype's
        # own id is usually a GHSA). _ids regexes each for its pattern.
        cwe="vulnerability.cwes",
        cve="relatedVulnerabilities",
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
    # IaC / config problems (Dockerfile, compose, k8s, Terraform) from trivy's misconfig
    # scanner. The file is the parent result's Target, passed in as the finding target.
    "trivy_misconfig": JsonMapping(
        kind="trivy_misconfig",
        title="Title",
        target="AVDID",  # replaced by the manifest file passed to _finding
        location=("AVDID", "CauseMetadata.StartLine"),
        key=("AVDID", "CauseMetadata.StartLine"),
        severity="Severity",
        severity_map=SEVERITY_WORDS,
        description="Description",
        remediation="Resolution",
    ),
}
