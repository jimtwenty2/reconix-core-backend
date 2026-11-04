"""osv-scanner JSON -> findings. One finding per vulnerability per package.

Unlike the JSON tools that fit one flat mapping, osv-scanner keeps the package and the
severity outside the vulnerability: the package is the vulnerability's parent, and the
severity is a CVSS score on the group that lists the vulnerability's id. So it has its own
reader. A severity osv-scanner does not give is UNKNOWN: never guessed. The target is
the manifest osv-scanner read (its absolute source.path), else the package name.
"""

import json
import re

from reconix_api.findings.shape import NewEvidence, NewFinding, OutputUnreadable, dedupe_key
from reconix_api.models.enums import SeverityStatus

CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
# A CVSS score (0-10) -> severity, highest first. The CVSS v3 bands.
SCORES = [
    (9.0, SeverityStatus.CRITICAL),
    (7.0, SeverityStatus.HIGH),
    (4.0, SeverityStatus.MEDIUM),
    (0.1, SeverityStatus.LOW),
]


def read(output: str) -> tuple[list[NewFinding], int]:
    """Masked osv-scanner JSON -> (findings, requests sent). It does not report requests: 0."""
    if not output or not output.strip():
        raise OutputUnreadable("EMPTY_OUTPUT")
    try:
        document = json.loads(output)
    except json.JSONDecodeError as error:
        raise OutputUnreadable(f"NOT_JSON: {error}") from error
    if not isinstance(document, dict) or "results" not in document:
        raise OutputUnreadable("NOT_OSV_SCANNER")
    findings = []
    for result in _list(document.get("results")):
        path = str(_dict(result.get("source")).get("path") or "")
        for package in _list(result.get("packages")):
            findings.extend(_package_findings(package, path))
    return findings, 0


def _package_findings(package: dict, path: str) -> list[NewFinding]:
    info = _dict(package.get("package"))
    name = str(info.get("name") or "")
    version = str(info.get("version") or "")
    severities = _group_severities(_list(package.get("groups")))
    where = f"{name}@{version}" + (f" ({path})" if path else "")
    findings = []
    for vuln in _list(package.get("vulnerabilities")):
        vuln_id = str(vuln.get("id") or "")
        # The manifest is part of the key: one package in two manifests is two findings.
        key = [vuln_id, name, version] + ([path] if path else [])
        aliases = [str(alias) for alias in vuln.get("aliases", []) if isinstance(alias, str)]
        title = _summary(vuln) or vuln_id
        findings.append(
            NewFinding(
                title=f"{title} in {name}" if name else title,
                target=path or name or vuln_id,
                description=_description(vuln, where),
                severity=severities.get(vuln_id, SeverityStatus.UNKNOWN),
                dedupe_key=dedupe_key("osv_vulnerability", *key),
                evidence=[
                    NewEvidence(
                        kind="osv_vulnerability",
                        content=json.dumps(vuln, sort_keys=True, default=str),
                        location=where,
                    )
                ],
                cve_ids=_cve_ids([vuln_id, *aliases]),
            )
        )
    return findings


def _group_severities(groups: list[dict]) -> dict[str, SeverityStatus]:
    """Each id in a group gets that group's max CVSS score, as a severity."""
    severities = {}
    for group in groups:
        level = _score_to_severity(group.get("max_severity"))
        for vuln_id in group.get("ids", []):
            if isinstance(vuln_id, str):
                severities[vuln_id] = level
    return severities


def _score_to_severity(value: object) -> SeverityStatus:
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return SeverityStatus.UNKNOWN
    for floor, level in SCORES:
        if score >= floor:
            return level
    return SeverityStatus.NONE


def _summary(vuln: dict) -> str:
    text = vuln.get("summary") or (vuln.get("details") or "").split("\n")[0]
    return str(text).strip()[:200]


def _description(vuln: dict, where: str) -> str:
    details = str(vuln.get("details") or vuln.get("summary") or "").strip()
    return details or f"{vuln.get('id')} affects {where}."


def _cve_ids(texts: list[str]) -> list[str]:
    return sorted({match.upper() for text in texts for match in CVE.findall(text)})


def _list(value: object) -> list[dict]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _dict(value: object) -> dict:
    return value if isinstance(value, dict) else {}
