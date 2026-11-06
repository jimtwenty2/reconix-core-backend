"""The one finding shape every parser's results are turned into, before they are saved."""

import hashlib
from dataclasses import dataclass, field

from reconix_api.models.enums import SeverityStatus


class OutputUnreadable(ValueError):
    """The tool ran, but its output could not be read."""


@dataclass(frozen=True)
class NewEvidence:
    kind: str  # e.g. nmap_port
    content: str  # masked again before it is saved
    location: str  # URL, host:port or file:line


@dataclass(frozen=True)
class NewFinding:
    title: str
    target: str
    description: str
    severity: SeverityStatus
    dedupe_key: str
    evidence: list[NewEvidence] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    owasp_id: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    remediation: str | None = None


def dedupe_key(*parts: str) -> str:
    """The same thing found again, by any tool, gets the same key."""
    text = "|".join(part.strip().lower() for part in parts)
    return hashlib.sha256(text.encode()).hexdigest()


def sca_dedupe_key(cve_ids: list[str], fallback_id: str, package: str, manifest: str) -> str:
    """One key for a dependency vulnerability, shared by trivy, grype and osv so the same CVE
    in the same package+manifest is one finding (listing each tool as a source), not three.

    - Prefer a CVE id (the tools disagree on GHSA vs CVE ids); fall back to the tool's own id.
    - Keep the manifest path (the tools scan the same folder, so the paths agree), so the same
      package in two different manifests is still two findings.
    - Leave the *version* out of the key on purpose: a manifest pins one version per package,
      and the tools format it differently (5.3 vs 5.3.0), so keying on it would wrongly split
      the same vulnerability across tools. The version stays on the finding as evidence.
    """
    ident = min((cve.upper() for cve in cve_ids), default="") or fallback_id
    return dedupe_key("dependency_vuln", ident, package, manifest)
